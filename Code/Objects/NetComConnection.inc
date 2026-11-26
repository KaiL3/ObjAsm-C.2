; ==================================================================================================
; Title:      NetComConnection.inc
; Author:     G. Friedrich
; Version:    C.1.3
; Purpose:    ObjAsm support of NetComConnection objects.
; Notes:      Version C.1.3, November 2026
;               - Close, Disconnect and QueueDestroy take the connection CritSect: they are called
;                 from application threads and the engine, concurrent calls posted the
;                 OnDisconnected/OnClosed completions twice (use after free).
;               - DoSndIOJob/QueueAccept call OnError before leaving the CritSect; QueueSendRaw
;                 holds it across all chunks and sends nothing after Close.
;               - OnReceived (non-TLS): the IOJob of a protocol error is no longer freed while it
;                 is still linked in the RcvIOJobChain (double free); the next receive is queued
;                 after the protocol has run, the consumption loop never frees a pending IOJob.
;               - ReadyToDestroy?: destruction check under the CritSect, closes the connection
;                 first if necessary (FreeRessources must not post completions).
;               - OnAccepted: no new acceptor on a closed listener.
;               - DoSndIOJob/OnSent/CheckSndQueueLow: Protocol.OnSendQueueLow once the send queue
;                 drained to dSndLowWtrMrk after it had reached dSndHighWtrMrk.
;               - All locking goes through pCritSect (own CritSect, or the lock owner's for a
;                 partner created with NewPartner). Init sets it once, it never changes. Done still
;                 deletes the own CritSect; FreeRessources of a partner releases the lock owner
;                 (dLockUsers), ReadyToDestroy? of an owner waits until no partner uses it.
;               - TLS error paths (handshake start in OnConnected, decrypt error, IO errors after
;                 the local TLS shutdown) abort the connection instead of leaving it alive until
;                 a supervisor timeout (forever without supervisor).
;             Version C.1.2, November 2026
;               - Init: calls NetComProtocol.Release if the socket cannot be created and returns
;                 the error code.
;               - QueueConnect/QueueAccept: ConnectEx/AcceptEx return a BOOL; FALSE was always
;                 taken as pending and TRUE as an error check of a stale WSAGetLastError.
;               - QueueConnect: no OnError on failure, frees its IOJob and returns a defined error
;                 code (bind error, out of memory).
;             Version C.1.1, November 2026
;               - CheckRcvLimit: enforces NetComProtocol.dMaxRcvBuffered after each receive.
;               - PauseReceive/ResumeReceive: NCC_RCV_PAUSED is honoured by OnReceived and
;                 QueueReceive; Disconnect lifts a pause; QueueReceive keeps at most one
;                 outstanding receive.
;             Version C.1.0, October 2017
;               - Initial release.
; ==================================================================================================


.code

if IMPLEMENT

; ==================================================================================================
;    NetComConnection implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.Admit
; Purpose:    Performs internal setup work after an accept was detected. Depending in the argument
;             value, the connection is established or discarded.
; Arguments:  Arg1: TRUE/FALSE.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.Admit, uses xsi, dDecision:DWORD
  local dTLSError:DWORD

  SetObject xsi
;  DbgText "NetComConnection.Admit", addr [xsi].wName
  .if dDecision != FALSE
    ;Bind the NetComConnection Socket to the IOCP
    mov xcx, [xsi].pOwner                               ;xcx -> NetComConnectionPool
    mov xax, [xcx].$Obj(NetComConnectionPool).pOwner    ;xax -> NetComEngine
    invoke CreateIoCompletionPort, [xsi].hSocket, [xax].$Obj(NetComEngine).hIOCP, xsi, 0
    .if eax != 0
      invoke GetSystemTimeAsFileTime, addr [xsi].StartTime

      ;TLS: If pTLSContext is set, start server handshake (sets TLS_STATE_HANDSHAKE)
      ;This must happen BEFORE QueueReceive, so that when the first client handshake
      ;token arrives, the state machine in OnReceived routes it to ProcessHandshakeData.
      .if [xsi].pTLSContext != NULL
        ; OnConfigureTLS: Let protocol provide TLS configuration before handshake
        OCall [xsi].pProtocol::NetComProtocol.OnConfigureTLS, xsi
        .if xax != NULL
          OCall xsi.ApplyTLSConfig, xax
        .endif

        OCall [xsi].pTLSContext::TLS_Context.StartServerHandshake, xsi
        .if eax != OBJ_OK
          ;TLS could not be started => notify the protocol and drop the connection
          mov dTLSError, eax
          OCall [xsi].pProtocol::NetComProtocol.OnHandshakeFailed, xsi, dTLSError
          OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, dTLSError
          OCall xsi.QueueDestroy
          OCall xsi.Close, TRUE
          mov eax, dTLSError
          ExitMethod
        .endif
      .endif

      OCall xsi.QueueReceive
    .else
      invoke WSAGetLastError
    .endif
  .else
    ;Connection rejected
    OCall xsi.QueueDestroy                              ;Mark to be released => close & free
    OCall xsi.Close, FALSE
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.CheckRcvLimit
; Purpose:    Enforces the receive limit of the protocol (NetComProtocol.dMaxRcvBuffered).
;             Counts the received BYTEs the protocol has not consumed yet: completed IOJobs in the
;             RcvIOJobChain (plain data or TLS ciphertext that is not yet in the reassembly buffer)
;             and all IOJobs in the PlaintextChain. If the limit is exceeded, the protocol is
;             notified (OnError, NCCN_RCV_LIMIT_EXCEEDED) and the connection is aborted.
; Arguments:  None.
; Return:     eax = Zero if the limit is not exceeded, otherwise NCCN_RCV_LIMIT_EXCEEDED.
; Note:       The chains are counted instead of keeping a running total, since protocols may
;             consume IOJobs directly from the chains (e.g. SRPS). Counting stops as soon as the
;             limit is exceeded, so the effort is bounded by the limit.

Method NetComConnection.CheckRcvLimit, uses xbx xdi xsi
  local dLimit:DWORD, dResult:DWORD

  SetObject xsi
  mov dResult, 0
  mov xcx, [xsi].pProtocol
  .if xcx != NULL
    mov edx, [xcx].$Obj(NetComProtocol).dMaxRcvBuffered
    .if edx != 0
      mov dLimit, edx
      invoke EnterCriticalSection, [xsi].pCritSect
      .ifBitClr [xsi].dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY
        xor edx, edx                                    ;edx = unconsumed BYTEs

        ;Completed IOJobs in the RcvIOJobChain (a pending receive has no data yet)
        lea xdi, [xsi].RcvIOJobChain
        mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
        .while xbx != xdi
          .ifBitSet [xbx - IOJOB_HEADER_SIZE].IOJOB.wFlags, IOF_JOB_COMPLETED
            add edx, [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed
            .break .if edx > dLimit
          .endif
          mov xbx, [xbx].SDLL_ITEM.pNextItem
        .endw

        ;Decrypted data not yet consumed by the protocol (TLS only)
        .if edx <= dLimit
          lea xdi, [xsi].PlaintextChain
          mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
          .while xbx != xdi
            add edx, [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed
            .break .if edx > dLimit
            mov xbx, [xbx].SDLL_ITEM.pNextItem
          .endw
        .endif

        .if edx > dLimit
          DbgWarning "NetComConnection.CheckRcvLimit - receive limit exceeded"
          mov dResult, NCCN_RCV_LIMIT_EXCEEDED
          OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, NCCN_RCV_LIMIT_EXCEEDED
          OCall xsi.QueueDestroy
          OCall xsi.Close, TRUE                         ;Abortive close, drops all buffered data
        .endif
      .endif
      invoke LeaveCriticalSection, [xsi].pCritSect
    .endif
  .endif
  mov eax, dResult
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.Close
; Purpose:    Perform a graceful/abortive disconnection of a NetCom connection sending
;             a FIN/RST to the remote endpoint.
; Arguments:  Arg1: Abortive flag (TRUE/FALSE).
; Return:     Nothing.
; Note:       Can be called from any thread while the connection exists (recursive CritSect).

Method NetComConnection.Close, uses xsi, dAbortive:DWORD
  local Linger:linger

  SetObject xsi
  invoke EnterCriticalSection, [xsi].pCritSect
  .ifBitClr [xsi].dFlags, NCC_CLOSED
;    DbgText "NetComConnection.Close", addr [xsi].wName

    ; TLS Shutdown Pending abbrechen
    BitClr [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING

    ; OnDisconnected posten falls noch nicht geschehen
    .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
      BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
      mov [xsi].dDisconnectError, NO_ERROR
      mov [xsi].dDisconnectDirection, SD_BOTH            ;Close = beide Richtungen
      mov xcx, [xsi].pOwner                             ;xcx -> NetComConnectionPool
      mov xax, [xcx].$Obj(NetComConnectionPool).pOwner  ;xax -> NetComEngine
      invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
             0, COMPLETION_KEY_DISCONNECTED, xsi
    .endif

    ;Perform a "graceful" or "abortive" disconnection of the socket sending a "FIN" or "RST"
    ;to the remote endpoint
    ?mov edx, dAbortive
    mov Linger.l_onoff, dx                              ;Linger ON/OFF
    mov Linger.l_linger, 0                              ;Wait time = 0
    invoke setsockopt, [xsi].hSocket, SOL_SOCKET, SO_LINGER, addr Linger, sizeof Linger
;    DbgCheckSockReturn "NetComConnection.Close - ERROR on SetSockOpt SO_LINGER",, addr [xsi].wName
    BitSet [xsi].dFlags, NCC_CLOSED                    ;Set marker before closesocket!
    invoke closesocket, [xsi].hSocket
    mov [xsi].hSocket, INVALID_SOCKET

    ; OnClosed asynchron posten (FIFO-Reihenfolge: nach DISCONNECTED)
    mov xcx, [xsi].pOwner                             ;xcx -> NetComConnectionPool
    mov xax, [xcx].$Obj(NetComConnectionPool).pOwner  ;xax -> NetComEngine
    invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
           0, COMPLETION_KEY_CLOSED, xsi
  .endif
  invoke LeaveCriticalSection, [xsi].pCritSect
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.Disconnect
; Purpose:    Disconnect writing and/or reading.
; Arguments:  Arg1: Disconnect direction = SD_RECEIVE(0)/SD_SEND(1)/SD_BOTH(2)
; Return:     eax = Zero if succeeded, otherwise an error code.
; Note:       Can be called from any thread while the connection exists (recursive CritSect).

Method NetComConnection.Disconnect, uses xsi, dDirection:DWORD
  local dRetValue:DWORD

  SetObject xsi
;  DbgText "NetComConnection.Disconnect", addr [xsi].wName
  mov dRetValue, NO_ERROR
  invoke EnterCriticalSection, [xsi].pCritSect
  .ifBitClr [xsi].dFlags, NCC_CLOSED

    ;A paused receive would block the graceful close: the peer's FIN or close_notify response
    ;would never be read. Lift the pause, unless the receive direction is shut down anyway.
    .if dDirection != SD_RECEIVE
      OCall xsi.ResumeReceive
    .endif

    ; === TLS: Graceful close_notify ===
    ; Serialized with OnReceivedTLS / QueueSend (same security context, recursive CritSect)
    .if [xsi].pTLSContext != NULL && dDirection != SD_RECEIVE
      OCall [xsi].pTLSContext::TLS_Context.GetState
      .if eax == TLS_STATE_DATA
        OCall [xsi].pTLSContext::TLS_Context.Shutdown, xsi
        BitSet [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
        invoke GetSystemTimeAsFileTime, addr [xsi].LastTime
        ; Kein TCP shutdown hier ù warten auf Peer-Antwort oder Timeout
        jmp @@Exit
      .endif
    .endif

    ; === Kein TLS oder TLS nicht im DATA-State ===
    invoke shutdown, [xsi].hSocket, dDirection            ;Send FIN to the remote host
    .if eax == NO_ERROR
      .if dDirection == SD_RECEIVE
        BitSet [xsi].dFlags, NCC_SHUTDOWN_RCV_LOCAL
      .elseif dDirection == SD_SEND
        BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
      .else
        BitSet [xsi].dFlags, NCC_SHUTDOWN_RCV_LOCAL or NCC_SHUTDOWN_SND_LOCAL
      .endif
    .else
      invoke WSAGetLastError
      mov dRetValue, eax
;      DbgCheckSockReturn "NetComConnection.Disconnect - shutdown error", eax, addr [xsi].wName
    .endif

    ; === OnDisconnected asynchron posten (genau einmal) ===
    .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
      BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
      m2m [xsi].dDisconnectError, dRetValue, eax
      m2m [xsi].dDisconnectDirection, dDirection, eax
      mov xcx, [xsi].pOwner                             ;xcx -> NetComConnectionPool
      mov xax, [xcx].$Obj(NetComConnectionPool).pOwner  ;xax -> NetComEngine
      invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
             0, COMPLETION_KEY_DISCONNECTED, xsi
    .endif
  .endif
@@Exit:
  invoke LeaveCriticalSection, [xsi].pCritSect
  mov eax, dRetValue
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.Done
; Purpose:    Finalize the NetComConnection object.
; Arguments:  None.
; Return:     Nothing.

Method NetComConnection.Done, uses xsi
  SetObject xsi
;  DbgText "NetComConnection.Done ***********************************************", addr [xsi].wName
  ;Always the own CritSect. A partner never used it; the shared one is deleted with its owner,
  ;which is destroyed only after all partners (dLockUsers).
  invoke DeleteCriticalSection, addr [xsi].CritSect
  mov [xsi].pCritSect, NULL
  BitSet [xsi].dFlags, NCC_DONE
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.DoRcvIOJob
; Purpose:    Perform an asynchronious read operation.
; Arguments:  Arg1: -> IOJob.
; Return:     eax = Zero if succeeded, otherwise an error code.
; Note:       Appending the IOJob to the RcvIOJobChain MUST be done before calling WSARecv to
;             ensure proper sequence on an multithreaded environment!

Method NetComConnection.DoRcvIOJob, uses xbx xdi xsi, pIOJob:PIOJOB
  local dRcvFlags:DWORD

  SetObject xsi
;  DbgText "NetComConnection.DoRcvIOJob", addr [xsi].wName

  mov xdi, pIOJob
  lea xcx, [xdi].IOJOB.pNextItem                        ;Get address of SDLL_ITEM
  lea xax, [xsi].RcvIOJobChain                          ;Get address of SDLL_SENTINEL
  SDLL_Append xax, xcx                                  ;Link this IOJob to the IO list
  mov dRcvFlags, 0
  invoke WSARecv, [xsi].hSocket, addr [xdi].IOJOB.WSABuf, 1, \
                  addr [xdi].IOJOB.dBytesConsumed, addr dRcvFlags, xdi, NULL
  .if eax != NO_ERROR                                   ;Did read IO complete synchronously?
    invoke WSAGetLastError                              ;No, check if it is a pending state
    .if eax == ERROR_IO_PENDING
      xor eax, eax                                      ;Not an error
    .endif
  .endif

  .if eax == 0
    inc [xsi].dPendingIOJobs
    inc [xsi].dRcvQueuedIOJobs
  .endif
  mov ebx, eax

  .if ebx != 0
    OCall xsi.OnError, xdi, ebx                         ;pIOJob
  .endif

  mov eax, ebx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.DoSndIOJob
; Purpose:    Perform an asynchronious write operation.
; Arguments:  Arg1: -> IOJOB.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.DoSndIOJob, uses xbx xdi xsi, pIOJob:PIOJOB
  SetObject xsi
;  DbgText "NetComConnection.DoSndIOJob", addr [xsi].wName
  mov xdi, pIOJob
  invoke EnterCriticalSection, [xsi].pCritSect
  invoke WSASend, [xsi].hSocket, addr [xdi].IOJOB.WSABuf, 1, \
                  addr [xdi].IOJOB.dBytesConsumed, 0, xdi, NULL
  .if eax != NO_ERROR                                   ;Did read IO complete synchronously?
    invoke WSAGetLastError                              ;No, check if it is a pending state
    .if eax == ERROR_IO_PENDING
      xor eax, eax                                      ;Not an error
    .endif
  .endif

  .if eax == 0
    inc [xsi].dPendingIOJobs
    inc [xsi].dSndQueuedIOJobs
    ;Remember that the send queue was high: OnSendQueueLow follows when it has drained
    mov ecx, [xsi].dSndQueuedIOJobs
    .if ecx >= [xsi].dSndHighWtrMrk
      BitSet [xsi].dFlags, NCC_SND_QUEUE_HIGH
    .endif
  .endif
  mov ebx, eax

  ;Report an immediate failure while the CritSect is held (OnError runs protocol code)
  .if ebx != 0
    OCall xsi.OnError, xdi, ebx                         ;pIOJob
  .endif

  invoke LeaveCriticalSection, [xsi].pCritSect

  mov eax, ebx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.FreeRessources
; Purpose:    Free all ressources, including the gattered IOJobs.
; Arguments:  None.
; Return:     Nothing.
; Note:       This method works worhs together with Done to isolate the call DeleteCriticalSection.
;             At this point no pending IOJobs should exist!
;             Must be called with the CritSect (pCritSect) held, except for a connection that is
;             not shared and has no IO (NetComEngine.DiscardConnection).
;             On the destroy paths the connection is already closed (ReadyToDestroy?,
;             NetComEngine.DiscardConnection), so Close posts no completions here.

Method NetComConnection.FreeRessources, uses xbx xdi xsi
  local pPrevItem:PSDLL_ITEM, pIOJobPool:$ObjPtr(NetComIOJobPool)

  SetObject xsi
;  DbgText "NetComConnection.FreeRessources", addr [xsi].wName

  OCall xsi.Close, TRUE                                 ;Abortive close if needed
  OCall [xsi].pProtocol::NetComProtocol.Release, xsi    ;Release protocol resources

  ;Iterate the RcvIOJobChain Linked List in reverse order.
  lea xbx, [xsi].RcvIOJobChain
  mov xcx, [xsi].pOwner
  m2m pIOJobPool, [xcx].$Obj(NetComConnectionPool).pIOJobPool, xax
  mov xdi, [xbx].SDLL_SENTINEL.pLastItem                ;Get the last IOJob
  .while xdi != xbx                                     ;Check for end of chain
    m2m pPrevItem, [xdi].SDLL_ITEM.pPrevItem, xax       ;Save prev item in pItem
    OCall pIOJobPool::NetComIOJobPool.FreeItem, addr [xdi - IOJOB_HEADER_SIZE]
    mov xdi, pPrevItem                                  ;Move to previos item
  .endw
  SDLL_Init xbx                                         ;Reset the linked list

  ;Iterate the PlaintextChain Linked List in reverse order (TLS decrypted data).
  lea xbx, [xsi].PlaintextChain
  mov xdi, [xbx].SDLL_SENTINEL.pLastItem
  .while xdi != xbx
    m2m pPrevItem, [xdi].SDLL_ITEM.pPrevItem, xax
    OCall pIOJobPool::NetComIOJobPool.FreeItem, addr [xdi - IOJOB_HEADER_SIZE]
    mov xdi, pPrevItem
  .endw
  SDLL_Init xbx

  ;Iterate the PendingSendChain (TLS plaintext held back during the handshake).
  lea xbx, [xsi].PendingSendChain
  mov xdi, [xbx].SDLL_SENTINEL.pLastItem
  .while xdi != xbx
    m2m pPrevItem, [xdi].SDLL_ITEM.pPrevItem, xax
    OCall pIOJobPool::NetComIOJobPool.FreeItem, addr [xdi - IOJOB_HEADER_SIZE]
    mov xdi, pPrevItem
  .endw
  SDLL_Init xbx

  ;A partner stops using the CritSect of its lock owner. The caller still holds the shared
  ;CritSect and leaves it through pCritSect, which stays valid until Done.
  mov xcx, [xsi].pLockOwner
  .if xcx != NULL
    dec [xcx].$Obj(NetComConnection).dLockUsers
    mov [xsi].pLockOwner, NULL
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.HandleProtocolCmd
; Purpose:    Executes what the Protocoll decided.
; Arguments:  Arg1: Protocol command (PROT_CMD_xxxx).
; Return:     Nothing.

Method NetComConnection.HandleProtocolCmd, uses xsi, dProtocolCommand:DWORD
  SetObject xsi
;  DbgText "NetComConnection.HandleProtocolCmd", addr [xsi].wName
  ?mov edx, dProtocolCommand
  .if edx == PROT_CMD_NONE
  .elseif edx == PROT_CMD_DISCONNECT
    OCall xsi.Disconnect, SD_BOTH
  .elseif edx == PROT_CMD_CLOSE
    OCall xsi.Close, TRUE
  .elseif edx == PROT_CMD_DESTROY
    OCall xsi.QueueDestroy
    OCall xsi.Close, TRUE
  .else
    DbgDec dProtocolCommand, "NetComConnection.HandleProtocolCmd | Unknown protocol command",
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.Init
; Purpose:    Initializes the NetComConnection object.
; Arguments:  Arg1: -> Owner object (NetComConnectionPool).
;             Arg2: -> NetComProtocol or derived object.
; Return:     eax = Zero if succeeded, otherwise an error code.
; Note:       On failure, Init has released what it allocated (NetComProtocol.Allocate failed or
;             Release was called after a socket error). The caller must call Done and return the
;             connection to the pool; nothing was queued on the IOCP.

Method NetComConnection.Init, uses xsi, pOwner:POINTER, pProtocol:POINTER
  local dOption:DWORD, dError:DWORD

  SetObject xsi
  ?mov xdx, pOwner
  ACall xsi.Init, xdx
  mov [xsi].dFlags, 0
  mov [xsi].dCompletedIOJobs, 0
  mov [xsi].dPendingIOJobs, 0

  FillTextW [xsi].wName, <Connection >
  invoke xword2hexW, addr [xsi].wName[??StrSize], xsi
;  DbgText "NetComConnection.Init", addr [xsi].wName

  invoke InitializeCriticalSectionEx, addr [xsi].CritSect, 4000, 0
  ;CritSect in use: the own one, or the one of the lock owner (NewPartner sets pLockOwner before
  ;Init). Set once here, it never changes afterwards.
  mov xcx, [xsi].pLockOwner
  .if xcx != NULL
    mov xax, [xcx].$Obj(NetComConnection).pCritSect
  .else
    lea xax, [xsi].CritSect
  .endif
  mov [xsi].pCritSect, xax
  m2m [xsi].pProtocol, pProtocol, xax
  lea xax, [xsi].RcvIOJobChain
  SDLL_Init xax
  lea xax, [xsi].PlaintextChain
  SDLL_Init xax
  lea xax, [xsi].PendingSendChain
  SDLL_Init xax

  OCall pProtocol::NetComProtocol.Allocate, xsi
  .if eax == 0
    ;Create a socket with WSA_FLAG_OVERLAPPED flag set! No WSAPROTOCOL_INFO and no Group
    invoke WSASocket, AF_INETX, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED
    mov [xsi].hSocket, xax
    .if xax != INVALID_SOCKET
      ;Set socket options: disable nagle's algorithm for fast reaction time
      mov dOption, 1                                  ;1 means algo disabled
      invoke setsockopt, [xsi].hSocket, IPPROTO_TCP, TCP_NODELAY, addr dOption, sizeof dOption
      DbgCheckSockReturn "NetComConnection.Init - ERROR on SetSockOpt TCP_NODELAY = 1",, addr [xsi].wName
      invoke MemZero, addr [xsi].StartTime, sizeof FILETIME
      xor eax, eax
    .else
      invoke WSAGetLastError
      mov dError, eax
      DbgOnSockError "NetComConnection.Init - Failed to create socket", eax,, addr [xsi].wName
      OCall pProtocol::NetComProtocol.Release, xsi      ;Undo NetComProtocol.Allocate
      mov eax, dError
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.NewPartner
; Purpose:    Creates a connection that uses the CritSect of this connection. Both connections are
;             then processed by one thread at a time, so code working on both (e.g. a proxy that
;             forwards data between them) cannot run into lock cycles.
; Arguments:  Arg1: -> NetComProtocol of the new connection.
; Return:     xax -> New NetComConnection (registered with the IOCP) or NULL if failed.
; Note:       - Call it with the CritSect of this connection held (e.g. in a protocol callback).
;             - This connection is destroyed only after all its partners.
;             - The pairing itself (who belongs to whom) is up to the protocol.

Method NetComConnection.NewPartner, uses xsi, pProtocol:POINTER
  SetObject xsi
  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  mov xcx, [xcx].$Obj(NetComConnectionPool).pOwner      ;xcx -> NetComEngine
  OCall xcx::NetComEngine.CreateConnection, pProtocol, xsi
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnAccepted
; Purpose:    Associates a newly accepted socket with the IOCP and queues an IOJob
;             of the "IOJOB_RECV" type.
; Arguments:  Arg1: -> IOJob. It contains in the buffer the addresses of both endpoints.
; Return:     Nothing.

Method NetComConnection.OnAccepted, uses xbx xdi xsi, pIOJob:PIOJOB
;  local dRcvLstElpsdTimeSize:DWORD

  SetObject xsi
;  DbgText "NetComConnection.OnAccepted", addr [xsi].wName

  BitClr [xsi].dFlags, NCE_ACCEPT
  BitSet [xsi].dFlags, NCC_ACCEPTED

  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  mov xdi, [xcx].$Obj(NetComConnectionPool).pOwner      ;xdi -> NetComEngine
  mov xbx, pIOJob

  .ifBitClr [xsi].dFlags, NCC_QUEUE_DESTROY
    mov xax, [xbx].IOJOB.DataBuffer.ACCEPT_DATA.pListener

    ;Updates the accepting socket with the context of the listening socket.
    invoke setsockopt, [xsi].hSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, \
                       addr [xax].LISTENER.hSocket, sizeof HANDLE
    DbgCheckSockReturn "NetComConnection.OnAccepted - Error on SetSockOpt SO_UPDATE_ACCEPT_CONTEXT",, addr [xsi].wName

;    mov dRcvLstElpsdTimeSize, sizeof DWORD
;    invoke getsockopt, [xsi].hSocket, SOL_SOCKET, SO_CONNECT_TIME, \
;                       addr [xsi].dRcvLstElpsdTime, addr dRcvLstElpsdTimeSize
;    DbgCheckSockReturn "NetComConnection.OnAccepted - ERROR on OnReceived getsockopt SO_CONNECT_TIME",, addr [xsi].wName

    ;Get the address of the local endpoint
    invoke MemClone, addr [xsi].LocalAddr, addr [xbx].IOJOB.DataBuffer.ACCEPT_DATA.LocalAddr, sizeof NETCOMADDR
;    DbgNetComAddrIPV4 [xsi].LocalAddr, "NetComConnection.OnAccepted - LocalAddr", addr [xsi].wName

    ;Get the address of the remote endpoint
    invoke MemClone, addr [xsi].RemoteAddr, addr [xbx].IOJOB.DataBuffer.ACCEPT_DATA.RemoteAddr, sizeof NETCOMADDR
;    DbgNetComAddrIPV4 [xsi].RemoteAddr, "NetComConnection.OnAccepted - RemoteAddr", addr [xsi].wName

    ;Notify the NetComConnection's Protocol handler
    OCall [xsi].pProtocol::NetComProtocol.OnAccepted, xsi

    ;Create a new acceptor, unless the listener was closed (StopListening / engine Done)
    mov xax, [xbx].IOJOB.DataBuffer.ACCEPT_DATA.pListener
    .if [xax].LISTENER.hSocket != INVALID_SOCKET
      OCall xdi::NetComEngine.NewAcceptor, xax, [xsi].pProtocol
    .endif
  .endif

  OCall [xdi].$Obj(NetComEngine).IOJobPool::NetComIOJobPool.FreeItem, xbx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnConnected
; Purpose:    A connect operation has finished.
; Arguments:  Arg1: -> IOJob.
; Return:     Nothing.

Method NetComConnection.OnConnected, uses xsi, pIOJob:PIOJOB
  local dSize:DWORD, dTLSError:DWORD

  SetObject xsi
;  DbgText "NetComConnection.OnConnected", addr [xsi].wName

  BitClr [xsi].dFlags, NCE_CONNECT
  BitSet [xsi].dFlags, NCC_CONNECTED

  mov xcx, [xsi].pOwner
  OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob
  invoke setsockopt, [xsi].hSocket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0
;  DbgCheckSockReturn "NetComConnection.OnConnected - ERROR on SetSockOpt SO_UPDATE_CONNECT_CONTEXT"
  invoke GetSystemTimeAsFileTime, addr [xsi].StartTime
  mov dSize, sizeof(NETCOMADDR)
  invoke getsockname, [xsi].hSocket, addr [xsi].LocalAddr, addr dSize
;  DbgCheckSockReturn "NetComConnection.OnConnected - getsockname",, addr [xsi].wName
;  DbgNetComAddrIPV4 [xsi].LocalAddr, "NetComConnection.OnConnected - LocalAddr", addr [xsi].wName
;  DbgNetComAddrIPV4 [xsi].RemoteAddr, "NetComConnection.OnConnected - RemoteAddr", addr [xsi].wName

  .if [xsi].pTLSContext != NULL
    ; OnConfigureTLS: Let protocol provide TLS configuration before handshake
    OCall [xsi].pProtocol::NetComProtocol.OnConfigureTLS, xsi
    .if xax != NULL
      OCall xsi.ApplyTLSConfig, xax
    .endif

    ; (1) TLS-Handshake initiieren (Context + Client Hello)
    OCall [xsi].pTLSContext::TLS_Context.StartClientHandshake, xsi
    .if eax != OBJ_OK
      ;TLS could not be started => notify the protocol and close the connection
      mov dTLSError, eax
      OCall [xsi].pProtocol::NetComProtocol.OnHandshakeFailed, xsi, dTLSError
      OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, dTLSError
      OCall xsi.QueueDestroy                            ;Like Admit: no plaintext fallback
      OCall xsi.Close, TRUE
      ExitMethod
    .endif

    ; (2) Socket empfangsbereit machen (single-IOJob mode ù nur ein ausstehender Receive)
    OCall xsi.QueueReceive

    ; (3) Anwendung informieren
    OCall [xsi].pProtocol::NetComProtocol.OnConnected, xsi
  .else
    ; Kein TLS ù normaler Ablauf
    OCall [xsi].pProtocol::NetComProtocol.OnConnected, xsi
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnError
; Purpose:    An error condition was fired. We have to decide what to do next.
; Arguments:  Arg1: -> IOJOB.
;             Arg2: Error.
; Return:     Nothing.

Method NetComConnection.OnError, uses xbx xdi xsi, pIOJob:PIOJOB, dError:DWORD
  local dProtocolCommand:DWORD

  SetObject xsi
  mov xbx, pIOJob
  mov xdi, [xsi].pOwner                                 ;xdi -> NetComConnectionPool

  ; === Spurious Errors nach Close unterdrùcken ===
  .ifBitSet [xsi].dFlags, NCC_CLOSED
    movzx eax, [xbx].IOJOB.wOperation
    .if eax == IOJOB_RECV
      ;IOJob aus RcvIOJobChain entfernen
      mov xcx, pIOJob
      lea xax, [xcx].IOJOB.pNextItem
      SDLL_Remove xax, xcx, xdx
    .endif
    OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx
    ExitMethod
  .endif
  ; === End Guard ===

  ; === Spurious Errors nach TLS Shutdown unterdrùcken ===
  ; Wenn der Socket bereits per shutdown(SD_SEND) halb-geschlossen ist,
  ; erzeugen pending IOJobs WSAEESHUTDOWN (10058) oder WSAECONNRESET.
  ; Diese sind erwartet und werden nicht an die Protocol-Schicht gemeldet.
  .ifBitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
    .if [xsi].pTLSContext != NULL
      movzx eax, [xbx].IOJOB.wOperation
      .if eax == IOJOB_RECV
        mov xcx, pIOJob
        lea xax, [xcx].IOJOB.pNextItem
        SDLL_Remove xax, xcx, xdx
      .endif
      OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx
      ;The shutdown cannot complete any more (no receive pending, the send side is broken):
      ;abort without notifying the protocol instead of waiting for a supervisor timeout
      OCall xsi.QueueDestroy
      OCall xsi.Close, TRUE
      ExitMethod
    .endif
  .endif
  ; === End TLS Shutdown Guard ===

  movzx eax, [xbx].IOJOB.wOperation
;  DbgDec eax, "NetComConnection.OnError Operation";, addr [xsi].wName
  .if eax == IOJOB_ACCEPT
;    DbgOnSockError "NetComConnection.OnError - Accept", dError,, addr [xsi].wName
    BitSet [xsi].dFlags, NCE_ACCEPT
    OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, xbx, dError
    mov dProtocolCommand, eax
    ;This IOJob must be freed before HandleProtocolCmd
    OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx
    OCall xsi.HandleProtocolCmd, dProtocolCommand

  .elseif eax == IOJOB_CONNECT
;    DbgOnSockError "NetComConnection.OnError - Connect", dError,, addr [xsi].wName
    BitSet [xsi].dFlags, NCE_CONNECT
    OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, xbx, dError
    mov dProtocolCommand, eax
    ;This IOJob must be freed before HandleProtocolCmd
    OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx
    OCall xsi.HandleProtocolCmd, dProtocolCommand

  .elseif eax == IOJOB_SEND
;    DbgOnSockError "NetComConnection.OnError - Send", dError,, addr [xsi].wName
    BitSet [xsi].dFlags, NCE_SEND
    OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, xbx, dError
    mov dProtocolCommand, eax
    ;This IOJob must be freed before HandleProtocolCmd
    OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx
    OCall xsi.HandleProtocolCmd, dProtocolCommand

  .elseif eax == IOJOB_RECV
;    DbgOnSockError "NetComConnection.OnError - Receive", dError,, addr [xsi].wName
    BitSet [xsi].dFlags, NCE_RECEIVE
    OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, xbx, dError
    mov dProtocolCommand, eax

    ;Note: This IOJob is linked to the NetComConnection RcvIOJobChain.
    ;      Remove the IOJob from the RcvIOJobChain and toss it into the pool.
    mov xcx, pIOJob
    lea xax, [xcx].IOJOB.pNextItem
    SDLL_Remove xax, xcx, xdx
    OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx
    OCall xsi.HandleProtocolCmd, dProtocolCommand

  .else
;    DbgOnSockError "NetComConnection.OnError - Unknown operation", dError,, addr [xsi].wName
    DbgHex [xbx].IOJOB.wOperation, "NetComConnection.OnError", addr [xsi].wName
    OCall [xdi].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xbx

  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnReceived
; Purpose:    A read operation has finished.
; Arguments:  Arg1: -> IOJOB.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.OnReceived, uses xbx xdi xsi, pIOJob:PIOJOB
  local dConsumed:DWORD

  SetObject xsi
  lock dec [xsi].dRcvQueuedIOJobs
  ?mov xdx, pIOJob
  mov xbx, [xsi].pOwner

  ;Check for special case of remote socket closure (remote sent a FIN) - end of stream
  .if [xdx].IOJOB.dBytesConsumed == 0                   ;Graceful remote shutdown send
;    DbgText "NetComConnection.OnReceived - FIN", addr [xsi].wName
    BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_REMOTE        ;Remote shutdown send

    ;Remove FIN IOJob from RcvIOJobChain and return to pool (contains no useful data)
    mov xcx, pIOJob
    lea xax, [xcx].IOJOB.pNextItem
    SDLL_Remove xax, xcx, xdx
    OCall [xbx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob

    ; TLS Shutdown Pending: Peer hat TCP FIN statt close_notify geschickt
    .ifBitSet [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
      BitClr [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
      BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
      .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
        BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
        mov [xsi].dDisconnectError, NO_ERROR
        mov [xsi].dDisconnectDirection, SD_SEND          ;Wir haben initiiert
        mov xcx, [xsi].pOwner                           ;xcx -> NetComConnectionPool
        mov xax, [xcx].$Obj(NetComConnectionPool).pOwner ;xax -> NetComEngine
        invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
               0, COMPLETION_KEY_DISCONNECTED, xsi
      .endif

    .elseif [xsi].pTLSContext != NULL
      ; TLS Responder-Pfad: FIN kam nach close_notify-Verarbeitung.
      ; Wir haben bereits unsere close_notify-Antwort gesendet (NCC_SHUTDOWN_SND_LOCAL).
      ; Kein weiterer Disconnect nùtig ù Socket wird ùber QueueDestroy abgebaut.
      .ifBitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
        ; Shutdown-Sequenz bereits komplett ù nichts weiter tun
      .else
        ; FIN ohne vorherige close_notify (truncated close) ù sauber beenden
        .ifBitClr [xsi].dFlags, NCC_CLOSED
          invoke shutdown, [xsi].hSocket, SD_SEND
          BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
        .endif
        .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
          BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
          mov [xsi].dDisconnectError, NO_ERROR
          mov [xsi].dDisconnectDirection, SD_RECEIVE
          mov xcx, [xsi].pOwner
          mov xax, [xcx].$Obj(NetComConnectionPool).pOwner
          invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
                 0, COMPLETION_KEY_DISCONNECTED, xsi
        .endif
      .endif

    .else
      ; Normaler FIN-Pfad (non-TLS)
      .ifBitClr [xsi].dFlags, NCC_CLOSED
        OCall xsi.Disconnect, SD_RECEIVE                  ;Local shutdown receive
      .endif
    .endif

  .else
;    DbgText "NetComConnection.OnReceived", addr [xsi].wName

    ; === TLS Dispatch ===
    .if [xsi].pTLSContext != NULL
      ;The next receive is queued before the TLS processing. OnReceivedTLS drains only completed
      ;IOJobs, so a receive that completes synchronously cannot be consumed too early.
      ;While the receive is paused, ResumeReceive queues it later.
      .ifBitClr [xsi].dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY
        OCall xsi.QueueReceive                          ;Only if not paused and none pending
      .endif
      OCall xsi.OnReceivedTLS, pIOJob
      OCall xsi.CheckRcvLimit                           ;Abort if too much data is unconsumed
      ExitMethod
    .endif

    ; === Non-TLS path ===
    ;The protocol scans the RcvIOJobChain, so the next receive is queued only after it has run.
    ;A receive queued before could complete synchronously: its data would be in the chain while
    ;its completion is still queued (IOF_JOB_COMPLETED not set) and could be consumed and freed.
    OCall [xsi].pProtocol::NetComProtocol.IsDataComplete?, xsi, pIOJob
    .if eax == ERROR_BAD_PROTOCOL || eax == ERROR_USER_QUIT
      ;The IOJob stays linked in the RcvIOJobChain, FreeRessources releases it
      OCall xsi.Disconnect, SD_BOTH
      OCall xsi.QueueDestroy
      OCall xsi.Close, TRUE
    .elseif eax != 0
      OCall [xsi].pProtocol::NetComProtocol.ProcessData, xsi, eax
      .if eax != 0                                      ;eax = # of BYTEs that can be disposed
        mov dConsumed, eax
        lea xdi, [xsi].RcvIOJobChain                    ;Sentinel
        mov xbx, [xdi].SDLL_SENTINEL.pFirstItem         ;Get first item
        .while xbx != xdi && dConsumed != 0
          .ifBitClr [xbx - IOJOB_HEADER_SIZE].IOJOB.wFlags, IOF_JOB_COMPLETED
            .break                                      ;Never release a pending receive
          .endif
          mov edx, [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed
          .if edx <= dConsumed
            sub dConsumed, edx
            mov xcx, [xsi].pOwner
            lea xdx, [xbx - IOJOB_HEADER_SIZE]          ;xdx -> IOJob
            mov xbx, [xbx].SDLL_ITEM.pNextItem          ;xbx -> next linked item
            OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xdx
            .break .if dConsumed == 0
          .else
            mov ecx, dConsumed
            add [xbx - IOJOB_HEADER_SIZE].IOJOB.WSABuf.buf, xcx
            sub [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed, ecx
            .break
          .endif
        .endw
        mov [xdi].SDLL_SENTINEL.pFirstItem, xbx
        mov [xbx].SDLL_ITEM.pPrevItem, xdi
      .endif
    .endif
    OCall xsi.CheckRcvLimit                             ;Abort if too much data is unconsumed
    .ifBitClr [xsi].dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY
      OCall xsi.QueueReceive                            ;Only if not paused and none pending
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnSent
; Purpose:    A write operation has finished.
; Arguments:  Arg1: -> IOJOB.
; Return:     Nothing.

Method NetComConnection.OnSent, uses xsi, pIOJob:PIOJOB
  SetObject xsi
;  DbgText "NetComConnection.OnSent", addr [xsi].wName
  dec [xsi].dSndQueuedIOJobs

  ;Toss the completed IOJob back in the IOJobPool (the protocol may send again below)
  mov xax, [xsi].pOwner
  OCall [xax].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob

  OCall xsi.CheckSndQueueLow                            ;May call Protocol.OnSendQueueLow
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.CheckSndQueueLow
; Purpose:    Called after a send IOJob has left the send queue (completed or failed). When the
;             queue has drained to dSndLowWtrMrk after it had reached dSndHighWtrMrk, the protocol
;             is notified once (NetComProtocol.OnSendQueueLow), e.g. to resume a paused source.
; Arguments:  None.
; Return:     Nothing.
; Note:       Called by the worker with the connection CritSect held.

Method NetComConnection.CheckSndQueueLow, uses xsi
  SetObject xsi
  mov eax, [xsi].dSndQueuedIOJobs
  .if eax <= [xsi].dSndLowWtrMrk
    BitClr [xsi].dFlags, NCC_SND_PAUSED
    .ifBitSet [xsi].dFlags, NCC_SND_QUEUE_HIGH
      BitClr [xsi].dFlags, NCC_SND_QUEUE_HIGH
      OCall [xsi].pProtocol::NetComProtocol.OnSendQueueLow, xsi
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.PauseReceive
; Purpose:    Pauses the receive direction (flow control). The outstanding receive (if any)
;             still completes and is processed, but no new WSARecv is posted. Incoming data then
;             stays in the TCP receive buffer and the zero receive window throttles the peer.
;             Typical use: a proxy whose outgoing side cannot keep up (send high-water mark).
; Arguments:  None.
; Return:     Nothing.
; Note:       - Call ResumeReceive when the protocol can consume data again.
;             - While paused, a peer FIN/RST is noticed only after ResumeReceive.
;             - Disconnect lifts the pause, Close ignores it.
;             - NetComSupervisor: no inactivity timeout while paused, dRcvPauseTimeout instead.

Method NetComConnection.PauseReceive, uses xsi
  SetObject xsi
  invoke EnterCriticalSection, [xsi].pCritSect
  .ifBitClr [xsi].dFlags, NCC_RCV_PAUSED
    BitSet [xsi].dFlags, NCC_RCV_PAUSED
    invoke GetSystemTimeAsFileTime, addr [xsi].PauseTime
  .endif
  invoke LeaveCriticalSection, [xsi].pCritSect
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.ResumeReceive
; Purpose:    Ends a receive pause and posts a receive if none is outstanding and the stream is
;             still open.
; Arguments:  None.
; Return:     Nothing.
; Note:       Data already buffered in the RcvIOJobChain / PlaintextChain is not processed again
;             here; the protocol is called with the next completed receive.

Method NetComConnection.ResumeReceive, uses xsi
  SetObject xsi
  invoke EnterCriticalSection, [xsi].pCritSect
  .ifBitSet [xsi].dFlags, NCC_RCV_PAUSED
    BitClr [xsi].dFlags, NCC_RCV_PAUSED
    invoke GetSystemTimeAsFileTime, addr [xsi].LastTime ;The pause was no peer inactivity
    ;No receive after a peer FIN (would report it twice) or a local receive shutdown
    .ifBitClr [xsi].dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY or NCC_SHUTDOWN_SND_REMOTE or \
                            NCC_SHUTDOWN_RCV_LOCAL
      OCall xsi.QueueReceive                            ;Posts only if none is outstanding
    .endif
  .endif
  invoke LeaveCriticalSection, [xsi].pCritSect
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueAccept
; Purpose:    Queues an accept IOJOB.
; Arguments:  Arg1: -> LISTENER.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.QueueAccept, uses xbx xdi xsi, pListener:PLISTENER
  local dBytesReceived:DWORD

  SetObject xsi
;  DbgText "NetComConnection.QueueAccept", addr [xsi].wName

  ;Allocate an IOJob to represent the accept IO operation
  mov xcx, [xsi].pOwner
  OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_ACCEPT
  ;DbgHex xax, "NetComConnection.QueueAccept - Acceptor IOJob"
  .if xax == NULL
    OCall xsi.ErrorReport, NULL, WSA_NOT_ENOUGH_MEMORY
    mov eax, WSA_NOT_ENOUGH_MEMORY
    ExitMethod
  .endif
  mov xdi, xax

  invoke EnterCriticalSection, [xsi].pCritSect

  invoke MemZero, addr [xdi].IOJOB.DataBuffer.ACCEPT_DATA.LocalAddr, sizeof(ACCEPT_DATA.LocalAddr)
  invoke MemZero, addr [xdi].IOJOB.DataBuffer.ACCEPT_DATA.RemoteAddr, sizeof(ACCEPT_DATA.RemoteAddr)
  mrm [xdi].IOJOB.DataBuffer.ACCEPT_DATA.pListener, pListener, xcx   ;xcx -> LISTENER
  mov [xdi].IOJOB.DataBuffer.ACCEPT_DATA.pConnection, xsi
  BitClr [xsi].dFlags, NCE_ACCEPT
  BitSet [xsi].dFlags, NCC_QUEUE_ACCEPT
  ;if ReceiveDataLength = 0, AcceptEx completes as soon as a connection arrives,
  ;without waiting for any data. Local and remote addresses are written into the buffer
  invoke AcceptEx, [xcx].LISTENER.hSocket, [xsi].hSocket, [xdi].IOJOB.WSABuf.buf, 0, \
                   sizeof ACCEPT_DATA.LocalAddr, sizeof ACCEPT_DATA.RemoteAddr, \
                   addr dBytesReceived, xdi
  ;AcceptEx returns a BOOL: TRUE = completed synchronously (the completion is posted anyway),
  ;FALSE = pending or failed
  .if eax == FALSE
    invoke WSAGetLastError
    .if eax == ERROR_IO_PENDING
      xor eax, eax                                      ;Not an error
    .endif
  .else
    xor eax, eax
  .endif

  .if eax == 0
    inc [xsi].dPendingIOJobs
  .endif
  mov ebx, eax

  ;Report an immediate failure while the CritSect is held (OnError runs protocol code)
  .if ebx != 0
    OCall xsi.OnError, xdi, ebx                         ;pIOJob
  .endif

  invoke LeaveCriticalSection, [xsi].pCritSect

  mov eax, ebx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueDestroy
; Purpose:    Mark a NetCom connection to destroy.
; Arguments:  None.
; Return:     Nothing.

Method NetComConnection.QueueDestroy, uses xsi
  SetObject xsi
;  DbgText "NetComConnection.QueueDestroy", addr [xsi].wName
  invoke EnterCriticalSection, [xsi].pCritSect      ;dFlags is changed by the workers too
  BitSet [xsi].dFlags, NCC_QUEUE_DESTROY
  invoke LeaveCriticalSection, [xsi].pCritSect
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.ReadyToDestroy?
; Purpose:    Checks if a connection flagged with NCC_QUEUE_DESTROY can be destroyed now: no IOJob
;             is pending and the posted OnDisconnected/OnClosed completions have been delivered.
;             A connection that is not closed yet is closed here (Close posts these completions),
;             it can be destroyed by a later check. A lock owner additionally waits until no
;             partner (NewPartner) uses its CritSect any more.
; Arguments:  None.
; Return:     eax = TRUE if the connection can be destroyed, otherwise FALSE.
; Note:       Must be called with the connection CritSect held. FreeRessources must only follow a
;             TRUE result, otherwise its Close would post completions for a released connection.

Method NetComConnection.ReadyToDestroy?, uses xsi
  SetObject xsi
  xor eax, eax
  .ifBitSet [xsi].dFlags, NCC_QUEUE_DESTROY
    .if [xsi].dPendingIOJobs == 0
      .ifBitClr [xsi].dFlags, NCC_CLOSED
        OCall xsi.Close, TRUE                           ;Abortive, posts the completions
        xor eax, eax
      .else
        ;NCC_CLOSED => OnClosed was posted and must have been delivered
        mov ecx, [xsi].dFlags
        test ecx, NCC_CLOSED_DELIVERED
        jz @@Exit
        test ecx, NCC_DISCONNECT_POSTED
        jz @@Ready
        test ecx, NCC_DISCONNECTED_DELIVERED
        jz @@Exit
      @@Ready:
        cmp [xsi].dLockUsers, 0                         ;A partner still uses our CritSect
        jne @@Exit
        mov eax, TRUE
      .endif
    .endif
  .endif
@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueConnect
; Purpose:    Queue a connect IOJOB.
; Arguments:  Arg1: -> Remote address.
;             Arg2: -> Local address. If NULL, not binding is performed.
; Return:     eax = Zero if succeeded, otherwise an error code.
; Note:       On failure nothing is queued and OnError is not called. The caller must discard the
;             connection with NetComEngine.DiscardConnection.

Method NetComConnection.QueueConnect, uses xbx xdi xsi, pRemoteAddr:PNETCOMADDR, \
                                                        pLocalAddr:PNETCOMADDR
  local dOption:DWORD, dError:DWORD

  SetObject xsi
  ;Here we can change the returning port
  mov dOption, 1
  invoke setsockopt, [xsi].hSocket, SOL_SOCKET, SO_REUSEADDR, addr dOption, sizeof dOption
;  DbgCheckSockReturn "NetComConnection.QueueConnect- ERROR on SetSockOpt SO_REUSEADDR"

  invoke MemClone, addr [xsi].RemoteAddr, pRemoteAddr, sizeof NETCOMADDR

  ;Associate a local address with the socket
  .if pLocalAddr != NULL
    invoke MemClone, addr [xsi].LocalAddr, pLocalAddr, sizeof NETCOMADDR
    BitSet [xsi].dFlags, NCC_BIND
    invoke bind, [xsi].hSocket, pLocalAddr, sizeof NETCOMADDR
    .if eax == SOCKET_ERROR
      invoke WSAGetLastError
      mov dError, eax
      DbgSockError "NetComConnection.QueueConnect - BIND result", eax,, addr [xsi].wName
      ;In this case, nothing is queued to the IOCP. ConnectEx would fail.
      mov eax, dError
      ExitMethod
    .endif
    BitSet [xsi].dFlags, NCC_BOUND
  .endif

;  DbgNetComAddrIPV4 [xsi].LocalAddr, "NetComConnection.QueueConnect - LocalAddr", addr [xsi].wName
;  DbgNetComAddrIPV4 [xsi].RemoteAddr,"NetComConnection.QueueConnect - RemoteAddr",addr [xsi].wName

  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_CONNECT
  .if xax == NULL
    OCall xsi.ErrorReport, NULL, WSA_NOT_ENOUGH_MEMORY
    mov eax, WSA_NOT_ENOUGH_MEMORY
    ExitMethod
  .endif
  mov xdi, xax

  invoke EnterCriticalSection, [xsi].pCritSect

  m2z [xdi].IOJOB.WSABuf.len                            ;Size MUST be zero
  BitClr [xsi].dFlags, NCE_CONNECT
  BitSet [xsi].dFlags, NCC_QUEUE_CONNECT
  invoke PTYP_CONNECTEX ptr pConnectEx, [xsi].hSocket, pRemoteAddr, sizeof NETCOMADDR, \
                                       NULL, 0, NULL, xdi
  ;ConnectEx returns a BOOL: TRUE = completed synchronously (the completion is posted anyway),
  ;FALSE = pending or failed
  .if eax == FALSE
    invoke WSAGetLastError
    .if eax == ERROR_IO_PENDING
      xor eax, eax                                      ;Not an error
    .endif
  .else
    xor eax, eax
  .endif

  .if eax == 0
    inc [xsi].dPendingIOJobs
  .else
    BitClr [xsi].dFlags, NCC_QUEUE_CONNECT
  .endif
  mov ebx, eax

  invoke LeaveCriticalSection, [xsi].pCritSect

  .if ebx != 0
    ;Nothing was queued: return the IOJob. No OnError here, the caller discards the connection.
    mov xcx, [xsi].pOwner                               ;xcx -> NetComConnectionPool
    OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xdi
  .endif

  mov eax, ebx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueReceive
; Purpose:    Queue a read IOJOB.
; Arguments:  None.
; Return:     eax = Zero if succeeded, otherwise an error code.
; Note:       Nothing is posted while the receive is paused (ResumeReceive posts it) or if a
;             receive is already outstanding (only one WSARecv per connection at a time).

Method NetComConnection.QueueReceive, uses xsi
  local dResult:DWORD

  SetObject xsi
;  DbgText "NetComConnection.QueueReceive", addr [xsi].wName
  mov dResult, 0
  invoke EnterCriticalSection, [xsi].pCritSect
  .ifBitClr [xsi].dFlags, NCC_RCV_PAUSED
    .if [xsi].dRcvQueuedIOJobs == 0
      mov xcx, [xsi].pOwner
      OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_RECV
      .if xax == NULL
        OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
        mov dResult, NCCN_OUT_OF_MEMORY
      .else
        OCall xsi.DoRcvIOJob, xax                       ;dRcvQueuedIOJobs is incr. inside DoRcvIOJob
        mov dResult, eax
      .endif
    .endif
  .endif
  invoke LeaveCriticalSection, [xsi].pCritSect
  mov eax, dResult
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueSend
; Purpose:    Copy the information pointed to by pData to the send buffers and queue a
;             Send operation on each one.
;             With TLS, application data is NEVER sent unencrypted:
;               - TLS_STATE_DATA:            encrypted via QueueSendTLS.
;               - TLS_STATE_NONE/HANDSHAKE:  copied to PendingSendChain and sent encrypted as soon
;                                            as the handshake has completed (FlushPendingTLS).
;               - TLS_STATE_SHUTDOWN/ERROR:  rejected (0 BYTEs queued).
;             All TLS send operations are serialized with the connection CritSect (shared
;             encryption buffer, record sequence). The CritSect is recursive, so calls from
;             protocol callbacks running inside OnReceivedTLS are safe.
; Arguments:  Arg1: -> Data buffer.
;             Arg2: Data size in BYTEs.
; Return:     eax = Number of queued BYTEs.

Method NetComConnection.QueueSend, uses xbx xdi xsi, pData:POINTER, dSize:DWORD
  local dResult:DWORD, pItem:PIOJOB, dChunk:DWORD

  SetObject xsi
;  DbgText "NetComConnection.QueueSend", addr [xsi].wName

  ; === TLS Dispatch ===
  .if [xsi].pTLSContext != NULL
    invoke EnterCriticalSection, [xsi].pCritSect
    mov dResult, 0
    OCall [xsi].pTLSContext::TLS_Context.GetState
    .if eax == TLS_STATE_DATA
      ;Data held back during the handshake goes first to preserve the byte order
      OCall xsi.FlushPendingTLS
      .ifBitClr [xsi].dFlags, NCC_SND_PAUSED            ;Backpressure check before encryption
        OCall xsi.QueueSendTLS, pData, dSize
        mov dResult, eax
      .endif

    .elseif eax == TLS_STATE_HANDSHAKE || eax == TLS_STATE_NONE
      ;Hold the plaintext back until the handshake is complete
      mov xbx, pData
      mov edi, dSize
      .while edi != 0
        mov xcx, [xsi].pOwner                           ;xcx -> NetComConnectionPool
        OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_SEND
        .if xax == NULL
          OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
          .break
        .endif
        mov pItem, xax
        mov xcx, [xsi].pOwner
        mov xcx, [xcx].$Obj(NetComConnectionPool).pIOJobPool
        mov eax, [xcx].$Obj(NetComIOJobPool).dBufferSize
        .if eax > edi
          mov eax, edi
        .endif
        mov dChunk, eax
        mov xax, pItem
        m2m [xax].IOJOB.WSABuf.len, dChunk, ecx
        invoke MemClone, [xax].IOJOB.WSABuf.buf, xbx, dChunk
        mov xax, pItem
        lea xcx, [xax].IOJOB.pNextItem
        lea xax, [xsi].PendingSendChain
        SDLL_Append xax, xcx, xdx
        mov eax, dChunk
        add xbx, xax
        sub edi, eax
        add dResult, eax
      .endw
    .endif
    ;TLS_STATE_SHUTDOWN / TLS_STATE_ERROR: nothing is sent, dResult = 0
    invoke LeaveCriticalSection, [xsi].pCritSect
    mov eax, dResult
    ExitMethod
  .endif

  ; --- Non-TLS ---
  OCall xsi.QueueSendRaw, pData, dSize
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueSendRaw
; Purpose:    Copy the information pointed to by pData to the send buffers and queue a
;             Send operation on each one, WITHOUT any TLS processing.
;             Used for non-TLS connections and by TLS_Context for handshake/shutdown tokens.
; Arguments:  Arg1: -> Data buffer.
;             Arg2: Data size in BYTEs.
; Return:     eax = Number of queued BYTEs.

Method NetComConnection.QueueSendRaw, uses xbx xdi xsi, pData:POINTER, dSize:DWORD
  local dBufferSize:DWORD, pItem:PIOJOB, dResult:DWORD

  SetObject xsi
  mov edi, dSize

  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  mov xdx, [xcx].$Obj(NetComConnectionPool).pIOJobPool  ;xdx -> NetComIOJobPool
  m2m dBufferSize, [xdx].$Obj(NetComIOJobPool).dBufferSize, eax

  ;Application threads call this too: the CritSect keeps the chunks of one call together and
  ;lets OnError (immediate send failure) run serialized with the workers (recursive CritSect)
  invoke EnterCriticalSection, [xsi].pCritSect
  .while edi != 0
    ;Check if we are allowed to send
    .ifBitSet [xsi].dFlags, NCC_SND_PAUSED or NCC_CLOSED
      .break
    .endif

    mov xcx, [xsi].pOwner                               ;xcx -> NetComConnectionPool
    OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_SEND
    .if xax != NULL
      mov pItem, xax
      .if dBufferSize < edi
        ;Send a full buffer and cycle again
        m2m [xax].IOJOB.WSABuf.len, dBufferSize, edx
        invoke MemClone, [xax].IOJOB.WSABuf.buf, pData, dBufferSize
        OCall xsi.DoSndIOJob, pItem
        .break .if eax != NO_ERROR
        mov edx, dBufferSize
        sub edi, edx
        add pData, xdx
      .else
        ;Send a partially full buffer and break
        mov [xax].IOJOB.WSABuf.len, edi
        invoke MemClone, [xax].IOJOB.WSABuf.buf, pData, edi
        OCall xsi.DoSndIOJob, pItem
        .break .if eax != NO_ERROR
        xor edi, edi
        .break
      .endif
    .else
      OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
      .break
    .endif
  .endw
  mov eax, dSize
  sub eax, edi
  mov dResult, eax
  invoke LeaveCriticalSection, [xsi].pCritSect
  mov eax, dResult
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.FlushPendingTLS
; Purpose:    Encrypts and sends all plaintext that was held back in PendingSendChain while the
;             TLS handshake was in progress. Ignores NCC_SND_PAUSED (this data was already
;             accepted by QueueSend).
; Arguments:  None.
; Return:     Nothing.
; Note:       Must be called with the connection CritSect held and TLS state = TLS_STATE_DATA.

Method NetComConnection.FlushPendingTLS, uses xbx xdi xsi
  local pFreeJob:PIOJOB, pBuf:POINTER, dLen:DWORD

  SetObject xsi
  lea xdi, [xsi].PendingSendChain                       ;xdi -> Sentinel
  mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
  .while xbx != xdi
    lea xcx, [xbx - IOJOB_HEADER_SIZE]                  ;xcx -> IOJob
    mov pFreeJob, xcx
    m2m pBuf, [xcx].IOJOB.WSABuf.buf, xax
    m2m dLen, [xcx].IOJOB.WSABuf.len, eax
    mov xbx, [xbx].SDLL_ITEM.pNextItem                  ;Advance before removing
    mov xax, pFreeJob
    lea xax, [xax].IOJOB.pNextItem
    SDLL_Remove xax, xcx, xdx
    OCall xsi.QueueSendTLS, pBuf, dLen
    mov xcx, [xsi].pOwner
    OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pFreeJob
  .endw
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnReceivedTLS
; Purpose:    Chain-based TLS receive processing. Iterates the RcvIOJobChain from the front,
;             copies completed IOJobs sequentially into the TLS_Context reassembly buffer,
;             and invokes the appropriate SSPI operation based on TLS state.
;             This design guarantees correct ordering regardless of IOCP completion delivery order.
;             The method cycles until no further progress is possible:
;               - IOJobs are drained partially if the reassembly buffer is (almost) full, so a
;                 large IOJob can never block the stream.
;               - All complete handshake messages / TLS records in the buffer are processed,
;                 not only the first one.
;               - Data following the last handshake message (SECBUFFER_EXTRA) is decrypted
;                 immediately after the handshake has completed.
; Arguments:  Arg1: -> IOJOB (the IOJob that just completed - used only as trigger).
; Return:     Nothing.
; Note:       Called only when pTLSContext != NULL. CritSect is entered/left internally.

Method NetComConnection.OnReceivedTLS, uses xbx xdi xsi, pIOJob:PIOJOB
  local pPlaintext:POINTER, dPlaintextSize:DWORD
  local pTLSCtx:POINTER, pFreeJob:PIOJOB
  local dCopied:DWORD, dChunk:DWORD, dBefore:DWORD, bFirstPass:DWORD, dDeliverResult:DWORD

  SetObject xsi
  invoke EnterCriticalSection, [xsi].pCritSect

  ; Cache TLS context pointer
  mov xax, [xsi].pTLSContext
  mov pTLSCtx, xax
  mov bFirstPass, TRUE

@@Cycle:
  ; --- Step 1: Drain completed IOJobs from the Chain into the Reassembly Buffer ---
  ; Iterate chain from the front. Only process consecutive completed IOJobs.
  ; Stop at the first non-completed IOJob (preserves ordering guarantee).
  ; If an IOJob does not fit completely, copy what fits and keep the rest in the IOJob.
  mov dCopied, 0
  lea xdi, [xsi].RcvIOJobChain                          ;xdi = Sentinel
  mov xbx, [xdi].SDLL_SENTINEL.pFirstItem               ;xbx = first chain item (SDLL_ITEM ptr)
  .while xbx != xdi
    lea xcx, [xbx - IOJOB_HEADER_SIZE]                  ;xcx -> IOJOB
    mov pFreeJob, xcx
    .ifBitClr [xcx].IOJOB.wFlags, IOF_JOB_COMPLETED
      .break                                            ;Not yet completed - stop here
    .endif

    ; Determine how many BYTEs fit into the reassembly buffer
    mov xdx, pTLSCtx
    .break .if [xdx].$Obj(TLS_Context).pReassemblyBuffer == NULL
    mov eax, [xdx].$Obj(TLS_Context).dReassemblyCapacity
    sub eax, [xdx].$Obj(TLS_Context).dReassemblyUsed
    .break .if eax == 0                                 ;Buffer full - process first
    .if eax > [xcx].IOJOB.dBytesConsumed
      mov eax, [xcx].IOJOB.dBytesConsumed
    .endif
    mov dChunk, eax

    ; Copy IOJob data into reassembly buffer at current offset
    mov xax, [xdx].$Obj(TLS_Context).pReassemblyBuffer
    mov edx, [xdx].$Obj(TLS_Context).dReassemblyUsed
    add xax, xdx                                        ;xax = destination
    mov xdx, [xcx].IOJOB.WSABuf.buf                     ;xdx = source
    invoke MemClone, xax, xdx, dChunk

    ; Update dReassemblyUsed
    mov xdx, pTLSCtx
    mov eax, dChunk
    add [xdx].$Obj(TLS_Context).dReassemblyUsed, eax
    add dCopied, eax

    mov xcx, pFreeJob
    .if eax == [xcx].IOJOB.dBytesConsumed
      ; IOJob completely consumed: remove it from the chain and return it to the pool
      mov xbx, [xbx].SDLL_ITEM.pNextItem                ;Advance xbx to next BEFORE removing
      lea xax, [xcx].IOJOB.pNextItem                    ;xax -> SDLL_ITEM of this IOJob
      SDLL_Remove xax, xdx, xcx
      mov xcx, [xsi].pOwner
      OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pFreeJob
    .else
      ; IOJob partially consumed: keep the remainder for the next cycle
      add [xcx].IOJOB.WSABuf.buf, xax
      sub [xcx].IOJOB.dBytesConsumed, eax
      .break
    .endif
  .endw

  ; Stop when a further cycle brought no new data
  .if dCopied == 0 && bFirstPass == FALSE
    jmp @@Done
  .endif
  mov bFirstPass, FALSE

  ; --- Step 2: Process accumulated data based on TLS state ---
  OCall pTLSCtx::TLS_Context.GetState
  DbgDec eax, "TLS State"

  .if eax == TLS_STATE_SHUTDOWN
    ; --- TLS Shutdown in progress ---
    ; Peer's close_notify response received (or we responded to peer's close_notify).
    ; ISC/ASC cannot process shutdown records - do NOT call ProcessHandshakeData.
    ; Just clear the reassembly buffer and complete the TCP-level disconnect.
    mov xbx, pTLSCtx
    mov [xbx].$Obj(TLS_Context).dReassemblyUsed, 0

    ; If WE initiated the TLS Shutdown, complete the TCP-level disconnect
    .ifBitSet [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
      BitClr [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
      invoke shutdown, [xsi].hSocket, SD_SEND
      BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
      .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
        BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
        mov [xsi].dDisconnectError, NO_ERROR
        mov [xsi].dDisconnectDirection, SD_SEND
        mov xcx, [xsi].pOwner
        mov xax, [xcx].$Obj(NetComConnectionPool).pOwner
        invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
               0, COMPLETION_KEY_DISCONNECTED, xsi
      .endif
    .endif
    jmp @@Done

  .elseif eax == TLS_STATE_HANDSHAKE
    jmp @@HandshakeLoop

  .elseif eax == TLS_STATE_DATA
    jmp @@DecryptLoop

  .elseif eax == TLS_STATE_ERROR
    ; --- Error state: flush remaining chain IOJobs (error was already reported) ---
    lea xdi, [xsi].RcvIOJobChain
    mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
    .while xbx != xdi
      lea xcx, [xbx - IOJOB_HEADER_SIZE]
      mov xbx, [xbx].SDLL_ITEM.pNextItem
      .ifBitSet [xcx].IOJOB.wFlags, IOF_JOB_COMPLETED
        mov pFreeJob, xcx
        lea xax, [xcx].IOJOB.pNextItem
        SDLL_Remove xax, xcx, xdx
        mov xdx, [xsi].pOwner
        OCall [xdx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pFreeJob
      .endif
    .endw
    mov xbx, pTLSCtx
    mov [xbx].$Obj(TLS_Context).dReassemblyUsed, 0
  .endif
  jmp @@Done                                            ;TLS_STATE_ERROR / TLS_STATE_NONE


  ; ==========================================================================================
  ; Handshake: process all complete handshake messages that are in the reassembly buffer
  ; ==========================================================================================
@@HandshakeLoop:
  mov xbx, pTLSCtx
  mov eax, [xbx].$Obj(TLS_Context).dReassemblyUsed
  .if eax == 0
    jmp @@Cycle                                         ;Need more data
  .endif
  mov dBefore, eax
  OCall pTLSCtx::TLS_Context.ProcessHandshakeData, \
        [xbx].$Obj(TLS_Context).pReassemblyBuffer, \
        [xbx].$Obj(TLS_Context).dReassemblyUsed, xsi

@@AfterHandshakeStep:
  OCall pTLSCtx::TLS_Context.GetState
  .if eax == TLS_STATE_DATA
    ; Handshake complete: send held-back application data, then decrypt what followed
    ; the last handshake message (SECBUFFER_EXTRA was moved to the buffer start)
    OCall xsi.FlushPendingTLS
    jmp @@DecryptLoop
  .elseif eax == TLS_STATE_HANDSHAKE
    mov xbx, pTLSCtx
    mov eax, [xbx].$Obj(TLS_Context).dReassemblyUsed
    .if eax != 0 && eax != dBefore
      jmp @@HandshakeLoop                               ;Progress made, more data left
    .endif
    jmp @@Cycle                                         ;Incomplete message - need more data
  .endif
  jmp @@Done                                            ;Handshake failed (already reported)


  ; ==========================================================================================
  ; Data phase: decrypt all complete TLS records that are in the reassembly buffer
  ; ==========================================================================================
@@DecryptLoop:
  mov xbx, pTLSCtx
  mov eax, [xbx].$Obj(TLS_Context).dReassemblyUsed
  DbgDec eax, "DATA: ResBuf"
  .if eax == 0
    jmp @@Cycle                                         ;No data to process
  .endif
  mov dBefore, eax
  ; Clear deferred extra before Decrypt (will be set if EXTRA data exists)
  mov [xbx].$Obj(TLS_Context).pDeferredExtra, NULL
  OCall pTLSCtx::TLS_Context.Decrypt, \
        [xbx].$Obj(TLS_Context).pReassemblyBuffer, \
        [xbx].$Obj(TLS_Context).dReassemblyUsed, \
        addr pPlaintext, addr dPlaintextSize

  .if eax != OBJ_OK
    ; Fatal decrypt error: the TLS stream is unusable => report and abort (a graceful
    ; disconnect left the connection alive until a supervisor timeout)
    OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, TLS_DECRYPT_ERROR
    OCall xsi.QueueDestroy
    OCall xsi.Close, TRUE
    jmp @@Done
  .endif

  ; Hand plaintext to the protocol (split into IOJob sized pieces)
  mov dDeliverResult, 0
  .if dPlaintextSize != 0 && pPlaintext != NULL
    OCall xsi.DeliverPlaintext, pPlaintext, dPlaintextSize
    mov dDeliverResult, eax
  .endif

  ; Execute deferred EXTRA shift now that the plaintext was consumed.
  ; This must also happen if the record contained no plaintext!
  mov xbx, pTLSCtx
  .if [xbx].$Obj(TLS_Context).pDeferredExtra != NULL
    invoke MemShift, [xbx].$Obj(TLS_Context).pReassemblyBuffer, \
                     [xbx].$Obj(TLS_Context).pDeferredExtra, \
                     [xbx].$Obj(TLS_Context).dReassemblyUsed
    mov xbx, pTLSCtx
    mov [xbx].$Obj(TLS_Context).pDeferredExtra, NULL
  .endif

  .if dDeliverResult != 0
    jmp @@Done                                          ;Protocol closed the connection
  .endif

  ; Check state transitions signalled by Decrypt
  OCall pTLSCtx::TLS_Context.GetState
  .if eax == TLS_STATE_DATA
    mov xbx, pTLSCtx
    mov eax, [xbx].$Obj(TLS_Context).dReassemblyUsed
    .if eax != 0 && eax != dBefore
      jmp @@DecryptLoop                                 ;More records in the buffer
    .endif
    jmp @@Cycle                                         ;Incomplete record - need more data

  .elseif eax == TLS_STATE_SHUTDOWN
    ; Peer sent close_notify - respond unless peer already sent FIN (half-close)
    .ifBitClr [xsi].dFlags, NCC_SHUTDOWN_SND_REMOTE
      ; Peer socket still open - send our own close_notify (RFC 8446)
      OCall pTLSCtx::TLS_Context.Shutdown, xsi
    .endif
    invoke shutdown, [xsi].hSocket, SD_SEND
    BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
    .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
      BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
      mov [xsi].dDisconnectError, NO_ERROR
      mov [xsi].dDisconnectDirection, SD_RECEIVE
      mov xcx, [xsi].pOwner
      mov xax, [xcx].$Obj(NetComConnectionPool).pOwner
      invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
             0, COMPLETION_KEY_DISCONNECTED, xsi
    .endif
    jmp @@Done

  .elseif eax == TLS_STATE_HANDSHAKE
    ; Renegotiation (TLS 1.2) or post-handshake message (TLS 1.3, e.g. NewSessionTicket).
    ; Decrypt moved any EXTRA data to the buffer start. ISC/ASC must be called once even
    ; with 0 bytes input (TLS 1.2 renegotiation: generates our ClientHello).
    mov xbx, pTLSCtx
    m2m dBefore, [xbx].$Obj(TLS_Context).dReassemblyUsed, eax
    OCall pTLSCtx::TLS_Context.ProcessHandshakeData, \
          [xbx].$Obj(TLS_Context).pReassemblyBuffer, \
          [xbx].$Obj(TLS_Context).dReassemblyUsed, xsi
    jmp @@AfterHandshakeStep
  .endif

@@Done:
  invoke LeaveCriticalSection, [xsi].pCritSect
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.DeliverPlaintext
; Purpose:    Copies decrypted data into IOJobs (split by the IOJob buffer size), appends them
;             to the PlaintextChain and lets the protocol process them (IsDataComplete? /
;             ProcessData), exactly like received IOJobs on a non-TLS connection.
; Arguments:  Arg1: -> Plaintext.
;             Arg2: Plaintext size in BYTEs.
; Return:     eax = Zero to continue, otherwise the connection is being closed.
; Note:       Called from OnReceivedTLS with the connection CritSect held.

Method NetComConnection.DeliverPlaintext, uses xbx xdi xsi, pPlain:POINTER, dSize:DWORD
  local dBufferSize:DWORD, dChunk:DWORD, dConsumed:DWORD, pItem:PIOJOB

  SetObject xsi
  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  mov xcx, [xcx].$Obj(NetComConnectionPool).pIOJobPool  ;xcx -> NetComIOJobPool
  m2m dBufferSize, [xcx].$Obj(NetComIOJobPool).dBufferSize, eax

  .while dSize != 0
    mov xcx, [xsi].pOwner
    OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_RECV
    .if xax == NULL
      ; Decrypted data cannot be delivered => the stream is broken
      OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
      OCall xsi.QueueDestroy
      OCall xsi.Close, TRUE
      mov eax, NCCN_OUT_OF_MEMORY
      ExitMethod
    .endif
    mov pItem, xax

    ; Chunk = min(remaining, IOJob buffer size)
    mov eax, dSize
    .if eax > dBufferSize
      mov eax, dBufferSize
    .endif
    mov dChunk, eax
    mov xax, pItem
    invoke MemClone, [xax].IOJOB.WSABuf.buf, pPlain, dChunk
    mov xbx, pItem
    m2m [xbx].IOJOB.dBytesConsumed, dChunk, eax
    mov eax, dChunk
    add pPlain, xax
    sub dSize, eax

    ; Append to PlaintextChain
    lea xcx, [xbx].IOJOB.pNextItem
    lea xax, [xsi].PlaintextChain
    SDLL_Append xax, xcx, xdx

    ; Let protocol process accumulated plaintext from PlaintextChain
    OCall [xsi].pProtocol::NetComProtocol.IsDataComplete?, xsi, xbx
    .if eax == ERROR_BAD_PROTOCOL || eax == ERROR_USER_QUIT
      OCall xsi.Disconnect, SD_BOTH
      OCall xsi.QueueDestroy
      OCall xsi.Close, TRUE
      mov eax, ERROR_USER_QUIT
      ExitMethod
    .elseif eax != 0
      OCall [xsi].pProtocol::NetComProtocol.ProcessData, xsi, eax
      .if eax != 0
        ; Remove consumed IOJobs from PlaintextChain
        mov dConsumed, eax
        lea xdi, [xsi].PlaintextChain
        mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
        .while xbx != xdi && dConsumed != 0
          mov edx, [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed
          .if edx <= dConsumed
            sub dConsumed, edx
            mov xcx, [xsi].pOwner
            lea xdx, [xbx - IOJOB_HEADER_SIZE]
            mov xbx, [xbx].SDLL_ITEM.pNextItem
            OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xdx
            .break .if dConsumed == 0
          .else
            mov ecx, dConsumed
            add [xbx - IOJOB_HEADER_SIZE].IOJOB.WSABuf.buf, xcx
            sub [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed, ecx
            .break
          .endif
        .endw
        mov [xdi].SDLL_SENTINEL.pFirstItem, xbx
        mov [xbx].SDLL_ITEM.pPrevItem, xdi
      .endif
    .endif
  .endw
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueSendTLS
; Purpose:    Encrypt plaintext data and send via IOJobs. Fragments into TLS record blocks
;             of at most cbMaximumMessage bytes. Each encrypted block is sent atomically.
; Arguments:  Arg1: -> Plaintext data buffer.
;             Arg2: Data size in BYTEs.
; Return:     eax = Number of plaintext BYTEs successfully queued for sending.
; Note:       Called only when TLS state is TLS_STATE_DATA, with the connection CritSect held.

Method NetComConnection.QueueSendTLS, uses xbx xdi xsi, pData:POINTER, dSize:DWORD
  local dBufferSize:DWORD, pItem:PIOJOB
  local pEncrypted:POINTER, dEncryptedSize:DWORD
  local dBlockSize:DWORD, dPlainBlockSize:DWORD
  local pEncData:POINTER, dEncDataRemaining:DWORD

  SetObject xsi
  mov edi, dSize

  ; Backpressure check is done by the caller (QueueSend) BEFORE calling this method, so that
  ; FlushPendingTLS can always deliver data that was already accepted.

  ; Get cbMaximumMessage for block fragmentation
  mov xbx, [xsi].pTLSContext
  mov eax, [xbx].$Obj(TLS_Context).dMaxMessageSize
  .if eax == 0                                          ;Stream sizes not known => no TLS session
    xor eax, eax
    ExitMethod
  .endif
  mov dBlockSize, eax

  ; Get IOJob buffer size
  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  mov xdx, [xcx].$Obj(NetComConnectionPool).pIOJobPool  ;xdx -> NetComIOJobPool
  m2m dBufferSize, [xdx].$Obj(NetComIOJobPool).dBufferSize, eax

  ; Fragment plaintext into blocks <= cbMaximumMessage, encrypt each, send encrypted
  .while edi != 0
    ; Determine this block's plaintext size (min of remaining and cbMaximumMessage)
    mov eax, edi
    .if eax > dBlockSize
      mov eax, dBlockSize
    .endif
    mov dPlainBlockSize, eax

    ; Encrypt this block via TLS_Context.Encrypt
    OCall [xsi].pTLSContext::TLS_Context.Encrypt, pData, dPlainBlockSize, \
          addr pEncrypted, addr dEncryptedSize
    .if eax != OBJ_OK
      OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, TLS_ENCRYPT_ERROR
      .break
    .endif

    ; Send the encrypted block via IOJob fragmentation
    m2m pEncData, pEncrypted, xax
    m2m dEncDataRemaining, dEncryptedSize, eax

    .while dEncDataRemaining != 0
      mov xcx, [xsi].pOwner                             ;xcx -> NetComConnectionPool
      OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_SEND
      .if xax != NULL
        mov pItem, xax
        mov edx, dEncDataRemaining
        .if dBufferSize < edx
          ;Send a full IOJob buffer and cycle again
          m2m [xax].IOJOB.WSABuf.len, dBufferSize, edx
          invoke MemClone, [xax].IOJOB.WSABuf.buf, pEncData, dBufferSize
          OCall xsi.DoSndIOJob, pItem
          .if eax != NO_ERROR
            sub edi, dPlainBlockSize
            jmp @@Done
          .endif
          mov edx, dBufferSize
          sub dEncDataRemaining, edx
          add pEncData, xdx
        .else
          ;Send the remaining encrypted data
          m2m [xax].IOJOB.WSABuf.len, dEncDataRemaining, edx
          invoke MemClone, [xax].IOJOB.WSABuf.buf, pEncData, dEncDataRemaining
          OCall xsi.DoSndIOJob, pItem
          .if eax != NO_ERROR
            sub edi, dPlainBlockSize
            jmp @@Done
          .endif
          mov dEncDataRemaining, 0
        .endif
      .else
        OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
        sub edi, dPlainBlockSize
        jmp @@Done
      .endif
    .endw

    ; Encrypted block sent successfully - advance plaintext pointer
    mov eax, dPlainBlockSize
    sub edi, eax
    add pData, xax
  .endw

@@Done:
  mov eax, dSize
  sub eax, edi
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.ApplyTLSConfig
; Purpose:    Applies a TLS_Connection_Config to this connection's pTLSContext.
;             Called synchronously from OnConnected (client) or Admit (server) before the
;             TLS handshake starts. Transfers all non-NULL config values to the TLS_Context.
; Arguments:  Arg1: -> TLS_Connection_Config object.
; Return:     Nothing.

Method NetComConnection.ApplyTLSConfig, uses xbx xsi, pConfig:POINTER
  local pAlgs:POINTER, dCount:DWORD

  SetObject xsi
  mov xbx, pConfig
  .if xbx == NULL
    ExitMethod
  .endif

  ; TargetName (SNI)
  OCall xbx::TLS_Connection_Config.GetTargetName
  .if xax != NULL
    OCall [xsi].pTLSContext::TLS_Context.SetTargetName, xax
  .endif

  ; Allowed Protocols
  OCall xbx::TLS_Connection_Config.GetAllowedProtocols
  OCall [xsi].pTLSContext::TLS_Context.SetAllowedProtocols, eax

  ; CertValidator
  OCall xbx::TLS_Connection_Config.GetCertValidator
  .if xax != NULL
    OCall [xsi].pTLSContext::TLS_Context.SetCertValidator, xax
  .endif

  ; ServerCertProvider
  OCall xbx::TLS_Connection_Config.GetServerCertProvider
  .if xax != NULL
    OCall [xsi].pTLSContext::TLS_Context.SetServerCertProvider, xax
  .endif

  ; ClientCertProvider
  OCall xbx::TLS_Connection_Config.GetClientCertProvider
  .if xax != NULL
    OCall [xsi].pTLSContext::TLS_Context.SetClientCertProvider, xax
  .endif

  ; Cipher Suites
  OCall xbx::TLS_Connection_Config.GetCipherSuites, addr pAlgs, addr dCount
  .if pAlgs != NULL
    OCall [xsi].pTLSContext::TLS_Context.SetAllowedCipherSuites, pAlgs, dCount
  .endif

  ; VerifyServerName flag
  OCall xbx::TLS_Connection_Config.GetVerifyServerName
  OCall [xsi].pTLSContext::TLS_Context.SetVerifyServerName, eax

  ; Mutual authentication flag (server side: request + require a client certificate)
  OCall xbx::TLS_Connection_Config.GetMutualAuth
  OCall [xsi].pTLSContext::TLS_Context.SetMutualAuth, eax
MethodEnd

endif
