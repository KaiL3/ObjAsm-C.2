; ==================================================================================================
; Title:      NetComConnection.inc
; Author:     G. Friedrich
; Version:    C.1.0
; Purpose:    ObjAsm support of NetComConnection objects.
; Notes:      Version C.1.0, October 2017
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
        OCall [xsi].pTLSContext::TLS_Context.StartServerHandshake, xsi
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
; Method:     NetComConnection.Close
; Purpose:    Perform a graceful/abortive disconnection of a NetCom connection sending
;             a FIN/RST to the remote endpoint.
; Arguments:  Arg1: Abortive flag (TRUE/FALSE).
; Return:     Nothing.

Method NetComConnection.Close, uses xsi, dAbortive:DWORD
  local Linger:linger

  SetObject xsi
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
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.Disconnect
; Purpose:    Disconnect writing and/or reading.
; Arguments:  Arg1: Disconnect direction = SD_RECEIVE(0)/SD_SEND(1)/SD_BOTH(2)
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.Disconnect, uses xsi, dDirection:DWORD
  local dRetValue:DWORD

  SetObject xsi
;  DbgText "NetComConnection.Disconnect", addr [xsi].wName
  mov dRetValue, NO_ERROR
  xor eax, eax
  .ifBitClr [xsi].dFlags, NCC_CLOSED

    ; === TLS: Graceful close_notify ===
    .if [xsi].pTLSContext != NULL && dDirection != SD_RECEIVE
      OCall [xsi].pTLSContext::TLS_Context.GetState
      .if eax == TLS_STATE_DATA
        OCall [xsi].pTLSContext::TLS_Context.Shutdown, xsi
        BitSet [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
        invoke GetSystemTimeAsFileTime, addr [xsi].LastTime
        ; Kein TCP shutdown hier — warten auf Peer-Antwort oder Timeout
        ExitMethod
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
  invoke DeleteCriticalSection, addr [xsi].CritSect
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
  invoke EnterCriticalSection, addr [xsi].CritSect
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
  .endif
  mov ebx, eax

  invoke LeaveCriticalSection, addr [xsi].CritSect

  .if ebx != 0
    OCall xsi.OnError, xdi, ebx                         ;pIOJob
  .endif

  mov eax, ebx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.FreeRessources
; Purpose:    Free all ressources, including the gattered IOJobs.
; Arguments:  None.
; Return:     Nothing.
; Note:       This method works worhs together with Done to isolate the call DeleteCriticalSection.
;             At this point no pending IOJobs should exist!

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

Method NetComConnection.Init, uses xsi, pOwner:POINTER, pProtocol:POINTER
  local dOption:DWORD

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
  m2m [xsi].pProtocol, pProtocol, xax
  lea xax, [xsi].RcvIOJobChain
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
      DbgOnSockError "NetComConnection.Init - Failed to create socket", eax,, addr [xsi].wName
    .endif
  .endif
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

    ;Create a new acceptor
    OCall xdi::NetComEngine.NewAcceptor, [xbx].IOJOB.DataBuffer.ACCEPT_DATA.pListener, [xsi].pProtocol
  .endif

  OCall [xdi].$Obj(NetComEngine).IOJobPool::NetComIOJobPool.FreeItem, xbx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.OnConnected
; Purpose:    A connect operation has finished.
; Arguments:  Arg1: -> IOJob.
; Return:     Nothing.

Method NetComConnection.OnConnected, uses xsi, pIOJob:PIOJOB
  local dSize:DWORD

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
    ; (1) Socket empfangsbereit machen BEVOR Handshake startet
    OCall xsi.QueueReceive

    ; (2) TLS-Handshake initiieren
    OCall [xsi].pTLSContext::TLS_Context.StartClientHandshake, xsi

    ; (3) Anwendung informieren
    OCall [xsi].pProtocol::NetComProtocol.OnConnected, xsi
  .else
    ; Kein TLS — normaler Ablauf
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

  ; === Spurious Errors nach Close unterdrücken ===
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
  local pPlaintext:POINTER
  local dPlaintextSize:DWORD
  local dTLSState:DWORD
  local pTLSData:POINTER
  local dTLSDataSize:DWORD

  SetObject xsi
  lock dec [xsi].dRcvQueuedIOJobs
  ?mov xdx, pIOJob
  mov xbx, [xsi].pOwner

  ;Check for special case of remote socket closure (remote sent a FIN) - end of stream
  .if [xdx].IOJOB.dBytesConsumed == 0                   ;Graceful remote shutdown send
;    DbgText "NetComConnection.OnReceived - FIN", addr [xsi].wName
    ;There is no other possibility to get a zero length payload => No need to pass it
    ;to any protocol handler
    BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_REMOTE        ;Remote shutdown send

    ;Remove FIN IOJob from RcvIOJobChain and return to pool (contains no useful data)
    mov xcx, pIOJob
    lea xax, [xcx].IOJOB.pNextItem
    SDLL_Remove xax, xcx, xdx
    OCall [xbx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob

    ; === TLS Shutdown Pending: Peer hat TCP FIN statt close_notify geschickt ===
    .ifBitSet [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
      BitClr [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
      BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
      ; OnDisconnected posten (genau einmal)
      .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
        BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
        mov [xsi].dDisconnectError, NO_ERROR
        mov [xsi].dDisconnectDirection, SD_SEND          ;Wir haben initiiert
        mov xcx, [xsi].pOwner                           ;xcx -> NetComConnectionPool
        mov xax, [xcx].$Obj(NetComConnectionPool).pOwner ;xax -> NetComEngine
        invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
               0, COMPLETION_KEY_DISCONNECTED, xsi
      .endif
    .else
      ; Normaler FIN-Pfad (non-TLS oder nicht von uns initiiert)
      .ifBitClr [xsi].dFlags, NCC_CLOSED
        OCall xsi.Disconnect, SD_RECEIVE                  ;Local shutdown receive
      .endif
    .endif

  .else
;    DbgText "NetComConnection.OnReceived", addr [xsi].wName
    mov xdx, pIOJob
    ;We queue a new read for the one we receive here
    .ifBitClr [xsi].dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY
      OCall [xbx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_RECV
      .if xax != NULL
        OCall xsi.DoRcvIOJob, xax                         ;Increments pending IOJobs
      .else
;        DbgText "NetComConnection.OnReceived - DoRcvIOJob failed", addr [xsi].wName
      .endif
    .endif

;    ;Return the number of seconds a socket has been connected.
;    mov dRcvLstElpsdTimeSize, sizeof DWORD
;    invoke getsockopt, [xsi].hSocket, SOL_SOCKET, SO_CONNECT_TIME, \
;                       addr [xsi].dRcvLstElpsdTime, addr dRcvLstElpsdTimeSize
;    DbgCheckSockReturn "ERROR on OnReceived getsockopt SO_CONNECT_TIME",, addr [xsi].wName

    ; === TLS State-Machine ===
    .if [xsi].pTLSContext != NULL
      invoke EnterCriticalSection, addr [xsi].CritSect
      OCall [xsi].pTLSContext::TLS_Context.GetState
      mov dTLSState, eax

      .if eax == TLS_STATE_HANDSHAKE || eax == TLS_STATE_SHUTDOWN
        ; Pass IOJob data to ProcessHandshakeData for handshake/shutdown processing
        mov xdx, pIOJob
        mov xax, [xdx].IOJOB.WSABuf.buf
        mov pTLSData, xax
        mov eax, [xdx].IOJOB.dBytesConsumed
        mov dTLSDataSize, eax
        OCall [xsi].pTLSContext::TLS_Context.ProcessHandshakeData, pTLSData, dTLSDataSize, xsi
        ; Remove IOJob from RcvIOJobChain and return to pool (data consumed by TLS context)
        mov xcx, pIOJob
        lea xax, [xcx].IOJOB.pNextItem
        SDLL_Remove xax, xcx, xdx
        mov xcx, [xsi].pOwner
        OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob

        ; === Wenn WIR den TLS Shutdown initiiert haben ===
        .ifBitSet [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
          BitClr [xsi].dFlags, NCC_TLS_SHUTDOWN_PENDING
          ; Peer hat close_notify bestätigt ? TCP-Level Shutdown nachholen
          invoke shutdown, [xsi].hSocket, SD_SEND
          BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
          ; OnDisconnected asynchron posten (genau einmal)
          .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
            BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
            mov [xsi].dDisconnectError, NO_ERROR
            mov [xsi].dDisconnectDirection, SD_SEND      ;Wir haben initiiert
            mov xcx, [xsi].pOwner
            mov xax, [xcx].$Obj(NetComConnectionPool).pOwner
            invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
                   0, COMPLETION_KEY_DISCONNECTED, xsi
          .endif
        .endif
        ; === END ===
        jmp @@TLSDone

      .elseif eax == TLS_STATE_DATA
        ; Decrypt the received data
        mov xdx, pIOJob
        mov xax, [xdx].IOJOB.WSABuf.buf
        mov pTLSData, xax
        mov eax, [xdx].IOJOB.dBytesConsumed
        mov dTLSDataSize, eax
        OCall [xsi].pTLSContext::TLS_Context.Decrypt, \
              pTLSData, dTLSDataSize, addr pPlaintext, addr dPlaintextSize
        mov xdi, xax                                    ;Save Decrypt return value

        ; Check for Decrypt error
        .if xdi != OBJ_OK
          ; Fatal decrypt error - remove IOJob and notify protocol
          mov xcx, pIOJob
          lea xax, [xcx].IOJOB.pNextItem
          SDLL_Remove xax, xcx, xdx
          mov xcx, [xsi].pOwner
          OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob
          OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, TLS_DECRYPT_ERROR
          jmp @@TLSDone
        .endif

        ; Check if we got plaintext data (0 bytes means incomplete TLS record, wait for more)
        .if dPlaintextSize != 0 && pPlaintext != NULL
          ; Reuse the existing IOJob: copy plaintext back into its buffer and adjust size
          mov xbx, pIOJob
          mov xdx, [xbx].IOJOB.WSABuf.buf
          invoke MemClone, xdx, pPlaintext, dPlaintextSize
          m2m [xbx].IOJOB.dBytesConsumed, dPlaintextSize, edx

          ; Call IsDataComplete? and ProcessData on the plaintext
          OCall [xsi].pProtocol::NetComProtocol.IsDataComplete?, xsi, xbx
          .if eax == ERROR_BAD_PROTOCOL || eax == ERROR_USER_QUIT
            OCall xsi.Disconnect, SD_BOTH
            OCall xsi.QueueDestroy
            OCall xsi.Close, TRUE
          .elseif eax != 0
            OCall [xsi].pProtocol::NetComProtocol.ProcessData, xsi, eax
            .if eax != 0                              ;eax = # of BYTEs consumed
              mov dConsumed, eax
              lea xdi, [xsi].RcvIOJobChain
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
        .else
          ; No plaintext yet (incomplete TLS record)
          mov xbx, pIOJob

          ; === Peer close_notify erkennen (SEC_I_CONTEXT_EXPIRED ? TLS_STATE_SHUTDOWN) ===
          OCall [xsi].pTLSContext::TLS_Context.GetState
          .if eax == TLS_STATE_SHUTDOWN
            ; IOJob freigeben (enthält keine nutzbaren Daten mehr)
            mov xcx, pIOJob
            lea xax, [xcx].IOJOB.pNextItem
            SDLL_Remove xax, xcx, xdx
            mov xcx, [xsi].pOwner
            OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob

            ; Antwort mit eigenem close_notify (RFC 8446 §6.1)
            OCall [xsi].pTLSContext::TLS_Context.Shutdown, xsi
            ; TCP-Level Disconnect
            invoke shutdown, [xsi].hSocket, SD_SEND
            BitSet [xsi].dFlags, NCC_SHUTDOWN_SND_LOCAL
            ; OnDisconnected posten — Direction = SD_RECEIVE (Peer hat initiiert)
            .ifBitClr [xsi].dFlags, NCC_DISCONNECT_POSTED
              BitSet [xsi].dFlags, NCC_DISCONNECT_POSTED
              mov [xsi].dDisconnectError, NO_ERROR
              mov [xsi].dDisconnectDirection, SD_RECEIVE  ;Peer hat close_notify initiiert
              mov xcx, [xsi].pOwner
              mov xax, [xcx].$Obj(NetComConnectionPool).pOwner
              invoke PostQueuedCompletionStatus, [xax].$Obj(NetComEngine).hIOCP, \
                     0, COMPLETION_KEY_DISCONNECTED, xsi
            .endif
          .else
            ; Wirklich incomplete TLS record - IOJob bleibt mit 0 Bytes in Chain
            mov [xbx].IOJOB.dBytesConsumed, 0
          .endif
          ; === END ===
        .endif
        jmp @@TLSDone

      .elseif eax == TLS_STATE_ERROR
        ; Error state - no processing, notify protocol and free the IOJob
        mov xcx, pIOJob
        lea xax, [xcx].IOJOB.pNextItem
        SDLL_Remove xax, xcx, xdx
        mov xcx, [xsi].pOwner
        OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob
        OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, TLS_DECRYPT_ERROR
        jmp @@TLSDone

      .endif
      ; TLS_STATE_NONE: Fall through to normal processing below
      invoke LeaveCriticalSection, addr [xsi].CritSect
    .endif
    ; === End TLS State-Machine ===

    mov xbx, [xsi].pOwner                              ;Restore xbx for non-TLS path
    OCall [xsi].pProtocol::NetComProtocol.IsDataComplete?, xsi, pIOJob
    .if eax == ERROR_BAD_PROTOCOL || eax == ERROR_USER_QUIT
      OCall xsi.Disconnect, SD_BOTH
      OCall [xbx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, pIOJob
      OCall xsi.QueueDestroy
      OCall xsi.Close, TRUE
    .elseif eax != 0
      OCall [xsi].pProtocol::NetComProtocol.ProcessData, xsi, eax
      .if eax != 0                                      ;eax = # of BYTEs that can be disposed
        ;eax = #BYTEs consumed, which must be removed.
        ;Note this value could be larger than one IOJob buffer, meaning that it represents
        ;several IOJobs. Also note that the total #BYTEs buffered could be larger than the
        ;#BYTEs consumed meaning the last IOJob will contain some data that is not part of
        ;the complete receive and must remain buffered!
        mov dConsumed, eax
        lea xdi, [xsi].RcvIOJobChain                    ;Sentinel
        mov xbx, [xdi].SDLL_SENTINEL.pFirstItem         ;Get first item
        .while xbx != xdi && dConsumed != 0
;          DbgStr [xbx - IOJOB_HEADER_SIZE].IOJOB.WSABuf.buf
          mov edx, [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed
          .if edx <= dConsumed
            sub dConsumed, edx
            mov xcx, [xsi].pOwner
            lea xdx, [xbx - IOJOB_HEADER_SIZE]          ;xdx -> IOJob
            mov xbx, [xbx].SDLL_ITEM.pNextItem          ;xbx -> next linked item
            OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xdx
            .break .if dConsumed == 0
          .else
            ;This is the last IOJob to be processed. We will leave some data in the buffer,
            ;so we'll need to move the buffer POINTER to the unconsumed data.
            mov ecx, dConsumed
            add [xbx - IOJOB_HEADER_SIZE].IOJOB.WSABuf.buf, xcx
            sub [xbx - IOJOB_HEADER_SIZE].IOJOB.dBytesConsumed, ecx
            .break
          .endif
        .endw
        mov [xdi].SDLL_SENTINEL.pFirstItem, xbx
        mov [xbx].SDLL_ITEM.pPrevItem, xdi
      .endif
      xor eax, eax
    .endif
@@TLSDone:
      invoke LeaveCriticalSection, addr [xsi].CritSect
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
  ?mov xdx, pIOJob
  dec [xsi].dSndQueuedIOJobs

  ;If below Low-WM => clear block
  mov eax, [xsi].dSndQueuedIOJobs
  .if eax < [xsi].dSndLowWtrMrk
    BitClr [xsi].dFlags, NCC_SND_PAUSED
  .endif

  ;Toss the completed IOJob back in the IOJobPool
  mov xax, [xsi].pOwner
  OCall [xax].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xdx
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

  invoke EnterCriticalSection, addr [xsi].CritSect

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
  .if eax != NO_ERROR                                   ;Did read IO complete synchronously?
    invoke WSAGetLastError                              ;No, check if it is a pending state
    .if eax == ERROR_IO_PENDING
      xor eax, eax                                      ;Not an error
    .endif
  .endif

  .if eax == 0
    inc [xsi].dPendingIOJobs
  .endif
  mov ebx, eax

  invoke LeaveCriticalSection, addr [xsi].CritSect

  .if ebx != 0
    OCall xsi.OnError, xdi, ebx                         ;pIOJob
  .endif

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
  BitSet [xsi].dFlags, NCC_QUEUE_DESTROY
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueConnect
; Purpose:    Queue a connect IOJOB.
; Arguments:  Arg1: -> Remote address.
;             Arg2: -> Local address. If NULL, not binding is performed.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.QueueConnect, uses xbx xdi xsi, pRemoteAddr:PNETCOMADDR, \
                                                        pLocalAddr:PNETCOMADDR
  local dOption:DWORD

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
      DbgSockError "NetComConnection.QueueConnect - BIND result", eax,, addr [xsi].wName
      ;In this case, nothing is queued to the IOCP. ConnectEx would fail.
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
    ExitMethod
  .endif
  mov xdi, xax

  invoke EnterCriticalSection, addr [xsi].CritSect

  m2z [xdi].IOJOB.WSABuf.len                            ;Size MUST be zero
  BitClr [xsi].dFlags, NCE_CONNECT
  BitSet [xsi].dFlags, NCC_QUEUE_CONNECT
  invoke PTYP_CONNECTEX ptr pConnectEx, [xsi].hSocket, pRemoteAddr, sizeof NETCOMADDR, \
                                       NULL, 0, NULL, xdi
  .if eax != NO_ERROR                                   ;Did read IO complete synchronously?
    invoke WSAGetLastError                              ;No, check if it is a pending state
    .if eax == ERROR_IO_PENDING
      xor eax, eax                                      ;Not an error
    .endif
  .endif

  .if eax == 0
    inc [xsi].dPendingIOJobs
  .endif
  mov ebx, eax

  invoke LeaveCriticalSection, addr [xsi].CritSect

  .if ebx != 0
    OCall xsi.OnError, xdi, ebx                         ;pIOJob
  .endif

  mov eax, ebx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueReceive
; Purpose:    Queue a read IOJOB.
; Arguments:  None.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComConnection.QueueReceive, uses xsi
  SetObject xsi
;  DbgText "NetComConnection.QueueReceive", addr [xsi].wName
  mov xcx, [xsi].pOwner
  OCall [xcx].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.NewItem, IOJOB_RECV
  .if xax == NULL
    OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
  .else
    OCall xsi.DoRcvIOJob, xax                           ;dRcvQueuedIOJobs is incr. inside DoRcvIOJob
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComConnection.QueueSend
; Purpose:    Copy the information pointed to by pData to the send buffers and queue a
;             Send operation on each one.
; Arguments:  Arg1: -> Data buffer.
;             Arg2: Data size in BYTEs.
; Return:     eax = Number of queued BYTEs.

Method NetComConnection.QueueSend, uses xbx xdi xsi, pData:POINTER, dSize:DWORD
  local dBufferSize:DWORD, pItem:PIOJOB
  local pEncrypted:POINTER, dEncryptedSize:DWORD
  local dBlockSize:DWORD, dPlainBlockSize:DWORD
  local pEncData:POINTER, dEncDataRemaining:DWORD

  SetObject xsi
;  DbgText "NetComConnection.QueueSend", addr [xsi].wName
  mov edi, dSize

  ; === TLS Check ===
  .if [xsi].pTLSContext != NULL
    OCall [xsi].pTLSContext::TLS_Context.GetState

    .if eax == TLS_STATE_DATA
      ; === TLS_STATE_DATA: Encrypt before sending ===

      ; Backpressure check BEFORE encryption (Requirement 7.9)
      .ifBitSet [xsi].dFlags, NCC_SND_PAUSED
        xor eax, eax                                    ;Return 0 bytes sent
        jmp @@Exit
      .endif

      ; Get cbMaximumMessage for block fragmentation
      mov xbx, [xsi].pTLSContext
      mov eax, [xbx].$Obj(TLS_SChannelContext).StreamSizes.cbMaximumMessage
      mov dBlockSize, eax

      ; Get IOJob buffer size for sending encrypted blocks
      mov xcx, [xsi].pOwner                             ;xcx -> NetComConnectionPool
      mov xdx, [xcx].$Obj(NetComConnectionPool).pIOJobPool ;xdx -> NetComIOJobPool
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
          ; Encryption error - report and stop
          OCall [xsi].pProtocol::NetComProtocol.OnError, xsi, NULL, TLS_ENCRYPT_ERROR
          .break
        .endif

        ; Send the encrypted block using existing IOJob fragmentation logic.
        m2m pEncData, pEncrypted, xax
        m2m dEncDataRemaining, dEncryptedSize, eax

        .while dEncDataRemaining != 0
          mov xcx, [xsi].pOwner                         ;xcx -> NetComConnectionPool
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
                jmp @@TLSDataDone
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
                jmp @@TLSDataDone
              .endif
              mov dEncDataRemaining, 0
            .endif
          .else
            OCall xsi.ErrorReport, NULL, NCCN_OUT_OF_MEMORY
            sub edi, dPlainBlockSize
            jmp @@TLSDataDone
          .endif
        .endw

        ; Encrypted block sent successfully - advance plaintext pointer
        mov eax, dPlainBlockSize
        sub edi, eax
        add pData, xax
      .endw

    @@TLSDataDone:
      mov eax, dSize
      sub eax, edi
      jmp @@Exit

    .elseif eax == TLS_STATE_HANDSHAKE || eax == TLS_STATE_SHUTDOWN
      ; === TLS_STATE_HANDSHAKE / TLS_STATE_SHUTDOWN: Token data goes directly without encryption ===
      ; Fall through to the existing send logic below (tokens are already SSPI-formatted)

    .elseif eax == TLS_STATE_ERROR
      ; === TLS_STATE_ERROR: Do not send ===
      xor eax, eax
      jmp @@Exit

    .else
      ; TLS_STATE_NONE with pTLSContext set: fall through to direct send
    .endif
  .endif
  ; === End TLS Check ===

  ; --- Existing send logic (non-TLS, or HANDSHAKE token pass-through) ---
  mov xcx, [xsi].pOwner                                 ;xcx -> NetComConnectionPool
  mov xdx, [xcx].$Obj(NetComConnectionPool).pIOJobPool  ;xdx -> NetComIOJobPool
  m2m dBufferSize, [xdx].$Obj(NetComIOJobPool).dBufferSize, eax

  .while edi != 0
    ;Check if we are allowed to send
    .ifBitSet [xsi].dFlags, NCC_SND_PAUSED
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

@@Exit:
MethodEnd

endif
