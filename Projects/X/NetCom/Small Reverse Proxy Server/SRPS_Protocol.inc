; ==================================================================================================
; Title:      SRPS_Protocol.inc
; Author:     G. Friedrich
; Version:    See SRPS.asm
; Purpose:    Protocol for a bidirectional Small Reverse Proxy Server.
; Note:       Minimal TCP reverse proxy (forwarding) using NetCom.
; ==================================================================================================


DEFAULT_SERVER_LISTENING_PORT equ $htons(25773)


; --------------------------------------------------------------------------------------------------
; Concept:
;                      Client Connections        Server Connections
;
;                     Remote         Local      Local         Remote            Peer Connections
;                    Endpoint      Endpoint    Endpoint      Endpoint               (A - a)
;                                                                                   (B - b)
;              +--------+              +----------+                                 (C - c)
;              | Client o---A--        |          o<--a--                             ...
;              +--------+      |       |          |      |                          (N - n)
;                              |       |          |      |       +--------+
;              +--------+       ----   |          |       ----   |        |
;              | Client o<--B-------|->o   SRPS   o<--b-------|->o Server |
;              +--------+       ----   |          |       ----   |        |
;                              |       |          |      |       +--------+
;              +--------+      |       |          |      |
;              | Client o<--C--        |          o<--c--
;              +--------+              +----------+
;
;
; --------------------------------------------------------------------------------------------------

SRPS_DEFAULT_LISTENING_PORT equ $htons(25772)

SND_MAX_RETRIES   equ   5
SND_DELAY_BASE    equ   100
;TX_DELAY = doubled each retry
;Retry 1 after 100 ms
;Retry 2 after 200 ms
;Retry 3 after 400 ms
;Retry 4 after 800 ms
;Retry 5 after 1600 ms

SRPS_CONNECTION_DATA struc
  pPeerConnection $ObjPtr(NetComConnection) ?   ;Paired connection (Client <=> Server)
;  dSndRetryCount  DWORD                     ?   ;Send retry count, max: TX_MAX_RETRIES
;  dRcvRetryDelay  DWORD                     ?   ;ms
SRPS_CONNECTION_DATA ends

Object NetComSrpsProtocol,, NetComProtocol
  RedefineMethod    Allocate,           $ObjPtr(NetComConnection)
  RedefineMethod    IsDataComplete?,    $ObjPtr(NetComConnection), PIOJOB
  RedefineMethod    OnAccepted,         $ObjPtr(NetComConnection)
  RedefineMethod    OnConnected,        $ObjPtr(NetComConnection)
  RedefineMethod    OnDisconnected,     $ObjPtr(NetComConnection), DWORD, DWORD
  RedefineMethod    OnError,            $ObjPtr(NetComConnection), PIOJOB, DWORD
  RedefineMethod    OnSendQueueLow,     $ObjPtr(NetComConnection)
  RedefineMethod    ProcessData,        $ObjPtr(NetComConnection), DWORD
  RedefineMethod    Release,            $ObjPtr(NetComConnection)
  VirtualMethod     ShowErrorBox,       PSTRING, DWORD

  RedefineVariable  ListeningAddr,      {AF_INETX, SRPS_DEFAULT_LISTENING_PORT}

  DefineVariable    dUseEphemeralPort,  DWORD,      TRUE          ;Setup value
  DefineVariable    ServerLocalAddr,    NETCOMADDR, {AF_INETX, 0} ;Setup Server IP + Port
  DefineVariable    ServerRemoteAddr,   NETCOMADDR, {AF_INETX, DEFAULT_LISTENING_PORT}
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    NetComSrpsProtocol implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.Allocate
; Purpose:    Allocates a memory block for management data for each connection.
;             Additional resources can be reserved here.
; Arguments:  Arg1: -> NetComConnection
; Return:     Zero if succeeded, otherwise an error code.

Method NetComSrpsProtocol.Allocate,, pConnection:$ObjPtr(NetComConnection)
  DbgSetWindowName

;  DbgText "NetComSrpsProtocol.Allocate", pDbgWndNameW
  MemAlloc sizeof SRPS_CONNECTION_DATA, MEM_INIT_ZERO
  .if xax != NULL
    mov xcx, pConnection
    mov [xcx].$Obj(NetComConnection).pData, xax
    xor eax, eax
  .else
    OCall ErrorReport, NULL, WSA_NOT_ENOUGH_MEMORY
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.IsDataComplete?
; Purpose:    Determines if received data is complete.
;             Streaming proxy: any completed IO job is valid.
; Arguments:  Arg1: -> NetComConnection
; Return:     eax = This many bytes are valid buffer information.

Method NetComSrpsProtocol.IsDataComplete?,, pConnection:$ObjPtr(NetComConnection), pIOJob:PIOJOB
  ANNOTATION use:pConnection
  DbgSetWindowName

;  DbgText "NetComSrpsProtocol.IsDataComplete?", pDbgWndNameW
  mov xcx, pIOJob
  mov eax, [xcx].IOJOB.dBytesConsumed              ;Send what was recieved
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.OnAccepted
; Purpose:    An inbound connection 'accept' has completed.
;             Establish backend connection and pair both sides.
; Arguments:  Arg1: -> NetComConnection
; Return:     Nothing.

Method NetComSrpsProtocol.OnAccepted, uses xbx xdi xsi, pConnection:$ObjPtr(NetComConnection)
  DbgSetWindowName

  SetObject xsi
  mov xbx, pConnection                                  ;xbx -> client connection (CritSect held)
  .if [xbx].$Obj(NetComConnection).pData == NULL
    ExitMethod
  .endif

  ;Create the server connection as partner: it shares the CritSect of the client connection, so
  ;one thread at a time works on the pair and forwarding in both directions cannot deadlock
  OCall xbx::NetComConnection.NewPartner, xsi
  .if xax == NULL
    OCall xbx::NetComConnection.QueueDestroy            ;Not admitted, nothing queued
    OCall xbx::NetComConnection.Close, TRUE
    ExitMethod
  .endif
  mov xdi, xax                                          ;xdi -> server connection

  ;Link both sides before the connect can complete (pData != NULL, Allocate succeeded)
  mov xax, [xbx].$Obj(NetComConnection).pData
  mov [xax].SRPS_CONNECTION_DATA.pPeerConnection, xdi
  mov xax, [xdi].$Obj(NetComConnection).pData
  mov [xax].SRPS_CONNECTION_DATA.pPeerConnection, xbx

  OCall xdi::NetComConnection.QueueConnect, addr [xsi].ServerRemoteAddr, addr [xsi].ServerLocalAddr
  .if eax != NO_ERROR
    ;Nothing was queued: unlink and discard the server connection (DiscardConnection posts no
    ;OnDisconnected/OnClosed; the shared CritSect is held as required), then drop the client
    mov xax, [xbx].$Obj(NetComConnection).pData
    mov [xax].SRPS_CONNECTION_DATA.pPeerConnection, NULL
    mov xax, [xsi].pOwner                               ;xax -> Application
    OCall [xax].$Obj(Application).RevProxy::NetComEngine.DiscardConnection, xdi
    OCall xbx::NetComConnection.QueueDestroy
    OCall xbx::NetComConnection.Close, TRUE
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.OnConnected
; Purpose:    An outbound connection attempt has completed.
; Arguments:  Arg1: -> NetComConnection.
; Return:     Nothing.

Method NetComSrpsProtocol.OnConnected, uses xbx xdi, pConnection:$ObjPtr(NetComConnection)
  DbgSetWindowName

;  DbgText "NetComSrpsProtocol.OnConnected", pDbgWndNameW

  ;Both connections of the pair share one CritSect (NewPartner), held by this worker
  mov xdi, pConnection                                  ;xdi -> server connection
  mov xax, [xdi].$Obj(NetComConnection).pData
  .if xax != NULL
    mov xbx, [xax].SRPS_CONNECTION_DATA.pPeerConnection ;xbx -> client connection
    .if xbx != NULL
      .ifBitClr [xbx].$Obj(NetComConnection).dFlags, NCC_QUEUE_DESTROY or NCC_CLOSED
        OCall xbx::NetComConnection.Admit, TRUE         ;Start receiving from the client
        OCall xdi::NetComConnection.QueueReceive
        ExitMethod
      .endif
      OCall xbx::NetComConnection.Admit, FALSE
    .endif
  .endif

  ;No (usable) client connection
  OCall xdi::NetComConnection.Disconnect, SD_SEND
  OCall xdi::NetComConnection.QueueDestroy
  OCall xdi::NetComConnection.Close, TRUE
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.OnDisconnected
; Purpose:    An established connection has been disconnected.
;             Tear down the paired connection as well.
; Arguments:  Arg1: -> NetComConnection
;             Arg2: Disconnect direction = SD_RECEIVE(0)/SD_SEND(1)/SD_BOTH(2)
;             Arg3: Operation result.
; Return:     Nothing.

Method NetComSrpsProtocol.OnDisconnected, uses xbx xdi, pConnection:$ObjPtr(NetComConnection), \
                                                        dDirection:DWORD, dResult:DWORD
  DbgSetWindowName

;  DbgText "NetComSrpsProtocol.OnDisconnected", pDbgWndNameW
  mov xdi, pConnection
  mov xax, [xdi].$Obj(NetComConnection).pData
  .if xax != NULL
    mov xbx, [xax].SRPS_CONNECTION_DATA.pPeerConnection   ;xbx -> peer connection
    .if xbx != NULL
      ;Both share one CritSect (NewPartner), held by this worker: break the links on both sides
      ;and let the peer disconnect gracefully; its own OnDisconnected completes its teardown.
      mov [xax].SRPS_CONNECTION_DATA.pPeerConnection, NULL
      mov xcx, [xbx].$Obj(NetComConnection).pData
      .if xcx != NULL
        mov [xcx].SRPS_CONNECTION_DATA.pPeerConnection, NULL
      .endif
      OCall xbx::NetComConnection.Disconnect, SD_SEND
    .endif
  .endif

  .ifBitClr [xdi].$Obj(NetComConnection).dFlags, NCC_QUEUE_DESTROY
;    DbgText "NetComSrpsProtocol.OnDisconnected - QueueDestroy", pDbgWndNameW
    OCall xdi::NetComConnection.QueueDestroy            ;Mark for selfdestruction
    .if dResult == NO_ERROR
      OCall xdi::NetComConnection.Close, FALSE
    .else
      OCall xdi::NetComConnection.Close, TRUE
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.OnError
; Purpose:    Error notification handler.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: -> IOJob.
;             Arg3: WSA Error code.
; Return:     eax = Command (PROT_CMD_NONE, PROT_CMD_DESTROY, ...).

Method NetComSrpsProtocol.OnError, uses xbx xdi xsi, pConnection:$ObjPtr(NetComConnection), \
                                                     pIOJob:PIOJOB, dError:DWORD
  local cBuffer[1024]:CHR
  DbgSetWindowName

  SetObject xsi
;  DbgDec dError, "NetComSrpsProtocol.OnError", pDbgWndNameW

  .if pIOJob != NULL
    ;An IO operation failed (accept, connect, send or receive): destroy this connection. Close
    ;posts OnDisconnected, which breaks the pair and disconnects the peer. Both connections
    ;share one CritSect (NewPartner), so nothing has to wait for the peer here.
    mov eax, PROT_CMD_DESTROY

  .elseif pConnection == NULL
    ;Listener errors (NetComEngine.StartListening, called by the application thread)
    mov eax, dError
    .if eax == WSAEADDRINUSE
      lea xbx, cBuffer
      mov edi, $32($invoke(htons, [xsi].ListeningAddr.NETCOMADDR.wPort))
      WriteF xbx, "¦ST ¦UD.", $OfsCStr("There is another application listening port"), edi
      OCall xsi.ShowErrorBox, addr cBuffer, dError
    .else
      lea xbx, cBuffer
      WriteF xbx, "Unhandled error"
      OCall xsi.ShowErrorBox, addr cBuffer, dError
    .endif
    mov eax, PROT_CMD_NONE

  .else
    ;Errors without IO operation (receive limit, timeouts): the connection handles them itself.
    ;No MessageBox: this runs on a worker or the supervisor thread.
    mov eax, PROT_CMD_NONE
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.OnSendQueueLow
; Purpose:    The send queue of a connection has drained to its low-water mark: resume the peer,
;             whose receive was paused in ProcessData while this connection could not keep up.
; Arguments:  Arg1: -> NetComConnection
; Return:     Nothing.

Method NetComSrpsProtocol.OnSendQueueLow,, pConnection:$ObjPtr(NetComConnection)
  DbgSetWindowName

  mov xcx, pConnection
  mov xax, [xcx].$Obj(NetComConnection).pData
  .if xax != NULL
    mov xax, [xax].SRPS_CONNECTION_DATA.pPeerConnection
    .if xax != NULL
      OCall xax::NetComConnection.ResumeReceive         ;Shared CritSect (NewPartner) is held
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.ProcessData
; Purpose:    Forwards received data to the paired connection.
; Arguments:  Arg1: -> NetComConnection
;             Arg2: Transmission length
; Return:     Positive INT32 - BYTEs processed.

Method NetComSrpsProtocol.ProcessData, uses xbx xdi xsi, pConnection:$ObjPtr(NetComConnection), \
                                                         TransmitionLength:DWORD
  local dRemainingBytes:DWORD
  DbgSetWindowName

;  DbgText "NetComSrpsProtocol.ProcessData", pDbgWndNameW

  mov xdx, pConnection
  mov xsi, [xdx].$Obj(NetComConnection).pData
  .if xsi != NULL
    mov xdi, [xsi].SRPS_CONNECTION_DATA.pPeerConnection
    .if xdi != NULL
      jmp @F
    .endif
  .endif
  xor eax, eax
  ExitMethod

@@:
  .ifAnyBitSet [xdi].$Obj(NetComConnection).dFlags, NCC_DISCONNECTED_SEND or NCC_CLOSED
    xor eax, eax
    ExitMethod
  .endif

  lea xbx, [xdx].$Obj(NetComConnection).RcvIOJobChain   ;xbx -> Sentinel from the incoming connection
  m2m dRemainingBytes, TransmitionLength, eax

  .while TRUE
    ;Get first IOJob from receive chain
    mov xax, [xbx].SDLL_SENTINEL.pFirstItem
    cmp xax, xbx
    .break .if ZERO?                                    ;Chain empty?

    ;Check if the IOJob was completed
    lea xsi, [xax - IOJOB_HEADER_SIZE]                  ;xsi -> IOJOB
    test [xsi].IOJOB.wFlags, IOF_JOB_COMPLETED
    .break .if ZERO?                                    ;IOJob receive pending?

    ;The peer shares the CritSect of this connection (NewPartner): QueueSend enters it
    ;recursively and never waits for another thread
    OCall xdi::NetComConnection.QueueSend, addr [xsi].IOJOB.DataBuffer, [xsi].IOJOB.dBytesConsumed
    ;The retured value is the number of queued bytes, that may be different than TransmitionLength
    .break .if eax == 0                                 ;Transmission paused
    sub dRemainingBytes, eax
    .if eax != [xsi].IOJOB.dBytesConsumed
      ;Move the pointer inside IOJob
      mov ecx, [xsi].IOJOB.dBytesConsumed
      sub ecx, eax
      mov [xsi].IOJOB.dBytesConsumed, ecx
      add xax, [xsi].IOJOB.WSABuf.buf
      mov [xsi].IOJOB.WSABuf.buf, xax
      .break
    .endif

    ;A full DataBuffer was consumed => remove it from the receive chain
    mov xax, [xbx].SDLL_SENTINEL.pFirstItem
    mov xdx, [xax].SDLL_ITEM.pNextItem
    mov [xbx].SDLL_SENTINEL.pFirstItem, xdx
    mov [xdx].SDLL_ITEM.pPrevItem, xbx

    ;Toss the received IOJob back in the IOJobPool
    mov xax, [xdi].$Obj(NetComConnection).pOwner
    OCall [xax].$Obj(NetComConnectionPool).pIOJobPool::NetComIOJobPool.FreeItem, xsi
  .endw

  ;Backpressure: while the peer cannot send fast enough (its send queue reached the high-water
  ;mark), stop receiving on this side. NetComSrpsProtocol.OnSendQueueLow of the peer resumes it.
  ;Everything received so far was forwarded above, nothing waits in the receive chain.
  mov eax, [xdi].$Obj(NetComConnection).dSndQueuedIOJobs
  .if eax >= [xdi].$Obj(NetComConnection).dSndHighWtrMrk
    OCall pConnection::NetComConnection.PauseReceive
  .endif

  ;Since we processed the IOJobs here, return zero to avoid any further processing.
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.Release
; Purpose:    Releases the memory chunk allocated with Allocate.
; Arguments:  Arg1: -> NetComConnection
; Return:     Nothing.

Method NetComSrpsProtocol.Release,, pConnection:$ObjPtr(NetComConnection)
  DbgSetWindowName

  ?mov xdx, pConnection
;  DbgText "NetComSrpsProtocol.Release", pDbgWndNameW
  mov xax, [xdx].$Obj(NetComConnection).pData
  mov [xdx].$Obj(NetComConnection).pData, NULL
  .if xax != NULL
    MemFree xax
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSrpsProtocol.ShowErrorBox
; Purpose:    Shows a MessageBox displaying a message and WSA error message.
; Arguments:  Arg1: -> Message.
;             Arg2: error code.
; Return:     Nothing.

Method NetComSrpsProtocol.ShowErrorBox, uses xbx xsi, pMessage:PSTRING, dError:DWORD
  local pMsgInfo:PMSG_INFO

  SetObject xsi
  MemAlloc MSG_INFO_SIZE * sizeof(CHR)
  .if xax != NULL
    mov pMsgInfo, xax
    mov [xax].MSG_INFO.dType, MB_OK or MB_ICONERROR
    lea xbx, [xax].MSG_INFO.cBuffer
    mov [xax].MSG_INFO.pMessage, xbx
    invoke StrECopy, xbx, pMessage
    mov xbx, xax
    invoke StrECopy, xbx, offset cCRLF
    invoke StrECopy, xax, offset cCRLF
    invoke StrECopy, xax, $OfsCStr("Description: ")
    mov xbx, xax
    sub xax, pMsgInfo
    neg eax
    add eax, MSG_INFO_SIZE
    if sizeof(CHR) eq 2
      shr eax, 1
    endif
    invoke NetErr2Str, dError, xbx, eax                 ;Returns the number of CHRs written
    if sizeof(CHR) eq 2
      shl eax, 1
    endif
    add xbx, xax
    WriteF xbx, "\nError = ¦UD", dError
    mov xax, pMsgInfo
    add xbx, sizeof(CHR)
    mov [xax].MSG_INFO.pCaption, xbx
    invoke StrCopy, xbx, offset cError
    mov xax, [xsi].pOwner
    invoke PostMessage, [xax].$Obj(WinApp).hWnd, WM_SHOWMSG, pMsgInfo, NULL
  .endif
MethodEnd

endif
