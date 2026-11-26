; ==================================================================================================
; Title:      NetComEngine.inc
; Author:     G. Friedrich
; Version:    C.1.2
; Purpose:    ObjAsm support of NetComEngine objects.
; Notes:      Version C.1.2, November 2026
;               - WorkerJob (no supervisor): destroys through NetComConnection.ReadyToDestroy?;
;                 a connection not closed yet is closed first instead of being released while
;                 its OnDisconnected/OnClosed completions are still queued.
;               - LeaveConnection: new; the destroy check also runs after the synthetic
;                 OnDisconnected/OnClosed completions (without a supervisor, connections were
;                 practically never destroyed).
;               - ConnectionsApply: new; ConnectionsClose/Destroy/Disconnect use it. They blocked
;                 on connection CritSects under the pool lock (deadlock with OnAccepted ->
;                 NewAcceptor); Disconnect is applied only once per connection.
;               - Closed listeners are kept in RetiredListeners until the workers have stopped
;                 (queued accept completions refer to them); Done closes the listeners first.
;               - WorkerJob: no stale completion key if GetQueuedCompletionStatus dequeues no
;                 packet; OnClosed is not delivered before OnDisconnected.
;               - StartListening: returns the error if not a single acceptor could be queued.
;               - Connection CritSects are used through NetComConnection.pCritSect;
;                 CreateConnection (new, NewConnection uses it) can create a connection sharing the
;                 CritSect of another one; LeaveConnection also destroys a lock owner that only
;                 waited for the destroyed partner (no supervisor).
;             Version C.1.1, November 2026
;               - NewAcceptor: checks the NetComConnection.Init result; on failure the connection
;                 is returned to the pool instead of queuing AcceptEx on an invalid socket.
;               - NewConnection: calls Done before returning a failed connection to the pool.
;               - DiscardConnection: new. ConnectTo used FreeRessources, whose Close posted
;                 OnDisconnected/OnClosed completions for a connection already back in the pool.
;             Version C.1.0, October 2017
;               - Initial release.
; ==================================================================================================


.data
  pConnectEx  POINTER   NULL

if IMPLEMENT

.code
; ==================================================================================================
;    Helper
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Procedure:  WsaErrBox
; Purpose:    Auxiliar procedure to to show a WSA error
; Arguments:  Arg1: Parent Window Hnadle.
;             Arg2: -> Message.
;             Arg3: -> Caption.
;             Arg4: MessageBox options.
;             Arg5: WSA Error Code.
; Return:     MessageBox return value.

WsaErrBox proc uses xbx hParent:HWND, pMessage:PSTRING, pCaption:PSTRING, \
                                      dOptions:DWORD, dError:DWORD
  local cBuffer[4096]:CHR

  lea xbx, cBuffer
  invoke StrECopy, xbx, pMessage
  invoke StrECopy, xax, offset cCRLF
  invoke StrECopy, xax, offset cCRLF
  invoke StrECopy, xax, $OfsCStr("Description: ")
  mov xdx, xax
  sub xax, xbx
  mov xbx, xdx
  neg xax
  add xax, sizeof cBuffer
  if sizeof(CHR) eq 2
    shr eax, 1
  endif
  invoke NetErr2Str, dError, xdx, eax                 ;Returns the number of CHRs written
  if sizeof(CHR) eq 2
    shl eax, 1
  endif
  add xbx, xax
  WriteF xbx, "\nError = ¦UD", dError
  invoke MessageBox, hParent, addr cBuffer, pCaption, dOptions
  ret
WsaErrBox endp


; ==================================================================================================
;    ListenerCollection implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     ListenerCollection.DestroyItem
; Purpose:    Auxiliar function to dispose a listener from the collection. Don't call directly!
;             The listening socket is closed (pending AcceptEx operations are aborted). The LISTENER
;             memory is moved to NetComEngine.RetiredListeners and released by NetComEngine.Done
;             after the workers have stopped, since queued accept completions still refer to it.
; Arguments:  Arg1: -> Listener.
; Return:     Nothing.

Method ListenerCollection.DestroyItem, uses xbx, pListener:PLISTENER
  local Linger:linger, hSocket:SOCKET

  DbgText "ListenerCollection.DestroyItem"
  mov xbx, pListener
  .if xbx != NULL
    mov xax, [xbx].LISTENER.hSocket
    .if xax != INVALID_SOCKET
      ;Mark it closed first: OnAccepted does not re-arm an acceptor on a closed listener
      mov hSocket, xax
      mov [xbx].LISTENER.hSocket, INVALID_SOCKET
      ;Perform an "abortive close" of the socket, just in case.
      mov Linger.l_onoff, 1
      mov Linger.l_linger, 0
      invoke setsockopt, hSocket, SOL_SOCKET, SO_LINGER, addr Linger, sizeof Linger
      DbgOnSockError "ListenerCollection.DestroyItem - ERROR on SetSockOpt SO_LINGER"
      invoke closesocket, hSocket
    .endif
    mov xax, pSelf                                      ;xax -> Listeners (DataCollection)
    mov xcx, [xax].$Obj(DataCollection).pOwner          ;xcx -> NetComEngine
    OCall [xcx].$Obj(NetComEngine).RetiredListeners::DataCollection.Insert, xbx
  .endif
MethodEnd



; ==================================================================================================
;    NetComEngine implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.ConnectionsApply
; Purpose:    Applies an action to all connections.
;             A worker can hold a connection CritSect and wait for the pool lock (OnAccepted ->
;             NewAcceptor). Therefore a connection is entered only with TryEnterCriticalSection
;             while the pool lock is held; busy connections are handled in a further pass after
;             the pool lock was released for a moment.
; Arguments:  Arg1: Action: NCE_APPLY_CLOSE, NCE_APPLY_DESTROY or NCE_APPLY_DISCONNECT.
; Return:     eax = Number of connections that were still busy after the last pass (0 = all).
; Note:       NCE_APPLY_DISCONNECT disconnects each connection only once (SD_SEND): a second
;             Disconnect of a TLS connection would cut a pending close_notify exchange.

Method NetComEngine.ConnectionsApply, uses xbx xdi xsi, dAction:DWORD
  local dBusy:DWORD, dPass:DWORD, pConnection:$ObjPtr(NetComConnection)

  SetObject xsi
  mov dPass, 0
  .while TRUE
    mov dBusy, 0
    invoke EnterCriticalSection, addr [xsi].ConnectionPool.CritSect
    lea xdi, [xsi].ConnectionChain                      ;xdi -> SENTINEL
    mov xbx, [xdi].SDLL_SENTINEL.pFirstItem             ;Get first item
    .while xbx != xdi                                   ;Empty?
      lea xax, [xbx - offset($Obj(NetComConnection).ChainItem)]
      mov pConnection, xax
      mov xbx, [xbx].SDLL_ITEM.pNextItem                ;Move to next item
      .if [xax].$Obj(NetComConnection).pCritSect == NULL
        inc dBusy                                       ;Init not done yet => next pass
        .continue
      .endif
      invoke TryEnterCriticalSection, [xax].$Obj(NetComConnection).pCritSect
      .if eax == FALSE
        inc dBusy                                       ;Busy => next pass
      .else
        mov xcx, pConnection
        .if dAction == NCE_APPLY_DISCONNECT
          .ifBitClr [xcx].$Obj(NetComConnection).dFlags, NCC_CLOSED or NCC_TLS_SHUTDOWN_PENDING or \
                                                         NCC_SHUTDOWN_SND_LOCAL
            OCall pConnection::NetComConnection.Disconnect, SD_SEND
          .endif
        .elseif dAction == NCE_APPLY_DESTROY
          OCall pConnection::NetComConnection.QueueDestroy
        .else
          OCall pConnection::NetComConnection.Close, FALSE
        .endif
        mov xcx, pConnection
        invoke LeaveCriticalSection, [xcx].$Obj(NetComConnection).pCritSect
      .endif
    .endw
    invoke LeaveCriticalSection, addr [xsi].ConnectionPool.CritSect
    .break .if dBusy == 0
    inc dPass
    .break .if dPass >= NCE_APPLY_MAX_PASSES
    invoke Sleep, 10                                    ;Let the busy threads continue
  .endw
  mov eax, dBusy
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.ConnectionsClose
; Purpose:    Closes all connections (graceful).
; Arguments:  None.
; Return:     eax = Number of connections that could not be handled (busy), see ConnectionsApply.

Method NetComEngine.ConnectionsClose, uses xsi
  SetObject xsi
  OCall xsi.ConnectionsApply, NCE_APPLY_CLOSE
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.ConnectionsDestroy
; Purpose:    Marks all connections for destruction.
; Arguments:  None.
; Return:     eax = Number of connections that could not be handled (busy), see ConnectionsApply.

Method NetComEngine.ConnectionsDestroy, uses xsi
  SetObject xsi
  OCall xsi.ConnectionsApply, NCE_APPLY_DESTROY
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.ConnectionsDisconnect
; Purpose:    Disconnects all connections (SD_SEND; TLS connections send a close_notify).
; Arguments:  None.
; Return:     eax = Number of connections that could not be handled (busy), see ConnectionsApply.

Method NetComEngine.ConnectionsDisconnect, uses xsi
  SetObject xsi
  OCall xsi.ConnectionsApply, NCE_APPLY_DISCONNECT
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.ConnectTo
; Purpose:    Creates a NetComConnection and initiates a Connect attempt.
; Arguments:  Arg1: -> Protocol object.
;             Arg2: -> Remote address.
;             Arg2: -> Local address.
; Return:     xax -> New NetComConnection or NULL if failed.

Method NetComEngine.ConnectTo, uses xbx xsi, pProtocol:$ObjPtr(NetComProtocol), \
                                             pRemoteAddr:PNETCOMADDR, pLocalAddr:PNETCOMADDR
  SetObject xsi
  ;Get a new NetComConnection and (re)initialize it.
  ?mov xdx, pProtocol
  OCall xsi.NewConnection, xdx
  .if xax != NULL
    mov xbx, xax
    OCall xbx::NetComConnection.QueueConnect, pRemoteAddr, pLocalAddr
    .if eax != NO_ERROR
      ;If we have an error here, nothing was queued, so we can dispose our connection safely
      OCall xsi.DiscardConnection, xbx
      xor eax, eax
    .else
      mov xax, xbx                                        ;Return xax -> NetComConnection
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.DiscardConnection
; Purpose:    Releases a connection that has no IO in flight (e.g. QueueConnect failed) and returns
;             it to the pool.
; Arguments:  Arg1: -> NetComConnection. Its own CritSect must not be held by the caller (Done
;                   deletes it). A partner (NetComConnection.NewPartner) is discarded with the
;                   shared CritSect held, since FreeRessources releases the lock owner.
; Return:     Nothing.
; Note:       NetComConnection.Close posts OnDisconnected/OnClosed completions to the IOCP. They
;             would be processed after the connection was returned to the pool (use after free or
;             delivered to the next connection using the same slot). Therefore the socket is closed
;             here directly and Close becomes a no-op inside FreeRessources.

Method NetComEngine.DiscardConnection, uses xbx xsi, pConnection:$ObjPtr(NetComConnection)
  SetObject xsi
  mov xbx, pConnection
  .ifBitClr [xbx].$Obj(NetComConnection).dFlags, NCC_CLOSED
    BitSet [xbx].$Obj(NetComConnection).dFlags, NCC_CLOSED
    .if [xbx].$Obj(NetComConnection).hSocket != INVALID_SOCKET
      invoke closesocket, [xbx].$Obj(NetComConnection).hSocket
      mov [xbx].$Obj(NetComConnection).hSocket, INVALID_SOCKET
    .endif
  .endif
  OCall xbx::NetComConnection.FreeRessources            ;Protocol.Release and IOJob chains
  OCall xbx::NetComConnection.Done
  OCall [xsi].ConnectionPool::NetComConnectionPool.FreeItem, xbx
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.Done
; Purpose:    Finalizes the NetComEngine object.
; Arguments:  None.
; Return:     Nothing.

Method NetComEngine.Done, uses xbx xdi xsi
  local dThreadExitCode:DWORD

  SetObject xsi
;  DbgText "NetComEngine.Done"
  ;Teardown all connections — graceful TLS shutdown
  DbgLine2
  ;Stop accepting first, so no new connections arrive during the teardown. The LISTENER memory
  ;stays in RetiredListeners until the workers have stopped.
  OCall [xsi].Listeners::DataCollection.Done
  OCall xsi.ConnectionsDisconnect                       ;Sends TLS close_notify + TCP FIN
  invoke Sleep, 500                                     ;Give worker time to send close_notify
  OCall xsi.ConnectionsDestroy                          ;Mark all for destruction
  OCall xsi.ConnectionsClose                            ;Close all sockets (abortive if needed)

  mov xax, [xsi].pSupervisor
  .if xax != NULL
    invoke SetEvent, [xax].$Obj(NetComSupervisor).WaitHandles[NCS_EVENT_INDEX_RUN*sizeof(HANDLE)]
  .endif

  ;Tell NetComEngine worker to die, and wait for the death. Then shutdown the supervisor thread.
  DbgText "NetComEngine.Done - Closing Workers"
  .ColForEach [xsi].Workers, edi
    invoke PostQueuedCompletionStatus, [xsi].hIOCP, 0, COMPLETION_KEY_KILL_WORKER, NULL
  .ColNext

  invoke WaitForMultipleObjects, [xsi].Workers.dCount, [xsi].Workers.pItems, TRUE, 4000
  .if eax == WAIT_TIMEOUT
    DbgWarning "NetComEngine.Done - Brute force worker close"
    .ColForEach [xsi].Workers
      mov xdi, xax

      invoke GetExitCodeThread, xdi, addr dThreadExitCode
      .if eax != 0 && dThreadExitCode == STILL_ACTIVE
        invoke TerminateThread, xdi, -1
        ;IMPORTANT: calling TerminateThread can left synchronization objects in an
        ;           undefined state. Don't call an Debug macro after this point,
        ;           since you can hang the server application!
      .endif
    .ColNext
  .endif

  if DEBUGGING
    mov xbx, [xsi].pOwner
    invoke EnterCriticalSection, addr [xsi].ConnectionPool.CritSect
    lea xdi, [xsi].ConnectionChain                        ;xdi -> SENTINEL
    mov xbx, [xdi].SDLL_SENTINEL.pFirstItem               ;Get first Item
    .while xbx != xdi                                     ;Empty?
      lea xcx, [xbx - offset($Obj(NetComConnection).ChainItem)]
      mov xbx, [xbx].SDLL_ITEM.pNextItem
      DbgConnection xcx
    .endw
    invoke LeaveCriticalSection, addr [xsi].ConnectionPool.CritSect
  endif


  OCall [xsi].Workers::XWCollection.Done

  .if [xsi].pSupervisor != NULL
    OCall [xsi].pSupervisor::NetComSupervisor.Done
  .endif

  ;No completion can refer to a closed listener any more
  OCall [xsi].RetiredListeners::DataCollection.Done

  ;Destroy IOCP
  invoke CloseHandle, [xsi].hIOCP

  ;Clean up resource pools
  OCall [xsi].IOJobPool::NetComIOJobPool.Done
  OCall [xsi].ConnectionPool::NetComConnectionPool.Done

  ;Housekeeping
  Invoke StrDispose, [xsi].pLocalHostName
  DbgText "NetComEngine.Done"
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.Init
; Purpose:    Initializes internal collections, threads, IOCP etc.
; Arguments:  Arg1: -> Owner object.
;             Arg2: -> Supervisor.
;             Arg3: Number of preallocated connections.
;             Arg4: Number of preallocated IOJOBs.
;             Arg5: IO socket buffer size, usually the "Maximum Segment Size" (MSS).
; Return:     eax = 0 if succeeded, otherwise an error code.

Method NetComEngine.Init, uses xbx xsi, pOwner:POINTER, pSupervisor:POINTER, \
                                        dAllocConnections:DWORD, dAllocIOJobs:DWORD, \
                                        dIOJobBufferSize:DWORD
  local dRetValue:DWORD, SysInfo:SYSTEM_INFO, cLocalHostName[256]:CHR    ;Max. 256 characters

  SetObject xsi

  mov dRetValue, NO_ERROR
  m2m [xsi].pSupervisor, pSupervisor, xax
  ACall xsi.Init, pOwner

  lea xax, [xsi].ConnectionChain
  SDLL_Init xax

  ;Override Listeners methods
  Override [xsi].Listeners::DataCollection.DestroyItem, ListenerCollection.DestroyItem

  ;Get the local host name
  invoke GetHostName, addr cLocalHostName, lengthof cLocalHostName
  mov [xsi].pLocalHostName, $invoke(StrNew, addr cLocalHostName)

  ;Initialize the collections
  lea xbx, [xsi].IOJobPool                             ;xbx -> NetComIOJobPool
  OCall xbx::NetComIOJobPool.Init, xsi, dAllocIOJobs, dIOJobBufferSize
  OCall [xsi].ConnectionPool::NetComConnectionPool.Init, xsi, dAllocConnections, xbx
  OCall [xsi].Listeners::DataCollection.Init, xsi, 5, 5, COL_MAX_CAPACITY
  OCall [xsi].RetiredListeners::DataCollection.Init, xsi, 5, 5, COL_MAX_CAPACITY
  invoke GetSystemInfo, addr SysInfo
  mrm [xsi].dWorkerCount, SysInfo.dwNumberOfProcessors, eax   ;Number of logical processors
;  mrm [xsi].dWorkerCount, 1, eax
  OCall [xsi].Workers::XWCollection.Init, xsi, eax, 0, eax

  ;Create the IOCP
  mov [xsi].hIOCP, $invoke(CreateIoCompletionPort, INVALID_HANDLE_VALUE, 0, 0, [xsi].dWorkerCount)
  .if xax == 0
    OCall xsi.ErrorReport, NULL, NCE_IOCP_INIT_ERROR
    mov dRetValue, $32($invoke(WSAGetLastError))
    DbgSockError "NetComEngine.Init - Failed to create the IOCP", dRetValue
    jmp @@Exit
  .endif

  ;Initialize supervisor and worker thread
  .if pSupervisor != NULL
    OCall pSupervisor::NetComSupervisor.Init, xsi
  .endif

  ;Create a Worker Thread per available "logical" cpu
  mov ebx, [xsi].dWorkerCount
  test ebx, ebx
  .while !ZERO?
    invoke CreateThread, 0, 16*1024, $MethodAddr(NetComEngine.WorkerJob), xsi, 0, NULL
    .if xax == 0
      mov dRetValue, $32($invoke(GetLastError))
      OCall xsi.ErrorReport, NULL, NCE_THREAD_CREATION_FAILED
      DbgSockError "NetComEngine.Init - Failed to create worker thread", dRetValue
      jmp @@Exit
    .endif
    DbgHex xax, "NetComEngine.Init - New Worker"
    OCall [xsi].Workers::XWCollection.Insert, xax
    dec ebx
  .endw

@@Exit:
  mov eax, dRetValue
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.LeaveConnection
; Purpose:    Leaves the connection CritSect after a completion. Without a supervisor, a connection
;             that is ready to be destroyed (NetComConnection.ReadyToDestroy?) is destroyed here and
;             returned to the pool; with a supervisor, the supervisor does it.
; Arguments:  Arg1: -> NetComConnection. Its CritSect is held once by the calling worker.
; Return:     Nothing.
; Note:       Also called after the synthetic OnDisconnected/OnClosed completions: they are usually
;             the last events of a connection and their delivery is required for destruction.

Method NetComEngine.LeaveConnection, uses xbx xdi xsi, pConnection:$ObjPtr(NetComConnection)
  local pLockOwner:$ObjPtr(NetComConnection), pOwnerDone:$ObjPtr(NetComConnection)

  SetObject xsi
  mov xbx, pConnection
  mov xdi, [xbx].$Obj(NetComConnection).pCritSect       ;CritSect held by the caller
  .if [xsi].pSupervisor == NULL
    OCall xbx::NetComConnection.ReadyToDestroy?         ;Closes it first if necessary
    .if eax != FALSE
      m2m pLockOwner, [xbx].$Obj(NetComConnection).pLockOwner, xax
      mov pOwnerDone, NULL
      OCall xbx::NetComConnection.FreeRessources        ;Protocol data, IOJobs, lock owner use
      ;A lock owner that only waited for this partner gets no further completion: destroy it
      ;here as well, while the shared CritSect is still held
      .if pLockOwner != NULL
        OCall pLockOwner::NetComConnection.ReadyToDestroy?
        .if eax != FALSE
          OCall pLockOwner::NetComConnection.FreeRessources
          m2m pOwnerDone, pLockOwner, xax
        .endif
      .endif
      invoke LeaveCriticalSection, xdi
      OCall xbx::NetComConnection.Done                  ;Own CritSect of the partner
      OCall [xsi].ConnectionPool::NetComConnectionPool.FreeItem, xbx
      .if pOwnerDone != NULL
        OCall pOwnerDone::NetComConnection.Done         ;Deletes the shared CritSect
        OCall [xsi].ConnectionPool::NetComConnectionPool.FreeItem, pOwnerDone
      .endif
      ExitMethod
    .endif
  .endif
  invoke LeaveCriticalSection, xdi
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.NewAcceptor
; Purpose:    Creates a new NetComConnection and enqueues an accept IOJob using a new protocol.
; Arguments:  Arg1: -> Listener.
;             Arg2: -> NetComProtocol.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComEngine.NewAcceptor, uses xbx xsi, pListener:PLISTENER, pProtocol:$ObjPtr(NetComProtocol)
  local dError:DWORD

  SetObject xsi
  OCall [xsi].ConnectionPool::NetComConnectionPool.NewItem ;Get a new NetComConnection from the pool
  .if xax == NULL
    mov eax, WSA_NOT_ENOUGH_MEMORY
  .else
    mov xbx, xax
    OCall xbx::NetComConnection.Init, addr [xsi].ConnectionPool, pProtocol
    .if eax == 0                                        ;Zero means success
      OCall xbx::NetComConnection.QueueAccept, pListener  ;Queue the accept job
    .else
      ;Init failed (NetComProtocol.Allocate or socket creation). Nothing was queued and Init has
      ;released its resources, so the connection can be returned to the pool right away.
      mov dError, eax
      DbgWarning "NetComEngine.NewAcceptor - Connection initialization failed"
      OCall xbx::NetComConnection.Done                  ;Delete the CritSect
      OCall [xsi].ConnectionPool::NetComConnectionPool.FreeItem, xbx
      mov eax, dError
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.CreateConnection
; Purpose:    Creates a NetComConnection and registers its socket with the IOCP.
; Arguments:  Arg1: -> protocol object.
;             Arg2: -> NetComConnection whose CritSect the new connection uses, or NULL for its own
;                   CritSect. The caller must hold that CritSect (see NetComConnection.NewPartner).
; Return:     xax -> New NetComConnection or NULL if failed.

Method NetComEngine.CreateConnection, uses xbx xsi, pProtocol:POINTER, pLockOwner:POINTER
  SetObject xsi
  OCall [xsi].ConnectionPool::NetComConnectionPool.NewItem
  .if xax != NULL
    mov xbx, xax
    m2m [xbx].$Obj(NetComConnection).pLockOwner, pLockOwner, xax   ;Evaluated by Init
    OCall xbx::NetComConnection.Init, addr [xsi].ConnectionPool, pProtocol
    .if eax == 0                                        ;Zero means success
      ;Register the socket with IOCP, because we want socket event notifications
      invoke CreateIoCompletionPort, [xbx].$Obj(NetComConnection).hSocket, [xsi].hIOCP, xbx, 0
      mov xax, pLockOwner
      .if xax != NULL
        inc [xax].$Obj(NetComConnection).dLockUsers     ;Shared CritSect held by the caller
      .endif
      mov xax, xbx
    .else
      ;Failed to initialize new connection (the owner was not counted yet)
      mov [xbx].$Obj(NetComConnection).pLockOwner, NULL
      OCall xbx::NetComConnection.Done                  ;Delete the own CritSect
      OCall [xsi].ConnectionPool::NetComConnectionPool.FreeItem, xbx
      xor eax, eax
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.NewConnection
; Purpose:    Creates a NetComConnection.
; Arguments:  Arg1: -> protocol object.
; Return:     xax -> New NetComConnection or NULL if failed.
; Notes:      This method is useful for creating sockets with arbitrary semantics.
;             Use this for 'connectionless' socket types.

Method NetComEngine.NewConnection, uses xsi, pProtocol:$ObjPtr(NetComProtocol)
  SetObject xsi
  OCall xsi.CreateConnection, pProtocol, NULL
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.Shutdown
; Purpose:    WinSock Shutdown.
; Arguments:  None.
; Return:     Nothing.

Method NetComEngine.Shutdown
  invoke WSACleanup
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.StartListening
; Purpose:    Creates a "Listener" and begins listening on a port (Service) using a protocol.
; Arguments:  Arg1: Number of preallocated accept connections.
;             Arg2: -> NetComProtocol.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComEngine.StartListening, uses xbx xdi xsi, dAcceptorCount:DWORD, \
                                                      pProtocol:$ObjPtr(NetComProtocol)
  local dRetValue:DWORD

  DbgText "NetComEngine.StartListening"
  SetObject xsi
  mov dRetValue, NO_ERROR

  ;Create a socket with WSA_FLAG_OVERLAPPED flag!
  MemAlloc sizeof(LISTENER)
  .if xax == NULL
    mov dRetValue, WSA_NOT_ENOUGH_MEMORY
    DbgSockError "NetComEngine.StartListening - Can not allocate LISTENER structure", dRetValue
    jmp @@Exit
  .endif
  mov xbx, xax
  mov [xbx].LISTENER.hSocket, INVALID_SOCKET
  OCall [xsi].Listeners::DataCollection.Insert, xbx

  invoke WSASocket, AF_INETX, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED
  .if xax == INVALID_SOCKET
    mov dRetValue, $32($invoke(WSAGetLastError))
    DbgSockError "NetComEngine.StartListening - Failed to create listener socket", dRetValue
    OCall xsi.ErrorReport, NULL, NCE_SOCKET_CREATION_FAILED
    jmp @@Exit
  .endif
  mov [xbx].LISTENER.hSocket, xax
  DbgText "NetComEngine.StartListening - Listener socket created"

;  ;Set socket options: disable nagle's algorithm for fast reaction time
;  mov dOption, 1                                        ;1 means algo disabled
;  invoke setsockopt, [xbx].LISTENER.hSocket, IPPROTO_TCP, TCP_NODELAY, \
;                     addr dOption, sizeof dOption
;  DbgCheckSockReturn "NetComEngine.StartListening - ERROR on SetSockOpt TCP_NODELAY = 1"

  mov xdi, pProtocol
  invoke bind, [xbx].LISTENER.hSocket, addr [xdi].$Obj(NetComProtocol).ListeningAddr, \
               sizeof NETCOMADDR
  .if xax != NO_ERROR
    mov dRetValue, $32($invoke(WSAGetLastError))
    DbgSockError "NetComEngine.StartListening - Failed to bind listener socket", dRetValue
    OCall pProtocol::NetComProtocol.OnError, NULL, NULL, dRetValue
    OCall xsi.ErrorReport, NULL, NCE_LISTENER_BIND_ERROR
    jmp @@Exit
  .endif

  DbgText "NetComEngine.StartListening - SocketAddress has been bound to listener socket"
  invoke listen, [xbx].LISTENER.hSocket, SOMAXCONN
  .if eax != NO_ERROR
    mov dRetValue, $32($invoke(WSAGetLastError))
    DbgSockError "NetComEngine.StartListening - Listener socket failed to listen", dRetValue
    OCall pProtocol::NetComProtocol.OnError, NULL, NULL, dRetValue
    OCall xsi.ErrorReport, NULL, NCE_LISTENER_DOESNT_LISTEN
    jmp @@Exit
  .endif

  DbgText "NetComEngine.StartListening - Socket is listening..."
  ;Bind the listening socket to the IOCP => necessary for acceptor
  invoke CreateIoCompletionPort, [xbx].LISTENER.hSocket, [xsi].hIOCP, \
                                 COMPLETION_KEY_SOCK_ACCEPTED, 0
  .if xax == 0                                          ;0 means failure
    mov dRetValue, $32($invoke(GetLastError))
    DbgSockError "NetComEngine.StartListening - Listener can not de bound to the IOCP", dRetValue
    OCall pProtocol::NetComProtocol.OnError, NULL, NULL, eax
    OCall xsi.ErrorReport, NULL, NCE_LISTENER_IOCP_BIND_FAILED
    jmp @@Exit
  .endif

  DbgText "NetComEngine.StartListening - Socket has been bound to IOCP"
  ;Queue some accept NetComConnections
  mov edi, dAcceptorCount
  test edi, edi
  .while !ZERO?
    OCall xsi.NewAcceptor, xbx, pProtocol               ;Returns eax = error code
    .if eax != NO_ERROR && eax != ERROR_IO_PENDING
      .if edi == dAcceptorCount
        mov dRetValue, eax                              ;Not a single acceptor => report it
      .endif
      .break
    .endif
    dec xdi
  .endw

@@Exit:
  mov eax, dRetValue
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.Startup
; Purpose:    WinSock startup.
; Arguments:  None.
; Return:     Nothing.
; Note:       The WinSock startup is placed here so that other related APIs will work before the
;             NetComEngine is started.

Method NetComEngine.Startup
  local WsaData:WSADATA, hSocket:SOCKET, dBytesTransf:DWORD

  invoke WSAStartup, 0202h, addr WsaData
  .if eax != 0
    ;Write the error code into the NetComEngine template.
    ;New instances inherit this error code and must check it.
    OCall $ObjTmpl(NetComEngine)::NetComEngine.ErrorSet, NCE_WINSOCK_INIT_FAILED
  .endif

  invoke WSASocket, AF_INETX, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED
  .if xax != INVALID_SOCKET
    mov hSocket, xax

    ;Try to obtain a POINTER to the ConnectEx procedure, which does not change for the same provider
    invoke WSAIoctl, hSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                     offset WSAID_CONNECTEX, sizeof WSAID_CONNECTEX,
                     addr pConnectEx, sizeof POINTER, addr dBytesTransf, NULL, NULL
    .if eax != NO_ERROR
      DbgWarning "NetComEngine.Startup - Failed to get and address of the procedure ConnextEx"
    .endif
    invoke closesocket, hSocket
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.StopListening
; Purpose:    Stops the engine listening.
; Arguments:  None.
; Return:     Nothing.

Method NetComEngine.StopListening, uses xsi

  DbgText "NetComEngine.StopListening"
  SetObject xsi

  ;Close all listerners
  DbgText "NetComEngine.StopListening - Closing listeners"

  ;Closes all listening sockets. Pending IOs are cancelled through the IOCP,
  ;which frees the associated acceptor connections.
  OCall [xsi].Listeners::DataCollection.DisposeAll
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComEngine.WorkerJob
; Purpose:    Here is the HEART AND SOUL of the NetComEngine.
;             This thread is responsible for waiting on IOCP completion notifications and passing
;             them to the corresponding method.
;             There can be several of these Worker threads operating asynchronously.
; Arguments:  None.
; Return:     Nothing.

Method NetComEngine.WorkerJob, uses xbx xdi xsi
  local pIOJob:PIOJOB, xCompletionKey:XWORD, dBytesTransfered:DWORD
  local dFlags:DWORD, dBytesConsumed:DWORD, dOvrResult:DWORD
  local pEngine:POINTER

  SetObject xsi
  mov pEngine, xsi
  .while TRUE
    ;The GetQueuedCompletionStatus API call will return two useful pieces of information.
    ;One is the "completion key" of the completed IO, the other is a POINTER to the IOJob
    ;which represents the IO operation which was completed.
    ;Note: never abort if GetQueuedCompletionStatus returns FALSE!
    mov pIOJob, NULL                                    ;Both are not written if no packet
    mov xCompletionKey, 0                               ;is dequeued
    invoke GetQueuedCompletionStatus, [xsi].hIOCP, addr dBytesTransfered, addr xCompletionKey, \
                                      addr pIOJob, INFINITE
    .if eax == FALSE && pIOJob == NULL
      ;No packet was dequeued (a failed IO has pIOJob != NULL): the key is not valid
      invoke GetLastError
      .break .if eax == ERROR_ABANDONED_WAIT_0 || eax == ERROR_INVALID_HANDLE   ;IOCP closed
      .continue
    .endif

    ;Exit thread loop immediately if COMPLETION_KEY_KILL_WORKER received
    .break .if xCompletionKey == COMPLETION_KEY_KILL_WORKER

    ; ??????????????????????????????????????????????????????????????????????????
    ; Synthetische Completions — CritSect-geschützt mit Re-Post bei Contention
    ; pIOJob enthält hier den Connection-Pointer (kein echtes OVERLAPPED!)
    ; ??????????????????????????????????????????????????????????????????????????
    .if xCompletionKey == COMPLETION_KEY_DISCONNECTED
      mov xdi, pIOJob                                    ;xdi -> NetComConnection
      invoke TryEnterCriticalSection, [xdi].$Obj(NetComConnection).pCritSect
      .if eax != FALSE
        OCall [xdi].$Obj(NetComConnection).pProtocol::NetComProtocol.OnDisconnected, \
              xdi, [xdi].$Obj(NetComConnection).dDisconnectDirection, \
              [xdi].$Obj(NetComConnection).dDisconnectError
        mov xsi, pEngine                                 ;Restore Engine pointer
        ;Restore xdi from pIOJob — Protocol callback may have clobbered xdi (rdi)
        ;without 'uses xdi'. pIOJob holds the Connection pointer for synthetic keys.
        mov xdi, pIOJob
        lock or [xdi].$Obj(NetComConnection).dFlags, NCC_DISCONNECTED_DELIVERED
        OCall xsi.LeaveConnection, xdi                  ;Destroys it if ready (no supervisor)
      .else
        ; CritSect belegt — Re-Post ans Ende der IOCP-Queue
        invoke PostQueuedCompletionStatus, [xsi].hIOCP, \
               0, COMPLETION_KEY_DISCONNECTED, xdi
      .endif
      .continue

    .elseif xCompletionKey == COMPLETION_KEY_CLOSED
      mov xdi, pIOJob                                    ;xdi -> NetComConnection
      invoke TryEnterCriticalSection, [xdi].$Obj(NetComConnection).pCritSect
      .if eax != FALSE
        ;Keep the order OnDisconnected -> OnClosed: a re-posted DISCONNECTED completion can
        ;arrive after this one
        mov eax, [xdi].$Obj(NetComConnection).dFlags
        and eax, NCC_DISCONNECT_POSTED or NCC_DISCONNECTED_DELIVERED
        .if eax == NCC_DISCONNECT_POSTED
          invoke LeaveCriticalSection, [xdi].$Obj(NetComConnection).pCritSect
          invoke PostQueuedCompletionStatus, [xsi].hIOCP, 0, COMPLETION_KEY_CLOSED, xdi
          .continue
        .endif
        OCall [xdi].$Obj(NetComConnection).pProtocol::NetComProtocol.OnClosed, xdi
        mov xsi, pEngine                                 ;Restore Engine pointer
        ;Restore xdi from pIOJob — same reason as above
        mov xdi, pIOJob
        lock or [xdi].$Obj(NetComConnection).dFlags, NCC_CLOSED_DELIVERED
        OCall xsi.LeaveConnection, xdi                  ;Destroys it if ready (no supervisor)
      .else
        ; CritSect belegt — Re-Post
        invoke PostQueuedCompletionStatus, [xsi].hIOCP, \
               0, COMPLETION_KEY_CLOSED, xdi
      .endif
      .continue
    .endif
    ; ??????????????????????????????????????????????????????????????????????????

    mov xbx, pIOJob
    .if xbx != NULL
      .if xCompletionKey == COMPLETION_KEY_VOID
        mov xdi, xbx                                    ;pConnection passed using pIOJob
        DbgHex xdi, "NetComEngine.WorkerJob - VOID posted"
        invoke EnterCriticalSection, [xdi].$Obj(NetComConnection).pCritSect

      .else
        .if xCompletionKey == COMPLETION_KEY_SOCK_ACCEPTED
          mov xdi, [xbx].IOJOB.DataBuffer.ACCEPT_DATA.pConnection

        .else
          mov xdi, xCompletionKey                       ;xdi -> NetComConnection
        .endif

        invoke EnterCriticalSection, [xdi].$Obj(NetComConnection).pCritSect
        
        invoke GetSystemTimeAsFileTime, addr [xdi].$Obj(NetComConnection).LastTime

        ;Determine whether the operation completed successfully or not
        invoke WSAGetOverlappedResult, [xdi].$Obj(NetComConnection).hSocket, xbx, \
                                       addr dBytesConsumed, \
                                       FALSE, addr dFlags
        mov dOvrResult, eax
        ;Serialize on a per-connection basis
        BitSet [xbx].IOJOB.wFlags, IOF_JOB_COMPLETED   ;Set marker
        dec [xdi].$Obj(NetComConnection).dPendingIOJobs
        inc [xdi].$Obj(NetComConnection).dCompletedIOJobs

        .if dOvrResult != FALSE
          ;Operation succeeded *****************************************************************
          ;Each of the following connection handlers must manage the IOJob themselves
          movzx eax, [xbx].IOJOB.wOperation
          .if eax == IOJOB_RECV
            mrm [xbx].IOJOB.dBytesConsumed, dBytesConsumed, edx
            lock add [xsi].dBytesIn, edx
            OCall xdi::NetComConnection.OnReceived, xbx

          .elseif eax == IOJOB_SEND
            mrm [xbx].IOJOB.dBytesConsumed, dBytesConsumed, edx
            lock add [xsi].dBytesOut, edx
            OCall xdi::NetComConnection.OnSent, xbx

          .elseif eax == IOJOB_CONNECT
            OCall xdi::NetComConnection.OnConnected, xbx

          .elseif eax == IOJOB_ACCEPT
            OCall xdi::NetComConnection.OnAccepted, xbx

          .else
            invoke WSAGetLastError                      ;This error is thread specific
            OCall xdi::NetComConnection.OnError, xbx, eax
          .endif

        .else
          ;Operation failed! *******************************************************************
          invoke WSAGetLastError                        ;This error is thread specific
          OCall xdi::NetComConnection.OnError, xbx, eax
        .endif

      .endif

      ;Without a supervisor, the connection is destroyed here as soon as it is ready
      OCall xsi.LeaveConnection, xdi
    .endif

  .endw

  DbgText "NetComEngine.WorkerJob - Worker death"
  DbgDec [xsi].IOJobPool.dCount, "NetComEngine.WorkerJob"
MethodEnd

endif
