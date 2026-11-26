; ==================================================================================================
; Title:      NetComSupervisor.inc
; Author:     G. Friedrich
; Version:    C.1.2
; Purpose:    ObjAsm support of NetComSupervisor objects.
;             Version C.1.2, November 2026
;               - Destruction is decided by NetComConnection.ReadyToDestroy? under the connection
;                 CritSect (re-check after TryEnter; a connection not closed yet is closed first).
;               - Protocol callbacks (handshake/pause timeout) run without the pool lock.
;               - Connection CritSects through pCritSect; connections before Init are skipped.
;               - The connection ID is cleared under the pool lock before destruction.
;             Version C.1.1, November 2026
;               - Accepted (server) connections are supervised, only pending acceptors are skipped.
;               - TLS handshake timeout (dHandshakeTimeout) for the initial handshake.
;               - Receive pause timeout (dRcvPauseTimeout); no inactivity timeout while paused.
;               - A busy connection is checked in the next cycle instead of restarting the traversal.
;             Version C.1.0, October 2017
;               - Initial release.
; ==================================================================================================


.code

if IMPLEMENT

;NetComSupervisor
NCS_EVENT_INDEX_RUN     equ   0
NCS_EVENT_INDEX_STOP    equ   1


; ==================================================================================================
;    NetComSupervisor implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComSupervisor.Done
; Purpose:    Finalize this object.
; Arguments:  None.
; Return:     Nothing.

Method NetComSupervisor.Done, uses xsi
  SetObject xsi
  invoke SetEvent, [xsi].WaitHandles[NCS_EVENT_INDEX_STOP*sizeof(HANDLE)]
  invoke WaitForSingleObject, [xsi].hWorker, 4000
  .if eax == WAIT_TIMEOUT
    invoke TerminateThread, [xsi].hWorker, INVALID_HANDLE_VALUE
  .endif
  invoke CloseHandle, [xsi].WaitHandles[NCS_EVENT_INDEX_RUN*sizeof(HANDLE)]
  invoke CloseHandle, [xsi].WaitHandles[NCS_EVENT_INDEX_STOP*sizeof(HANDLE)]

  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSupervisor.Init
; Purpose:    Initialize this object.
; Arguments:  Arg1: -> NetComEngine.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComSupervisor.Init, uses xsi, pOwner:POINTER
  local dRetValue:DWORD

  SetObject xsi
  mov dRetValue, 0
  ACall xsi.Init, pOwner
  invoke CreateEvent, NULL, FALSE, FALSE, NULL          ;Auto-reset event
  mov [xsi].WaitHandles[NCS_EVENT_INDEX_RUN*sizeof(HANDLE)], xax
  invoke CreateEvent, NULL, FALSE, FALSE, NULL          ;Auto-reset event
  mov [xsi].WaitHandles[NCS_EVENT_INDEX_STOP*sizeof(HANDLE)], xax

  invoke CreateThread, 0, 16*1024, $MethodAddr(NetComSupervisor.WorkerJob), xsi, 0, NULL
  .if xax == 0
    mov dRetValue, $32($invoke(GetLastError))
    OCall xsi.ErrorReport, NULL, NCE_THREAD_CREATION_FAILED
    DbgSockError "NetComSupervisor.Init - Failed to create supervisor thread", dRetValue
    ExitMethod
  .endif
  mov [xsi].hWorker, xax
  mov eax, dRetValue
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComSupervisor.WorkerJob
; Purpose:    This thread is responsible making all administrative work on the engine.
;             It handles connection closing, destruction and timeout.  
; Arguments:  None.
; Return:     Nothing.

Method NetComSupervisor.WorkerJob, uses xbx xdi xsi
  local dConnectionTime:DWORD, dConnectionTimeSize:DWORD, TimeNow:FILETIME
  local dDirection:DWORD, pConn:POINTER

  SetObject xsi
  mov dConnectionTimeSize, sizeof dConnectionTime
  mov dDirection, TRUE

  .while TRUE
    invoke WaitForMultipleObjects, SUPERVISOR_WAITHANDLECOUNT, addr [xsi].WaitHandles, \
                                   FALSE, [xsi].dCycleTime
    .break .if eax == WAIT_OBJECT_0 + NCS_EVENT_INDEX_STOP

  @@Retry:
    mov xbx, [xsi].pOwner
    invoke EnterCriticalSection, addr [xbx].$Obj(NetComEngine).ConnectionPool.CritSect

    lea xdi, [xbx].$Obj(NetComEngine).ConnectionChain

    ;Traverse the list in alternating directions
    .if dDirection != FALSE
      mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
      mov dDirection, FALSE
    .else
      mov xbx, [xdi].SDLL_SENTINEL.pLastItem
      mov dDirection, TRUE
    .endif

    .while TRUE
      mov xcx, [xsi].pOwner
      lea xdx, [xcx].$Obj(NetComEngine).ConnectionChain
      .break .if xbx == xdx                                     ;Check for end of chain

      lea xbx, [xbx - offset $Obj(NetComConnection).ChainItem]  ;xbx -> NetComConnection

      ;NetComConnectionPool.NewItem links a connection before its Init has set pCritSect
      .if [xbx].$Obj(NetComConnection).pCritSect == NULL
        jmp @@Next
      .endif

      ;Skip only pending acceptors (AcceptEx posted, no peer connected yet). Accepted server
      ;connections must be supervised like client connections (timeouts).
      mov eax, [xbx].$Obj(NetComConnection).dFlags
      and eax, NCC_QUEUE_ACCEPT or NCC_ACCEPTED
      .if eax != NCC_QUEUE_ACCEPT

        ;A busy connection is checked in the next cycle. Restarting the whole traversal here
        ;can starve the supervisor (and the destruction below) under load.
        invoke TryEnterCriticalSection, [xbx].$Obj(NetComConnection).pCritSect
        .if eax == FALSE
          jmp @@Next
        .endif

        ; === TLS Shutdown Timeout ===
        .ifBitSet [xbx].$Obj(NetComConnection).dFlags, NCC_TLS_SHUTDOWN_PENDING
          .if ([xbx].$Obj(NetComConnection).LastTime.FILETIME.dwLowDateTime != 0 || \
               [xbx].$Obj(NetComConnection).LastTime.FILETIME.dwHighDateTime != 0)
            invoke GetSystemTimeAsFileTime, addr TimeNow
            mov eax, TimeNow.FILETIME.dwLowDateTime
            sub eax, [xbx].$Obj(NetComConnection).LastTime.FILETIME.dwLowDateTime
            mov edx, TimeNow.FILETIME.dwHighDateTime
            sbb edx, [xbx].$Obj(NetComConnection).LastTime.FILETIME.dwHighDateTime
            sub eax, [xsi].dTLSShutdownTimeout
            sbb edx, 0
            .if SDWORD ptr edx >= 0
              ; Timeout abgelaufen — abortives Close
              BitClr [xbx].$Obj(NetComConnection).dFlags, NCC_TLS_SHUTDOWN_PENDING
              OCall xbx::NetComConnection.QueueDestroy
              OCall xbx::NetComConnection.Close, TRUE
            .endif
          .endif
        .endif
        ; === END TLS Shutdown Timeout ===

        ; === TLS Handshake Timeout (initial handshake only) ===
        ;The inactivity timeout does not catch a peer that trickles handshake bytes, because every
        ;completion refreshes LastTime. This deadline runs from StartTime (set in Admit for server
        ;connections and in OnConnected for client connections). Renegotiations and TLS 1.3
        ;post-handshake messages are not affected (bHandshakeDone is TRUE then).
        .if [xsi].dHandshakeTimeout != 0
          mov xcx, [xbx].$Obj(NetComConnection).pTLSContext
          .if xcx != NULL
            .if [xcx].$Obj(TLS_Context).bHandshakeDone == FALSE
              .ifBitClr [xbx].$Obj(NetComConnection).dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY
                .if ([xbx].$Obj(NetComConnection).StartTime.FILETIME.dwLowDateTime != 0 || \
                     [xbx].$Obj(NetComConnection).StartTime.FILETIME.dwHighDateTime != 0)
                  OCall [xbx].$Obj(NetComConnection).pTLSContext::TLS_Context.GetState
                  .if eax == TLS_STATE_NONE || eax == TLS_STATE_HANDSHAKE
                    invoke GetSystemTimeAsFileTime, addr TimeNow
                    mov eax, TimeNow.FILETIME.dwLowDateTime
                    sub eax, [xbx].$Obj(NetComConnection).StartTime.FILETIME.dwLowDateTime
                    mov edx, TimeNow.FILETIME.dwHighDateTime
                    sbb edx, [xbx].$Obj(NetComConnection).StartTime.FILETIME.dwHighDateTime
                    sub eax, [xsi].dHandshakeTimeout
                    sbb edx, 0
                    .if SDWORD ptr edx >= 0
                      ;Handshake deadline expired => notify the protocol and abort the connection.
                      ;Protocol callbacks may not preserve xbx/xsi => reload them afterwards.
                      mov pConn, xbx
                      ;No protocol code under the pool lock: a callback waiting for another
                      ;connection would block every worker that needs the pool. The connection
                      ;stays locked, and only the supervisor destroys connections, so it stays
                      ;valid and linked in the chain meanwhile.
                      mov xcx, [xsi].pOwner
                      invoke LeaveCriticalSection, addr [xcx].$Obj(NetComEngine).ConnectionPool.CritSect
                      mov xbx, pConn
                      OCall [xbx].$Obj(NetComConnection).pProtocol::NetComProtocol.OnHandshakeFailed, \
                            xbx, TLS_HANDSHAKE_TIMEOUT
                      mov xbx, pConn
                      OCall [xbx].$Obj(NetComConnection).pProtocol::NetComProtocol.OnError, \
                            xbx, NULL, TLS_HANDSHAKE_TIMEOUT
                      SetObject xsi
                      mov xcx, [xsi].pOwner
                      invoke EnterCriticalSection, addr [xcx].$Obj(NetComEngine).ConnectionPool.CritSect
                      mov xbx, pConn
                      OCall xbx::NetComConnection.QueueDestroy
                      OCall xbx::NetComConnection.Close, TRUE
                    .endif
                  .endif
                .endif
              .endif
            .endif
          .endif
        .endif
        ; === END TLS Handshake Timeout ===

        ; === Receive Pause Timeout ===
        ;A paused connection receives nothing, so LastTime is not refreshed and the inactivity
        ;timeout does not apply. The pause itself is limited instead (PauseTime).
        .ifBitSet [xbx].$Obj(NetComConnection).dFlags, NCC_RCV_PAUSED
          .if [xsi].dRcvPauseTimeout != 0
            .ifBitClr [xbx].$Obj(NetComConnection).dFlags, NCC_CLOSED or NCC_QUEUE_DESTROY
              invoke GetSystemTimeAsFileTime, addr TimeNow
              mov eax, TimeNow.FILETIME.dwLowDateTime
              sub eax, [xbx].$Obj(NetComConnection).PauseTime.FILETIME.dwLowDateTime
              mov edx, TimeNow.FILETIME.dwHighDateTime
              sbb edx, [xbx].$Obj(NetComConnection).PauseTime.FILETIME.dwHighDateTime
              sub eax, [xsi].dRcvPauseTimeout
              sbb edx, 0
              .if SDWORD ptr edx >= 0
                ;Protocol callbacks may not preserve xbx/xsi => reload them afterwards
                mov pConn, xbx
                ;No protocol code under the pool lock (see the handshake timeout above)
                mov xcx, [xsi].pOwner
                invoke LeaveCriticalSection, addr [xcx].$Obj(NetComEngine).ConnectionPool.CritSect
                mov xbx, pConn
                OCall [xbx].$Obj(NetComConnection).pProtocol::NetComProtocol.OnError, \
                      xbx, NULL, NCCN_RCV_PAUSE_TIMEOUT
                SetObject xsi
                mov xcx, [xsi].pOwner
                invoke EnterCriticalSection, addr [xcx].$Obj(NetComEngine).ConnectionPool.CritSect
                mov xbx, pConn
                OCall xbx::NetComConnection.QueueDestroy
                OCall xbx::NetComConnection.Close, TRUE
              .endif
            .endif
          .endif
        .endif
        ; === END Receive Pause Timeout ===

        ;Handle connection inactivity timeout (not while the receive is paused, see above)
        mov eax, [xbx].$Obj(NetComConnection).dFlags
        and eax, NCC_RCV_PAUSED
        .if [xsi].dInactivityTimeout != 0 && eax == 0             ;0 means no timeout
          .if ([xbx].$Obj(NetComConnection).LastTime.FILETIME.dwLowDateTime != 0 || \
               [xbx].$Obj(NetComConnection).LastTime.FILETIME.dwHighDateTime != 0)
            invoke GetSystemTimeAsFileTime, addr TimeNow
            mov eax, TimeNow.FILETIME.dwLowDateTime
            sub eax, [xbx].$Obj(NetComConnection).LastTime.FILETIME.dwLowDateTime
            mov edx, TimeNow.FILETIME.dwHighDateTime
            sbb edx, [xbx].$Obj(NetComConnection).LastTime.FILETIME.dwHighDateTime
            sub eax, [xsi].dInactivityTimeout
            sbb edx, 0
            .if SDWORD ptr edx >= 0
;              DbgWarning "Connection Timeout"
;              DbgConnection xbx, "Connection Timeout"
              OCall xbx::NetComConnection.Disconnect, SD_SEND
              OCall xbx::NetComConnection.QueueDestroy
              OCall xbx::NetComConnection.Close, TRUE
            .endif
          .endif
        .endif

        invoke LeaveCriticalSection, [xbx].$Obj(NetComConnection).pCritSect
      .endif


      ;If the connection is flagged for destruction, proceed ONLY if the
      ;connection has no pending IOJobs AND all async completions have been delivered.
      ;The unlocked tests are a cheap pre-filter, ReadyToDestroy? decides under the CritSect.
      .ifBitSet [xbx].$Obj(NetComConnection).dFlags, NCC_QUEUE_DESTROY
        .if [xbx].$Obj(NetComConnection).dPendingIOJobs == 0
          invoke TryEnterCriticalSection, [xbx].$Obj(NetComConnection).pCritSect
          .if eax == FALSE
            jmp @@Next                                  ;Busy => destroy it in the next cycle
          .endif
          OCall xbx::NetComConnection.ReadyToDestroy?   ;Closes it first if necessary
          .if eax == FALSE
            invoke LeaveCriticalSection, [xbx].$Obj(NetComConnection).pCritSect
            jmp @@Next
          .endif
          mov [xbx].$Obj(NetComConnection).dConnectionId, 0   ;AcquireConnection fails from now on
          OCall xbx::NetComConnection.FreeRessources    ;Protocol data and IOJobs
          invoke LeaveCriticalSection, [xbx].$Obj(NetComConnection).pCritSect
          OCall xbx::NetComConnection.Done
          mov xcx, [xsi].pOwner
          mov xdx, xbx

          ;Get next connection
          .if dDirection == FALSE                       ;Inverted logic, we switched the direction
            mov xbx, [xbx + offset $Obj(NetComConnection).ChainItem].SDLL_ITEM.pNextItem
          .else
            mov xbx, [xbx + offset $Obj(NetComConnection).ChainItem].SDLL_ITEM.pPrevItem
          .endif
          OCall [xcx].$Obj(NetComEngine).ConnectionPool::NetComConnectionPool.FreeItem, xdx
          .continue
        .endif
      .endif

    @@Next:
      ;Get next connection
      .if dDirection == FALSE                           ;Inverted logic, we switched the direction
        mov xbx, [xbx + offset $Obj(NetComConnection).ChainItem].SDLL_ITEM.pNextItem
      .else
        mov xbx, [xbx + offset $Obj(NetComConnection).ChainItem].SDLL_ITEM.pPrevItem
      .endif
    .endw

    mov xcx, [xsi].pOwner
    invoke LeaveCriticalSection, addr [xcx].$Obj(NetComEngine).ConnectionPool.CritSect
  .endw
MethodEnd

endif
