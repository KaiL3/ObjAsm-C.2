; ==================================================================================================
; Title:      SRPS_Supervisor.inc
; Author:     G. Friedrich
; Version:    C.1.2
; Purpose:    ObjAsm support of SRPS_Supervisor objects.
;             Version C.1.2, November 2026
;               - Destruction through NetComConnection.ReadyToDestroy?: the connection was
;                 released without waiting for its OnDisconnected/OnClosed completions (use after
;                 free); a busy connection is skipped instead of restarting the traversal.
;               - Connection CritSects through pCritSect; both sides of a pair share one
;                 (NetComConnection.NewPartner), so the peer needs no lock and no retry.
;               - Accepted client connections are supervised (they were skipped like pending
;                 acceptors): timeout, backpressure server -> client. LastTime typo fixed; no
;                 inactivity timeout while the receive is paused.
;             Version C.1.1, November 2026
;               - Backpressure uses NetComConnection.PauseReceive/ResumeReceive.
;             Version C.1.0, October 2017
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:  NetComSrpsSupervisor
; Purpose: Controls overall status of the NetComEngine

Object NetComSrpsSupervisor,, NetComSupervisor
  RedefineMethod  WorkerJob
ObjectEnd


.code

if IMPLEMENT

; ==================================================================================================
;    NetComSrpsSupervisor implementation
; ==================================================================================================

; Method:     NetComSrpsSupervisor.WorkerJob
; Purpose:    This thread is responsible making all administrative work on the engine.
; Arguments:  None.
; Return:     Nothing.

Method NetComSrpsSupervisor.WorkerJob, uses xbx xdi xsi
  local dConnectionTime:DWORD, dConnectionTimeSize:DWORD, TimeNow:FILETIME
  local dDirection:DWORD

  SetObject xsi
  mov dConnectionTimeSize, sizeof dConnectionTime
  mov dDirection, TRUE

  .while TRUE
    invoke WaitForMultipleObjects, SUPERVISOR_WAITHANDLECOUNT, addr [xsi].WaitHandles, \
                                   FALSE, [xsi].dCycleTime
    .break .if eax == WAIT_OBJECT_0 + NCS_EVENT_INDEX_STOP

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

      lea xbx, [xbx - offset $Obj(NetComConnection).ChainItem]  ;xbx -> NetComConnection instance

      ;NetComConnectionPool.NewItem links a connection before its Init has set pCritSect
      .if [xbx].$Obj(NetComConnection).pCritSect == NULL
        jmp @@Next
      .endif

      ;Skip only pending acceptors (AcceptEx posted, no client yet). Accepted client connections
      ;are supervised too: inactivity timeout and backpressure of the server -> client direction.
      mov eax, [xbx].$Obj(NetComConnection).dFlags
      and eax, NCC_QUEUE_ACCEPT or NCC_ACCEPTED
      .if eax != NCC_QUEUE_ACCEPT

        ;A busy connection is checked in the next cycle (restarting the traversal can starve)
        invoke TryEnterCriticalSection, [xbx].$Obj(NetComConnection).pCritSect
        .if eax == FALSE
          jmp @@Next
        .endif

        ;Handle connection timeout. A paused connection receives nothing, its peer is supervised.
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

        ;Handle backpressure regulating the receive activity. Both connections of a pair share
        ;one CritSect (NetComConnection.NewPartner), which is held here: the peer needs no lock.
        mov xax, [xbx].$Obj(NetComConnection).pData
        .if xax != NULL
          mov xdi, [xax].SRPS_CONNECTION_DATA.pPeerConnection   ;xdi -> peer connection
          .if xdi != NULL
            mov eax, [xbx].$Obj(NetComConnection).dSndQueuedIOJobs
            .ifBitClr [xdi].$Obj(NetComConnection).dFlags, NCC_RCV_PAUSED
              .if eax >= [xbx].$Obj(NetComConnection).dSndHighWtrMrk
                ;Stop receiving (TCP throttles the peer)
                OCall xdi::NetComConnection.PauseReceive
                DbgText "NCC_RCV_PAUSED"
              .endif
            .else
              .if eax <= [xbx].$Obj(NetComConnection).dSndLowWtrMrk
                ;Reenable receive IOJobs (posts a receive if none is outstanding)
                OCall xdi::NetComConnection.ResumeReceive
              .endif
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
          OCall xbx::NetComConnection.FreeRessources    ;Protocol data, IOJobs, lock owner use
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
