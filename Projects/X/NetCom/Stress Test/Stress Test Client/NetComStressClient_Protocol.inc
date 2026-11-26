; ==================================================================================================
; Title:      NetComStressClient_Protocol.inc
; Author:     G. Friedrich
; Version:    See NetComStressClient.asm
; Purpose:    NetCom Client Application.
; ==================================================================================================


DEFAULT_SERVER_LISTENING_PORT equ $htons(25773)

Object NetComStressClientProtocol,, NetComProtocol
  RedefineMethod  Init,               POINTER                       ;-> Owner
  RedefineMethod  OnClosed,           $ObjPtr(NetComConnection)     ;-> NetComConnection
  RedefineMethod  OnError,            $ObjPtr(NetComConnection), PIOJOB, DWORD

  DefineVariable  ClientLocalAddr,    NETCOMADDR, {AF_INETX, 0} ;Setup Server IP + Port
  DefineVariable  ServerRemoteAddr,   NETCOMADDR, {AF_INETX, DEFAULT_SERVER_LISTENING_PORT}
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    NetComStressClientProtocol implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComStressClientProtocol.Init
; Purpose:    Initializes this object.
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method NetComStressClientProtocol.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  OCall [xsi].BlackList::NetComAddrCollection.Init, xsi, 10, 10, COL_MAX_CAPACITY
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComStressClientProtocol.OnClosed
; Purpose:    A client session has, for whatever reason, been terminated.
;             You can override this, perhaps to release extra per client/task resources.
; Arguments:  Arg1: -> NetComConnection.
; Return:     Nothing.

Method NetComStressClientProtocol.OnClosed, uses xsi, pConnection:$ObjPtr(NetComConnection)
;  DbgHex pConnection, "NetComStressClientProtocol.OnClose", "&PROTOCOL_WND_NAME"
  SetObject xsi
  mov xcx, [xsi].pOwner
  OCall [xcx].$Obj(NetComStressClient).SndDlg::SendDlg.CtlsEnable, TRUE
  ACall xsi.OnClosed, pConnection
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComStressClientProtocol.OnError
; Purpose:    Error notification handler.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: -> IOSockJob.
;             Arg3: Error code.
; Return:     eax = Command (PROT_CMD_XXXX).

Method NetComStressClientProtocol.OnError, uses xbx xdi xsi, pConnection:$ObjPtr(NetComConnection), \
                                                             pIOSockJob:PIOJOB, dError:DWORD
;  DbgHex pConnection, "NetComStressClientProtocol.OnError", "&PROTOCOL_WND_NAME"
  SetObject xsi
  mov xbx, [xsi].pOwner
  .ifBitClr [xbx].$Obj(NetComStressClient).SndDlg.dFlags, SDF_ERROR
    ;The send thread stops by itself (SDF_STOP, or AcquireConnection fails once the connection
    ;is gone). Waiting for it here could block it: it may wait for the CritSect of this
    ;connection, which this worker holds.
    BitSet [xbx].$Obj(NetComStressClient).SndDlg.dFlags, SDF_STOP or SDF_ERROR
    OCall [xbx].$Obj(NetComStressClient).SndDlg::SendDlg.CtlsEnable, TRUE     ;Enable controls
  .endif
  ;ACall xsi.OnError, pConnection, pIOSockJob, dError
  mov eax, PROT_CMD_DESTROY                             ;Abort the failed connection
MethodEnd

endif