; ==================================================================================================
; Title:      NetComTLSServer_Protocol.inc
; Author:     Kai Liebenau
; Version:    See NetComTLSServer.asm
; Purpose:    NetCom TLS Server Application - Protocol definition with TLS support.
; Notes:      The TLS configuration is a snapshot built from the settings (TestNewTLSConfig).
;             Reconfigure replaces it for new connections; previous snapshots stay alive in the
;             Graveyard until the protocol is finalized, because running connections still
;             reference their config and certificate provider.
; ==================================================================================================


SRVPROTDATA struc
  pNextIOData   POINTER   ?
SRVPROTDATA ends

Object NetComTLSServerProtocol,, NetComProtocol
  RedefineMethod  Allocate,           $ObjPtr(NetComConnection)
  RedefineMethod  Done
  RedefineMethod  Init,               POINTER
  RedefineMethod  IsDataComplete?,    $ObjPtr(NetComConnection), PIOJOB
  RedefineMethod  OnAccepted,         $ObjPtr(NetComConnection)
  RedefineMethod  OnConfigureTLS,     $ObjPtr(NetComConnection)
  RedefineMethod  OnDisconnected,     $ObjPtr(NetComConnection), DWORD, DWORD
  RedefineMethod  OnError,            $ObjPtr(NetComConnection), PIOJOB, DWORD
  RedefineMethod  OnHandshakeComplete,$ObjPtr(NetComConnection)
  RedefineMethod  OnHandshakeFailed,  $ObjPtr(NetComConnection), DWORD
  RedefineMethod  ProcessData,        $ObjPtr(NetComConnection), DWORD
  RedefineMethod  Release,            $ObjPtr(NetComConnection)
  StaticMethod    Reconfigure                            ;New TLS config snapshot from TestSettings

  DefineVariable  pTLSConfig,         POINTER,   NULL    ;-> current TLS_Connection_Config
  DefineVariable  pCertProv,          POINTER,   NULL    ;-> current TestCertProv
  RedefineVariable  ListeningAddr,    {AF_INETX, DEFAULT_SERVER_LISTENING_PORT}

  Embed Graveyard, Collection                            ;Previous snapshots (destroyed in Done)
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    NetComTLSServerProtocol implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.Init
; Purpose:    Initializes the server protocol and creates the TLS configuration snapshot.
; Arguments:  Arg1: -> Owner object.
; Return:     eax = Zero if succeeded, otherwise an error code.

Method NetComTLSServerProtocol.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  OCall [xsi].Graveyard::Collection.Init, xsi, 8, 8, COL_MAX_CAPACITY
  OCall xsi.Reconfigure
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.Done
; Purpose:    Finalizes the server protocol and frees all TLS config snapshots.
; Arguments:  None.
; Return:     Nothing.
; Note:       Call it after NetComEngine.Done (no connection may reference a snapshot anymore).

Method NetComTLSServerProtocol.Done, uses xsi
  SetObject xsi
  .if [xsi].pTLSConfig != NULL
    Destroy [xsi].pTLSConfig
    mov [xsi].pTLSConfig, NULL
  .endif
  .if [xsi].pCertProv != NULL
    Destroy [xsi].pCertProv
    mov [xsi].pCertProv, NULL
  .endif
  OCall [xsi].Graveyard::Collection.Done
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.Reconfigure
; Purpose:    Creates a new TLS config snapshot from TestSettings. Connections admitted from now on
;             use it; the previous snapshot is moved into the Graveyard.
; Arguments:  None.
; Return:     Nothing.

Method NetComTLSServerProtocol.Reconfigure, uses xbx xsi
  local pNewProv:POINTER

  SetObject xsi
  invoke TestNewTLSConfig, xsi, addr pNewProv, NULL
  .if xax != NULL
    mov xbx, [xsi].pTLSConfig
    mov [xsi].pTLSConfig, xax                           ;Atomic pointer switch
    .if xbx != NULL
      OCall [xsi].Graveyard::Collection.Insert, xbx
    .endif
    mov xbx, [xsi].pCertProv
    m2m [xsi].pCertProv, pNewProv, xax
    .if xbx != NULL
      OCall [xsi].Graveyard::Collection.Insert, xbx
    .endif
  .else
    DbgWarning "NetComTLSServerProtocol.Reconfigure - TLS config creation failed", "&PROTOCOL_WND_NAME"
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.Allocate
; Purpose:    Allocates per-connection protocol management data and creates a TLS context.
;             A TLS_SChannelContext is created for each connection and assigned to pTLSContext.
;             TLS configuration (server cert, etc.) is provided via OnConfigureTLS.
; Arguments:  Arg1: -> NetComConnection
; Return:     Zero if succeeded, otherwise an error code.

Method NetComTLSServerProtocol.Allocate, uses xbx xsi, pConnection:$ObjPtr(NetComConnection)
  SetObject xsi
  mov xbx, pConnection
  MemAlloc sizeof SRVPROTDATA
  .if xax == NULL
    OCall xsi.ErrorReport, NULL, NCSP_OUT_OF_MEMORY
    mov eax, WSA_NOT_ENOUGH_MEMORY
    ExitMethod
  .endif
  mov [xbx].$Obj(NetComConnection).pData, xax
  m2z [xax].SRVPROTDATA.pNextIOData

  ; Create a new TLS_SChannelContext for this connection. Without it the connection would run in
  ; plaintext, so a failure must fail the connection (fail closed). Release is not called then.
  New TLS_SChannelContext
  .if xax == NULL
    DbgWarning "NetComTLSServerProtocol.Allocate - Failed to create TLS_SChannelContext"
    MemFree [xbx].$Obj(NetComConnection).pData
    m2z [xbx].$Obj(NetComConnection).pData
    mov eax, WSA_NOT_ENOUGH_MEMORY
    ExitMethod
  .endif
  mov [xbx].$Obj(NetComConnection).pTLSContext, xax
  OCall xax::TLS_SChannelContext.Init, xbx             ;Mandatory: sets default validator etc.
  ; TLS configuration is applied later via OnConfigureTLS (called from Admit)
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.IsDataComplete?
; Purpose:    Determines if complete application-level messages have been received.
;             A ZTC (zero terminating character) delimits a message.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: -> IOJob that triggered the call (not used).
; Return:     eax = Number of BYTEs up to and including the last delimiter, zero if more data is
;                   needed.

Method NetComTLSServerProtocol.IsDataComplete?,, pConnection:$ObjPtr(NetComConnection), pIOJob:PIOJOB
  invoke TestFindDelimiter, pConnection
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.OnAccepted
; Purpose:    An inbound connection has been accepted.
;             Admits the connection (TLS handshake is initiated automatically in Admit).
; Arguments:  Arg1: -> NetComConnection.
; Return:     Nothing.

Method NetComTLSServerProtocol.OnAccepted, uses xbx xsi, pConnection:$ObjPtr(NetComConnection)
  SetObject xsi
  mov xbx, pConnection

  ; Check if the RemoteHost is in the BlackList
  .if $OCall(xsi.IsBlackListed?, addr [xbx].$Obj(NetComConnection).RemoteAddr) != FALSE
    DbgWarning "NetComTLSServerProtocol.OnAccepted - RemoteHost is blacklisted", "&PROTOCOL_WND_NAME"
    OCall xbx::NetComConnection.Admit, FALSE
  .else
    DbgText "NetComTLSServerProtocol.OnAccepted - Connection admitted, TLS handshake starting", "&PROTOCOL_WND_NAME"
    OCall xbx::NetComConnection.Admit, TRUE
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.OnConfigureTLS
; Purpose:    Returns the current TLS config snapshot for a new server-side connection.
; Arguments:  Arg1: -> NetComConnection.
; Return:     xax -> TLS_Connection_Config.

Method NetComTLSServerProtocol.OnConfigureTLS,, pConnection:$ObjPtr(NetComConnection)
  SetObject xcx
  mov xax, [xcx].pTLSConfig
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.OnDisconnected
; Purpose:    An established connection has been disconnected.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: Disconnect direction.
;             Arg3: Operation result. TLS_TRUNCATED = the client closed without close_notify.
; Return:     Nothing.

Method NetComTLSServerProtocol.OnDisconnected, uses xbx xsi, pConnection:$ObjPtr(NetComConnection), \
                                                    dDirection:DWORD, dResult:DWORD
  SetObject xsi
  DbgHex dResult, "NetComTLSServerProtocol.OnDisconnected", "&PROTOCOL_WND_NAME"
  .if dResult == TLS_TRUNCATED
    lock inc TestStats.dTruncated
  .endif
  ACall xsi.OnDisconnected, pConnection, dDirection, dResult
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.OnError
; Purpose:    An error occurred on a connection (I/O error, TLS error, timeout, receive limit).
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: -> IOJob or NULL.
;             Arg3: Error code.
; Return:     eax = Protocol command (PROT_CMD_xxx).

Method NetComTLSServerProtocol.OnError, uses xsi, pConnection:$ObjPtr(NetComConnection), \
                                              pIOJob:PIOJOB, dError:DWORD
  SetObject xsi
  invoke TestStatsError, dError
  DbgDec dError, "NetComTLSServerProtocol.OnError", "&PROTOCOL_WND_NAME"
  ACall xsi.OnError, pConnection, pIOJob, dError
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.OnHandshakeComplete
; Purpose:    TLS handshake completed successfully.
; Arguments:  Arg1: -> NetComConnection.
; Return:     Nothing.

Method NetComTLSServerProtocol.OnHandshakeComplete,, pConnection:$ObjPtr(NetComConnection)
  lock inc TestStats.dHandshakeOK
  DbgText "NetComTLSServerProtocol.OnHandshakeComplete - TLS session established!", "&PROTOCOL_WND_NAME"
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.OnHandshakeFailed
; Purpose:    TLS handshake failed.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: Error code.
; Return:     Nothing.

Method NetComTLSServerProtocol.OnHandshakeFailed, uses xbx, pConnection:$ObjPtr(NetComConnection), \
                                                       dError:DWORD
  lock inc TestStats.dHandshakeFailed
  m2m TestStats.dLastError, dError, eax
  DbgHex dError, "NetComTLSServerProtocol.OnHandshakeFailed", "&PROTOCOL_WND_NAME"
  mov xbx, pConnection
  OCall xbx::NetComConnection.QueueDestroy
  OCall xbx::NetComConnection.Close, TRUE
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.ProcessData
; Purpose:    Processes received application data (plaintext after TLS decryption).
;             Counts the messages, shows the first one and echoes all of them if enabled.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: Number of BYTEs up to and including the last delimiter.
; Return:     eax = Number of BYTEs processed.

Method NetComTLSServerProtocol.ProcessData, uses xdi, pConnection:$ObjPtr(NetComConnection), \
                                             dDelimiterIndex:DWORD
  MemAlloc dDelimiterIndex
  .if xax != NULL
    mov xdi, xax
    invoke TestCopyData, pConnection, xdi, dDelimiterIndex
    lock add TestStats.dMessages, eax
    DbgStrA xdi, "&PROTOCOL_WND_NAME"                  ;First message
    .if TestSettings.bEcho != FALSE
      OCall pConnection::NetComConnection.QueueSend, xdi, dDelimiterIndex
      .if eax < dDelimiterIndex                         ;Send backpressure or closed
        lock inc TestStats.dEchoDropped
      .endif
    .endif
    MemFree xdi
  .endif
  mov eax, dDelimiterIndex                              ;Dispose the processed data
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSServerProtocol.Release
; Purpose:    Releases per-connection protocol data and TLS context.
; Arguments:  Arg1: -> NetComConnection.
; Return:     Nothing.

Method NetComTLSServerProtocol.Release, uses xbx, pConnection:$ObjPtr(NetComConnection)
  mov xbx, pConnection

  ; Free the TLS context if it was allocated
  mov xax, [xbx].$Obj(NetComConnection).pTLSContext
  .if xax != NULL
    Destroy xax
    mov [xbx].$Obj(NetComConnection).pTLSContext, NULL
  .endif

  ; Free protocol data
  .if [xbx].$Obj(NetComConnection).pData != NULL
    MemFree [xbx].$Obj(NetComConnection).pData
    mov [xbx].$Obj(NetComConnection).pData, NULL
  .endif
MethodEnd

endif
