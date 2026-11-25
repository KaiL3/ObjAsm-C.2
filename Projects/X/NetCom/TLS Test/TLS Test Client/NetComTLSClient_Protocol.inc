; ==================================================================================================
; Title:      NetComTLSClient_Protocol.inc
; Author:     Kai Liebenau
; Version:    See NetComTLSClient.asm
; Purpose:    NetCom TLS Client Application - Protocol with TLS support.
; Notes:      The TLS configuration is a snapshot built from the settings (TestNewTLSConfig).
;             Reconfigure replaces it before connecting; previous snapshots stay alive in the
;             Graveyard until the protocol is finalized, because running connections still
;             reference their config and certificate provider.
;             bRawMode = TRUE creates plain TCP connections (no TLS context) for the handshake
;             trickle test.
; ==================================================================================================


Object NetComTLSClientProtocol,, NetComProtocol
  RedefineMethod  Allocate,           $ObjPtr(NetComConnection)
  RedefineMethod  Done
  RedefineMethod  Init,               POINTER
  RedefineMethod  IsDataComplete?,    $ObjPtr(NetComConnection), PIOJOB
  RedefineMethod  OnClosed,           $ObjPtr(NetComConnection)
  RedefineMethod  OnConfigureTLS,     $ObjPtr(NetComConnection)
  RedefineMethod  OnConnected,        $ObjPtr(NetComConnection)
  RedefineMethod  OnDisconnected,     $ObjPtr(NetComConnection), DWORD, DWORD
  RedefineMethod  OnError,            $ObjPtr(NetComConnection), PIOJOB, DWORD
  RedefineMethod  OnHandshakeComplete,$ObjPtr(NetComConnection)
  RedefineMethod  OnHandshakeFailed,  $ObjPtr(NetComConnection), DWORD
  RedefineMethod  ProcessData,        $ObjPtr(NetComConnection), DWORD
  RedefineMethod  Release,            $ObjPtr(NetComConnection)
  StaticMethod    Reconfigure,        POINTER            ;New TLS config snapshot from TestSettings

  DefineVariable  pTLSConfig,         POINTER,   NULL    ;-> current TLS_Connection_Config
  DefineVariable  pCertProv,          POINTER,   NULL    ;-> current TestCertProv or NULL
  DefineVariable  bRawMode,           DWORD,     FALSE   ;TRUE: plain TCP (handshake trickle test)
  DefineVariable  ClientLocalAddr,    NETCOMADDR, {AF_INETX, 0}
  DefineVariable  ServerRemoteAddr,   NETCOMADDR, {AF_INETX, DEFAULT_SERVER_LISTENING_PORT}

  Embed Graveyard, Collection                            ;Previous snapshots (destroyed in Done)
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    NetComTLSClientProtocol implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.Allocate
; Purpose:    Allocates per-connection data and creates a TLS_SChannelContext for the connection.
;             The client TLS context does not need a ServerCertProvider - it validates the
;             server certificate received during handshake.
; Arguments:  Arg1: -> NetComConnection
; Return:     Zero if succeeded, otherwise an error code.

Method NetComTLSClientProtocol.Allocate, uses xbx xsi, pConnection:$ObjPtr(NetComConnection)
  SetObject xsi
  mov xbx, pConnection

  ; Raw mode (handshake trickle test): plain TCP connection without TLS context
  .if [xsi].bRawMode != FALSE
    xor eax, eax
    ExitMethod
  .endif

  ; Create a new TLS_SChannelContext for this client connection. Without it the connection would
  ; run in plaintext, so a failure must fail the connection (fail closed).
  New TLS_SChannelContext
  .if xax == NULL
    DbgWarning "NetComTLSClientProtocol.Allocate - Failed to create TLS_SChannelContext"
    mov eax, WSA_NOT_ENOUGH_MEMORY
    ExitMethod
  .endif
  mov [xbx].$Obj(NetComConnection).pTLSContext, xax
  ; Init is mandatory: New only copies the template. Init sets the default
  ; TLS_DefaultCertValidator; without it ValidatePeer fails (no validator).
  OCall xax::TLS_SChannelContext.Init, xbx

  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.Init

Method NetComTLSClientProtocol.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  OCall [xsi].BlackList::NetComAddrCollection.Init, xsi, 10, 10, COL_MAX_CAPACITY
  OCall [xsi].Graveyard::Collection.Init, xsi, 8, 8, COL_MAX_CAPACITY

  ; Initial TLS config snapshot (Connect creates a new one with the server address)
  OCall xsi.Reconfigure, NULL
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.Reconfigure
; Purpose:    Creates a new TLS config snapshot from TestSettings. Connections started from now on
;             use it; the previous snapshot is moved into the Graveyard.
; Arguments:  Arg1: -> Server address used as target name if no target name is set, or NULL.
; Return:     Nothing.

Method NetComTLSClientProtocol.Reconfigure, uses xbx xsi, pTargetName:POINTER
  local pNewProv:POINTER

  SetObject xsi
  invoke TestNewTLSConfig, xsi, addr pNewProv, pTargetName
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
    DbgWarning "NetComTLSClientProtocol.Reconfigure - TLS config creation failed", "&PROTOCOL_WND_NAME"
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.IsDataComplete?
; Purpose:    Determines if complete messages (ZTC delimited, e.g. the server echo) were received.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: -> IOJob that triggered the call (not used).
; Return:     eax = Number of BYTEs up to and including the last delimiter, zero if more data is
;                   needed.

Method NetComTLSClientProtocol.IsDataComplete?,, pConnection:$ObjPtr(NetComConnection), pIOJob:PIOJOB
  invoke TestFindDelimiter, pConnection
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.ProcessData
; Purpose:    Counts the received messages and disposes them.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: Number of BYTEs up to and including the last delimiter.
; Return:     eax = Number of BYTEs processed.

Method NetComTLSClientProtocol.ProcessData,, pConnection:$ObjPtr(NetComConnection), dDelimiterIndex:DWORD
  invoke TestCopyData, pConnection, NULL, dDelimiterIndex
  lock add TestStats.dMessages, eax
  mov eax, dDelimiterIndex
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.Done

Method NetComTLSClientProtocol.Done, uses xsi
  SetObject xsi
  .if [xsi].pCertProv != NULL
    Destroy [xsi].pCertProv
    mov [xsi].pCertProv, NULL
  .endif
  .if [xsi].pTLSConfig != NULL
    Destroy [xsi].pTLSConfig
    mov [xsi].pTLSConfig, NULL
  .endif
  OCall [xsi].Graveyard::Collection.Done
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnConfigureTLS
; Purpose:    Returns the shared TLS connection config for the client connection.
;             The hostname (SNI) is set by the UI before ConnectTo is called.
; Arguments:  Arg1: -> NetComConnection.
; Return:     xax -> TLS_Connection_Config.

Method NetComTLSClientProtocol.OnConfigureTLS,, pConnection:$ObjPtr(NetComConnection)
  SetObject xcx
  mov xax, [xcx].pTLSConfig
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnClosed

Method NetComTLSClientProtocol.OnClosed, uses xbx xsi, pConnection:$ObjPtr(NetComConnection)
  SetObject xsi
  mov xbx, [xsi].pOwner
  ;Post to UI thread ù connection is closed
  invoke PostMessage, [xbx].$Obj(NetComTLSClient).SndDlg.hWnd, WM_NETCOM_ENABLE_CTRLS, TRUE, 0
  ACall xsi.OnClosed, pConnection
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnConnected

Method NetComTLSClientProtocol.OnConnected, uses xbx xsi, pConnection:$ObjPtr(NetComConnection)
  SetObject xsi
  DbgText "NetComTLSClientProtocol.OnConnected - TLS handshake initiated", "&PROTOCOL_WND_NAME"
  mov xbx, [xsi].pOwner
  ;Post to UI thread ù do NOT call CtlsEnable directly from worker thread
  invoke PostMessage, [xbx].$Obj(NetComTLSClient).SndDlg.hWnd, WM_NETCOM_ENABLE_CTRLS, FALSE, 0
  ;Raw mode: start a TLS record that announces 512 bytes; the timer trickles the rest
  mov xbx, pConnection
  .if [xbx].$Obj(NetComConnection).pTLSContext == NULL
    DbgText "Raw connection - handshake trickle started", "&PROTOCOL_WND_NAME"
    OCall xbx::NetComConnection.QueueSend, offset bTT_TrickleHeader, sizeof bTT_TrickleHeader
  .endif
  ACall xsi.OnConnected, pConnection
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnDisconnected

Method NetComTLSClientProtocol.OnDisconnected, uses xbx xsi, pConnection:$ObjPtr(NetComConnection), \
                                                             dDirection:DWORD, dResult:DWORD
  SetObject xsi
  DbgText "NetComTLSClientProtocol.OnDisconnected", "&PROTOCOL_WND_NAME"
  mov xbx, [xsi].pOwner
  ;Post to UI thread ù enable controls (connection is logically gone)
  invoke PostMessage, [xbx].$Obj(NetComTLSClient).SndDlg.hWnd, WM_NETCOM_ENABLE_CTRLS, TRUE, 0
  ACall xsi.OnDisconnected, pConnection, dDirection, dResult
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnError

Method NetComTLSClientProtocol.OnError, uses xbx xsi, pConnection:$ObjPtr(NetComConnection), \
                                                      pIOSockJob:PIOJOB, dError:DWORD
  SetObject xsi
  invoke TestStatsError, dError
  DbgWarning "NetComTLSClientProtocol.OnError", "&PROTOCOL_WND_NAME"
  DbgDec dError, "Error code", "&PROTOCOL_WND_NAME"
  mov xbx, [xsi].pOwner
  .ifBitClr [xbx].$Obj(NetComTLSClient).SndDlg.dFlags, SDF_ERROR
    BitSet [xbx].$Obj(NetComTLSClient).SndDlg.dFlags, SDF_ERROR
    ;Post to UI thread ù do NOT call CtlsEnable directly from worker thread
    invoke PostMessage, [xbx].$Obj(NetComTLSClient).SndDlg.hWnd, WM_NETCOM_ENABLE_CTRLS, TRUE, 0
  .endif
  ACall xsi.OnError, pConnection, pIOSockJob, dError
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnHandshakeComplete
; Purpose:    TLS handshake completed - connection is now encrypted and ready for data.
;             Outputs debug information about the validated server certificate.

; SecPkgContext_ConnectionInfo for QueryContextAttributes
ifndef SecPkgContext_ConnectionInfo
  SecPkgContext_ConnectionInfo struct
    dwProtocol      DWORD   ?
    aiCipher        DWORD   ?
    dwCipherStrength DWORD  ?
    aiHash          DWORD   ?
    dwHashStrength  DWORD   ?
    aiExch          DWORD   ?
    dwExchStrength  DWORD   ?
  SecPkgContext_ConnectionInfo ends
endif

ifndef SECPKG_ATTR_CONNECTION_INFO
  SECPKG_ATTR_CONNECTION_INFO equ 5Ah
endif

; Protocol version constants
ifndef SP_PROT_TLS1_CLIENT
  SP_PROT_TLS1_CLIENT      equ 00000080h
endif
ifndef SP_PROT_TLS1_1_CLIENT
  SP_PROT_TLS1_1_CLIENT    equ 00000200h
endif
ifndef SP_PROT_TLS1_2_CLIENT
  SP_PROT_TLS1_2_CLIENT    equ 00000800h
endif
ifndef SP_PROT_TLS1_3_CLIENT
  SP_PROT_TLS1_3_CLIENT    equ 00002000h
endif

Method NetComTLSClientProtocol.OnHandshakeComplete, uses xbx xdi xsi, pConnection:$ObjPtr(NetComConnection)
  local pCertContext:PCCERT_CONTEXT
  local cSubject[256]:CHRA
  local cIssuer[256]:CHRA
  local stNotBefore:SYSTEMTIME
  local stNotAfter:SYSTEMTIME
  local cTimeBuf[128]:CHRA
  local pCertInfo:POINTER
  local pStr:POINTER
  local ConnInfo:SecPkgContext_ConnectionInfo

  SetObject xsi
  lock inc TestStats.dHandshakeOK
  DbgText "NetComTLSClientProtocol.OnHandshakeComplete - TLS session established!", "&PROTOCOL_WND_NAME"

  ; Get the remote (server) certificate
  mov xbx, pConnection
  mov xbx, [xbx].$Obj(NetComConnection).pTLSContext
  .if xbx != NULL
    ; --- Query connection info (protocol version, cipher) ---
    lea xdi, [xbx].$Obj(TLS_SChannelContext).hSecurityContext
    invoke QueryContextAttributesA, xdi, SECPKG_ATTR_CONNECTION_INFO, addr ConnInfo
    .if eax == 0
      ; Decode protocol version to string
      mov eax, ConnInfo.dwProtocol
      .if eax == SP_PROT_TLS1_3_CLIENT
        lea xax, $OfsCStrA("TLS 1.3")
      .elseif eax == SP_PROT_TLS1_2_CLIENT
        lea xax, $OfsCStrA("TLS 1.2")
      .elseif eax == SP_PROT_TLS1_1_CLIENT
        lea xax, $OfsCStrA("TLS 1.1")
      .elseif eax == SP_PROT_TLS1_CLIENT
        lea xax, $OfsCStrA("TLS 1.0")
      .else
        lea xax, $OfsCStrA("Unknown")
      .endif
      mov pStr, xax
      DbgStrA pStr, "  Protocol", "&PROTOCOL_WND_NAME"

      ; Cipher strength
      invoke wsprintfA, addr cTimeBuf, \
             $OfsCStrA("Cipher=0x%04X (%u-bit), Hash=0x%04X (%u-bit), Exchange=0x%04X (%u-bit)"), \
             ConnInfo.aiCipher, ConnInfo.dwCipherStrength, \
             ConnInfo.aiHash, ConnInfo.dwHashStrength, \
             ConnInfo.aiExch, ConnInfo.dwExchStrength
      lea xax, cTimeBuf
      mov pStr, xax
      DbgStrA pStr, "  Algorithms", "&PROTOCOL_WND_NAME"
    .endif

    ; --- Query remote certificate ---
    mov pCertContext, NULL
    invoke QueryContextAttributesA, xdi, SECPKG_ATTR_REMOTE_CERT_CONTEXT, addr pCertContext

    .if eax == 0 && pCertContext != NULL
      DbgText "  --- Server Certificate Info ---", "&PROTOCOL_WND_NAME"

      ; --- Certificate Subject ---
      invoke CertGetNameStringA, pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, \
             0, NULL, addr cSubject, sizeof cSubject
      lea xax, cSubject
      mov pStr, xax
      DbgStrA pStr, "  Subject", "&PROTOCOL_WND_NAME"

      ; --- Certificate Issuer ---
      invoke CertGetNameStringA, pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, \
             CERT_NAME_ISSUER_FLAG, NULL, addr cIssuer, sizeof cIssuer
      lea xax, cIssuer
      mov pStr, xax
      DbgStrA pStr, "  Issuer", "&PROTOCOL_WND_NAME"

      ; --- Validity: NotBefore ---
      mov xdi, pCertContext
      mov xdi, [xdi].CERT_CONTEXT.pCertInfo
      mov pCertInfo, xdi
      lea xax, [xdi].CERT_INFO.NotBefore
      invoke FileTimeToSystemTime, xax, addr stNotBefore
      movzx eax, stNotBefore.wYear
      movzx ecx, stNotBefore.wMonth
      movzx edx, stNotBefore.wDay
      invoke wsprintfA, addr cTimeBuf, $OfsCStrA("Valid from: %04u-%02u-%02u"), eax, ecx, edx
      lea xax, cTimeBuf
      mov pStr, xax
      DbgStrA pStr, "  NotBefore", "&PROTOCOL_WND_NAME"

      ; --- Validity: NotAfter ---
      mov xdi, pCertInfo
      lea xax, [xdi].CERT_INFO.NotAfter
      invoke FileTimeToSystemTime, xax, addr stNotAfter
      movzx eax, stNotAfter.wYear
      movzx ecx, stNotAfter.wMonth
      movzx edx, stNotAfter.wDay
      invoke wsprintfA, addr cTimeBuf, $OfsCStrA("Valid until: %04u-%02u-%02u"), eax, ecx, edx
      lea xax, cTimeBuf
      mov pStr, xax
      DbgStrA pStr, "  NotAfter", "&PROTOCOL_WND_NAME"

      ; Free the certificate context
      invoke CertFreeCertificateContext, pCertContext
    .else
      DbgWarning "  Could not retrieve remote certificate", "&PROTOCOL_WND_NAME"
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.OnHandshakeFailed
; Purpose:    TLS handshake failed.

Method NetComTLSClientProtocol.OnHandshakeFailed, uses xbx xsi, pConnection:$ObjPtr(NetComConnection), \
                                                       dError:DWORD
  SetObject xsi
  lock inc TestStats.dHandshakeFailed
  m2m TestStats.dLastError, dError, eax
  DbgWarning "NetComTLSClientProtocol.OnHandshakeFailed", "&PROTOCOL_WND_NAME"
  DbgHex dError, "SECURITY_STATUS / HRESULT (dLastError)", "&PROTOCOL_WND_NAME"
  mov xbx, [xsi].pOwner
  .ifBitClr [xbx].$Obj(NetComTLSClient).SndDlg.dFlags, SDF_ERROR
    BitSet [xbx].$Obj(NetComTLSClient).SndDlg.dFlags, SDF_ERROR
    ;Post to UI thread
    invoke PostMessage, [xbx].$Obj(NetComTLSClient).SndDlg.hWnd, WM_NETCOM_ENABLE_CTRLS, TRUE, 0
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClientProtocol.Release
; Purpose:    Releases per-connection TLS context.

Method NetComTLSClientProtocol.Release, uses xbx, pConnection:$ObjPtr(NetComConnection)
  mov xbx, pConnection
  DbgWarning "NetComTLSClientProtocol.Release", "&PROTOCOL_WND_NAME"
  ; Free the TLS context if it was allocated
  mov xax, [xbx].$Obj(NetComConnection).pTLSContext
  .if xax != NULL
    mov [xbx].$Obj(NetComConnection).pTLSContext, NULL
    Destroy xax
  .endif
MethodEnd

endif
