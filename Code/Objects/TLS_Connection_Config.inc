; ==================================================================================================
; Title:      TLS_Connection_Config.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    Immutable TLS configuration container for NetCom connections.
;             Bundles all TLS settings needed by a connection for the handshake phase.
;             Read-Only from the connection's perspective. Can be shared across multiple
;             connections (e.g. same server config for all accepted connections).
; Notes:      - pTargetName and pCipherSuites are OWNED (heap-copied, freed in Done).
;             - pCertValidator, pClientCertProvider, pServerCertProvider are NOT owned
;               (references to external objects/templates managed by the application).
;             - Included automatically via NetCom.inc (Framework dependency).
;             Version C.2.0
;               - Initial release.
; ==================================================================================================


Object TLS_Connection_Config, TLS_Connection_ConfigID, Primer
  RedefineMethod  Init,                 POINTER
  RedefineMethod  Done

  ; --- Builder methods (config creator sets these BEFORE handing to connection) ---
  VirtualMethod   SetTargetName,        POINTER           ; pszHostname (ANSI/WIDE, stored as ANSI)
  VirtualMethod   SetAllowedProtocols,  DWORD             ; SP_PROT_TLS1_x bitmask
  VirtualMethod   SetCipherSuites,      POINTER, DWORD    ; pAlgIDArray, dCount (copied!)
  VirtualMethod   SetCertValidator,     POINTER           ; -> TLS_CertValidator instance/template
  VirtualMethod   SetClientCertProvider,POINTER           ; -> TLS_ClientCertProvider
  VirtualMethod   SetServerCertProvider,POINTER           ; -> TLS_ServerCertProvider
  VirtualMethod   SetVerifyServerName,  DWORD             ; TRUE/FALSE
  VirtualMethod   SetMutualAuth,        DWORD             ; TRUE/FALSE (server requests client cert)

  ; --- Getter methods (connection/framework reads these) ---
  VirtualMethod   GetTargetName                           ; xax -> ANSI string (owned) or NULL
  VirtualMethod   GetAllowedProtocols                     ; eax = bitmask
  VirtualMethod   GetCipherSuites,      POINTER, POINTER  ; out ppAlgIDs, out pdCount
  VirtualMethod   GetCertValidator                        ; xax -> TLS_CertValidator or NULL
  VirtualMethod   GetClientCertProvider                   ; xax -> Provider or NULL
  VirtualMethod   GetServerCertProvider                   ; xax -> Provider or NULL
  VirtualMethod   GetVerifyServerName                     ; eax = TRUE/FALSE
  VirtualMethod   GetMutualAuth                           ; eax = TRUE/FALSE

  ; --- Instance Variables ---
  DefineVariable  pTargetName,          POINTER,  NULL    ; Heap-copied hostname (owned)
  DefineVariable  dAllowedProtocols,    DWORD,    SP_PROT_TLS1_2 or SP_PROT_TLS1_3
  DefineVariable  pCipherSuites,        POINTER,  NULL    ; Heap-copied ALG_ID array (owned)
  DefineVariable  dCipherSuiteCount,    DWORD,    0
  DefineVariable  pCertValidator,       POINTER,  NULL    ; Reference (not owned)
  DefineVariable  bValidatorIsSet,      BOOL,     FALSE   ; Indicator if Validator is set
  DefineVariable  pClientCertProvider,  POINTER,  NULL    ; Reference (not owned)
  DefineVariable  pServerCertProvider,  POINTER,  NULL    ; Reference (not owned)
  DefineVariable  bVerifyServerName,    DWORD,    TRUE
  DefineVariable  bMutualAuth,          DWORD,    FALSE
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_Connection_Config implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.Init
; Purpose:    Initializes the configuration object with defaults.
; Arguments:  Arg1: -> Owner object.
; Return:     eax = OBJ_OK.

Method TLS_Connection_Config.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  mov [xsi].pTargetName, NULL
  mov [xsi].dAllowedProtocols, SP_PROT_TLS1_2 or SP_PROT_TLS1_3
  mov [xsi].pCipherSuites, NULL
  mov [xsi].dCipherSuiteCount, 0
  mov [xsi].pCertValidator, NULL
  mov [xsi].pClientCertProvider, NULL
  mov [xsi].pServerCertProvider, NULL
  mov [xsi].bVerifyServerName, TRUE
  mov [xsi].bMutualAuth, FALSE
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.Done
; Purpose:    Frees owned resources (copied hostname and cipher suite array).
; Arguments:  None.
; Return:     Nothing.

Method TLS_Connection_Config.Done, uses xsi
  SetObject xsi
  .if [xsi].pTargetName != NULL
    invoke StrDispose, [xsi].pTargetName
    mov [xsi].pTargetName, NULL
  .endif
  .if [xsi].pCipherSuites != NULL
    MemFree [xsi].pCipherSuites
    mov [xsi].pCipherSuites, NULL
  .endif
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetTargetName
; Purpose:    Sets the target server hostname for SNI. The string is COPIED into owned memory.
;             Accepts ANSI or WIDE depending on TARGET_STR_TYPE, stores always as ANSI
;             (SChannel requirement). Freed with StrDispose.
; Arguments:  Arg1: -> Hostname string in current TARGET_STR_TYPE (or NULL to clear).
; Return:     Nothing.

Method TLS_Connection_Config.SetTargetName, uses xsi, pszHostname:POINTER
  SetObject xsi
  ; Free previous
  .if [xsi].pTargetName != NULL
    invoke StrDispose, [xsi].pTargetName
    mov [xsi].pTargetName, NULL
  .endif
  ; Copy new (convert to ANSI if WIDE build)
  .if pszHostname != NULL
    if TARGET_STR_TYPE eq STR_TYPE_WIDE
      invoke StrW2NewStrA, pszHostname
    else
      invoke StrNewA, pszHostname
    endif
    mov [xsi].pTargetName, xax
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetAllowedProtocols
; Purpose:    Sets the allowed TLS protocol version bitmask.
; Arguments:  Arg1: Protocol bitmask (combination of SP_PROT_TLS1_x constants).
; Return:     Nothing.

Method TLS_Connection_Config.SetAllowedProtocols, uses xsi, dProtocolMask:DWORD
  SetObject xsi
  m2m [xsi].dAllowedProtocols, dProtocolMask, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetCipherSuites
; Purpose:    Sets the allowed cipher suite array. The array is COPIED into owned memory.
; Arguments:  Arg1: -> ALG_ID array (or NULL to clear).
;             Arg2: Number of elements.
; Return:     Nothing.

Method TLS_Connection_Config.SetCipherSuites, uses xbx xsi, pAlgIDs:POINTER, dCount:DWORD
  SetObject xsi
  ; Free previous
  .if [xsi].pCipherSuites != NULL
    MemFree [xsi].pCipherSuites
    mov [xsi].pCipherSuites, NULL
    mov [xsi].dCipherSuiteCount, 0
  .endif
  ; Copy new
  .if pAlgIDs != NULL && dCount != 0
    mov eax, dCount
    shl eax, 2                                          ; * sizeof(DWORD) = ALG_ID size
    mov ebx, eax
    MemAlloc ebx
    .if xax != NULL
      mov [xsi].pCipherSuites, xax
      m2m [xsi].dCipherSuiteCount, dCount, edx
      invoke MemClone, xax, pAlgIDs, ebx
    .endif
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetCertValidator
; Purpose:    Sets the certificate validator reference (not owned).
; Arguments:  Arg1: -> TLS_CertValidator instance/template (or NULL).
; Return:     Nothing.

Method TLS_Connection_Config.SetCertValidator, uses xsi, pValidator:POINTER
  SetObject xsi
  m2m [xsi].pCertValidator, pValidator, xax
  mov [xsi].bValidatorIsSet, TRUE
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetClientCertProvider
; Purpose:    Sets the client certificate provider reference (not owned).
; Arguments:  Arg1: -> TLS_ClientCertProvider (or NULL).
; Return:     Nothing.

Method TLS_Connection_Config.SetClientCertProvider, uses xsi, pProvider:POINTER
  SetObject xsi
  m2m [xsi].pClientCertProvider, pProvider, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetServerCertProvider
; Purpose:    Sets the server certificate provider reference (not owned).
; Arguments:  Arg1: -> TLS_ServerCertProvider (or NULL).
; Return:     Nothing.

Method TLS_Connection_Config.SetServerCertProvider, uses xsi, pProvider:POINTER
  SetObject xsi
  m2m [xsi].pServerCertProvider, pProvider, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetVerifyServerName
; Purpose:    Sets whether to verify server certificate against SNI hostname.
; Arguments:  Arg1: TRUE/FALSE.
; Return:     Nothing.

Method TLS_Connection_Config.SetVerifyServerName, uses xsi, bVerify:DWORD
  SetObject xsi
  m2m [xsi].bVerifyServerName, bVerify, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.SetMutualAuth
; Purpose:    Sets whether server should request client certificate (mutual authentication).
; Arguments:  Arg1: TRUE/FALSE.
; Return:     Nothing.

Method TLS_Connection_Config.SetMutualAuth, uses xsi, bMutual:DWORD
  SetObject xsi
  m2m [xsi].bMutualAuth, bMutual, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetTargetName
; Purpose:    Returns the stored target hostname.
; Arguments:  None.
; Return:     xax -> ANSI hostname string (owned by Config) or NULL.

Method TLS_Connection_Config.GetTargetName
  SetObject xcx
  mov xax, [xcx].pTargetName
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetAllowedProtocols
; Purpose:    Returns the allowed protocol bitmask.
; Arguments:  None.
; Return:     eax = Protocol bitmask.

Method TLS_Connection_Config.GetAllowedProtocols
  SetObject xcx
  mov eax, [xcx].dAllowedProtocols
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetCipherSuites
; Purpose:    Returns the cipher suite array and count.
; Arguments:  Arg1: -> POINTER to receive pAlgIDs.
;             Arg2: -> DWORD to receive count.
; Return:     Nothing (values stored via output pointers).

Method TLS_Connection_Config.GetCipherSuites, uses xsi, ppAlgIDs:POINTER, pdCount:POINTER
  SetObject xsi
  mov xax, ppAlgIDs
  .if xax != NULL
    mov xcx, [xsi].pCipherSuites
    mov [xax], xcx
  .endif
  mov xax, pdCount
  .if xax != NULL
    mov ecx, [xsi].dCipherSuiteCount
    mov [xax], ecx
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetCertValidator
; Purpose:    Returns the certificate validator reference.
; Arguments:  None.
; Return:     xax -> TLS_CertValidator or NULL.

Method TLS_Connection_Config.GetCertValidator
  SetObject xcx
  .if [xcx].bValidatorIsSet
    mov xax, [xcx].pCertValidator
  .else
    lea xax, offset $ObjTmpl(TLS_DefaultCertValidator)
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetClientCertProvider
; Purpose:    Returns the client certificate provider reference.
; Arguments:  None.
; Return:     xax -> Provider or NULL.

Method TLS_Connection_Config.GetClientCertProvider
  SetObject xcx
  mov xax, [xcx].pClientCertProvider
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetServerCertProvider
; Purpose:    Returns the server certificate provider reference.
; Arguments:  None.
; Return:     xax -> Provider or NULL.

Method TLS_Connection_Config.GetServerCertProvider
  SetObject xcx
  mov xax, [xcx].pServerCertProvider
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetVerifyServerName
; Purpose:    Returns whether server name verification is enabled.
; Arguments:  None.
; Return:     eax = TRUE/FALSE.

Method TLS_Connection_Config.GetVerifyServerName
  SetObject xcx
  mov eax, [xcx].bVerifyServerName
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Connection_Config.GetMutualAuth
; Purpose:    Returns whether mutual authentication is enabled.
; Arguments:  None.
; Return:     eax = TRUE/FALSE.

Method TLS_Connection_Config.GetMutualAuth
  SetObject xcx
  mov eax, [xcx].bMutualAuth
MethodEnd

endif
