; ==================================================================================================
; Title:      TLS_DefaultCertValidator.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm default implementation of TLS certificate validation.
;             Validates peer certificates using Windows CertGetCertificateChain and
;             CertVerifyCertificateChainPolicy (CERT_CHAIN_POLICY_SSL).
;             Optionally verifies hostname (CN/SAN) via SSL_EXTRA_CERT_CHAIN_POLICY_PARA.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy
; Notes:      Version C.2.1
;               - Fail closed on all errors, EKU check, peer store as additional store,
;                 client certificate validation (ValidateClient, AUTHTYPE_CLIENT).
;             Version C.2.0
;               - Added hostname verification via pszServerName parameter.
;             Version C.1.0
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:     TLS_DefaultCertValidator
; Purpose:    Default implementation of TLS_CertValidator using the Windows certificate chain
;             validation APIs. Builds the certificate chain via CertGetCertificateChain and
;             verifies it against CERT_CHAIN_POLICY_SSL via CertVerifyCertificateChainPolicy.
; Notes:      Returns structured HRESULT error codes:
;               - S_OK (0) on successful validation
;               - CERT_E_EXPIRED (800B0101h) for expired certificates
;               - CERT_E_UNTRUSTEDROOT (800B0109h) for untrusted root CA
;               - CERT_E_CN_NO_MATCH (800B010Fh) for hostname mismatch
;               - Or the dwError from CERT_CHAIN_POLICY_STATUS for other failures

Object TLS_DefaultCertValidator, TLS_DefaultCertValidatorID, TLS_CertValidator
  RedefineMethod  Validate,           POINTER, POINTER  ; pCertContext, pszServerName (ANSI or NULL)
  RedefineMethod  ValidateClient,     POINTER           ; pCertContext (client certificate)
  StaticMethod    DoValidate,         POINTER, POINTER, DWORD ; pCertContext, pszServerName, dAuthType
ObjectEnd

; ==================================================================================================

if IMPLEMENT

ifndef E_OUTOFMEMORY
  E_OUTOFMEMORY             equ   8007000Eh
endif

.const
  ; Extended Key Usage OIDs (ANSI, as required by CERT_ENHKEY_USAGE)
  szTLS_OID_ServerAuth  db "1.3.6.1.5.5.7.3.1", 0     ;szOID_PKIX_KP_SERVER_AUTH
  szTLS_OID_ClientAuth  db "1.3.6.1.5.5.7.3.2", 0     ;szOID_PKIX_KP_CLIENT_AUTH
.code

; ==================================================================================================
;    TLS_DefaultCertValidator implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultCertValidator.Validate
; Purpose:    Validates a SERVER certificate (client side). See DoValidate.
; Arguments:  Arg1: -> CERT_CONTEXT (peer certificate to validate).
;             Arg2: -> ANSI server hostname for CN/SAN check (or NULL to skip hostname check).
; Return:     eax = HRESULT (S_OK on success, CERT_E_xxx on failure).

Method TLS_DefaultCertValidator.Validate, uses xsi, pCertContext:POINTER, pszServerName:POINTER
  SetObject xsi
  OCall xsi.DoValidate, pCertContext, pszServerName, AUTHTYPE_SERVER
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultCertValidator.ValidateClient
; Purpose:    Validates a CLIENT certificate (server side, mutual authentication). See DoValidate.
; Arguments:  Arg1: -> CERT_CONTEXT (client certificate to validate).
; Return:     eax = HRESULT (S_OK on success, CERT_E_xxx on failure).

Method TLS_DefaultCertValidator.ValidateClient, uses xsi, pCertContext:POINTER
  SetObject xsi
  OCall xsi.DoValidate, pCertContext, NULL, AUTHTYPE_CLIENT
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultCertValidator.DoValidate
; Purpose:    Validates a peer certificate by building and verifying the certificate chain.
;             - CertGetCertificateChain with the peer's own certificate store as additional
;               store (intermediate CAs sent in the handshake) and the required Extended Key
;               Usage (Server Authentication or Client Authentication).
;             - CertVerifyCertificateChainPolicy with CERT_CHAIN_POLICY_SSL and
;               SSL_EXTRA_CERT_CHAIN_POLICY_PARA (dAuthType, optional hostname check).
;             Fails closed: every error (including out of memory) is reported as failure.
; Arguments:  Arg1: -> CERT_CONTEXT (peer certificate to validate).
;             Arg2: -> ANSI hostname for the CN/SAN check (or NULL to skip it).
;             Arg3: AUTHTYPE_SERVER (validate a server cert) or AUTHTYPE_CLIENT (client cert).
; Return:     eax = HRESULT (S_OK on success, CERT_E_xxx / error code on failure).
; Note:       No revocation check is performed (dwFlags = 0).

Method TLS_DefaultCertValidator.DoValidate, uses xbx xdi xsi, pCertContext:POINTER, \
                                           pszServerName:POINTER, dAuthType:DWORD
  local ChainPara:CERT_CHAIN_PARA
  local PolicyPara:CERT_CHAIN_POLICY_PARA
  local PolicyStatus:CERT_CHAIN_POLICY_STATUS
  local pChainContext:PCCERT_CHAIN_CONTEXT
  local SslPolicyPara:SSL_EXTRA_CERT_CHAIN_POLICY_PARA
  local pWideServerName:POINTER
  local pUsageOID:POINTER
  local hPeerStore:HANDLE

  SetObject xsi
  mov pWideServerName, NULL
  mov pChainContext, NULL
  mov ebx, CERT_E_UNTRUSTEDROOT                         ;Default result: failure

  ; --- Validate input ---
  .if pCertContext == NULL
    jmp @@Cleanup
  .endif

  ; --- CERT_CHAIN_PARA with the required Extended Key Usage ---
  invoke MemZero, addr ChainPara, sizeof(CERT_CHAIN_PARA)
  mov ChainPara.cbSize, sizeof(CERT_CHAIN_PARA)
  .if dAuthType == AUTHTYPE_CLIENT
    lea xax, szTLS_OID_ClientAuth
  .else
    lea xax, szTLS_OID_ServerAuth
  .endif
  mov pUsageOID, xax
  mov ChainPara.RequestedUsage.dwType, USAGE_MATCH_TYPE_AND
  mov ChainPara.RequestedUsage.Usage.cUsageIdentifier, 1
  lea xax, pUsageOID
  mov ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier, xax

  ; --- Build the certificate chain ---
  ; The peer's store contains the intermediate certificates sent during the handshake.
  mov xax, pCertContext
  m2m hPeerStore, [xax].CERT_CONTEXT.hCertStore, xcx
  invoke CertGetCertificateChain, \
         NULL, \                                ; hChainEngine (NULL = default engine)
         pCertContext, \                        ; pCertContext
         NULL, \                                ; pTime (NULL = current time)
         hPeerStore, \                          ; hAdditionalStore (peer supplied certificates)
         addr ChainPara, \                      ; pChainPara
         0, \                                   ; dwFlags (no revocation check)
         NULL, \                                ; pvReserved
         addr pChainContext                     ; ppChainContext (output)
  .if eax == FALSE
    jmp @@Cleanup                               ;Cannot build chain => untrusted
  .endif

  ; --- SSL_EXTRA_CERT_CHAIN_POLICY_PARA: auth type and optional hostname ---
  invoke MemZero, addr SslPolicyPara, sizeof(SSL_EXTRA_CERT_CHAIN_POLICY_PARA)
  mov SslPolicyPara.cbSize, sizeof(SSL_EXTRA_CERT_CHAIN_POLICY_PARA)
  m2m SslPolicyPara.dwAuthType, dAuthType, eax
  mov SslPolicyPara.fdwChecks, 0
  .if pszServerName != NULL
    ; Convert ANSI hostname to WIDE (required by pwszServerName)
    invoke StrA2NewStrW, pszServerName
    .if xax == NULL
      mov ebx, E_OUTOFMEMORY                    ;Fail closed - never skip the hostname check
      jmp @@Cleanup
    .endif
    mov pWideServerName, xax
    mov SslPolicyPara.pwszServerName, xax
  .endif

  invoke MemZero, addr PolicyPara, sizeof(CERT_CHAIN_POLICY_PARA)
  mov PolicyPara.cbSize, sizeof(CERT_CHAIN_POLICY_PARA)
  lea xax, SslPolicyPara
  mov PolicyPara.pvExtraPolicyPara, xax

  invoke MemZero, addr PolicyStatus, sizeof(CERT_CHAIN_POLICY_STATUS)
  mov PolicyStatus.cbSize, sizeof(CERT_CHAIN_POLICY_STATUS)

  ; --- Verify certificate chain policy (CERT_CHAIN_POLICY_SSL) ---
  invoke CertVerifyCertificateChainPolicy, \
         CERT_CHAIN_POLICY_SSL, \
         pChainContext, \
         addr PolicyPara, \
         addr PolicyStatus
  .if eax != FALSE
    ; dwError already contains a meaningful HRESULT (0 = S_OK, CERT_E_EXPIRED,
    ; CERT_E_UNTRUSTEDROOT, CERT_E_CN_NO_MATCH, CERT_E_WRONG_USAGE, ...)
    mov ebx, PolicyStatus.dwError
  .endif

@@Cleanup:
  .if pChainContext != NULL
    invoke CertFreeCertificateChain, pChainContext
  .endif
  .if pWideServerName != NULL
    invoke StrDispose, pWideServerName
  .endif
  mov eax, ebx
MethodEnd

endif
