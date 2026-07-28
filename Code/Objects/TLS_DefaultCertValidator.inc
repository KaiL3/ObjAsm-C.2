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
; Notes:      Version C.2.0
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
ObjectEnd

; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_DefaultCertValidator implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultCertValidator.Validate
; Purpose:    Validates a peer certificate by building and verifying the certificate chain.
;             Uses CertGetCertificateChain to build the chain, then
;             CertVerifyCertificateChainPolicy with CERT_CHAIN_POLICY_SSL to verify it.
;             If pszServerName is provided (non-NULL), additionally verifies the certificate
;             CN/SAN against the hostname using SSL_EXTRA_CERT_CHAIN_POLICY_PARA.
; Arguments:  Arg1: -> CERT_CONTEXT (peer certificate to validate).
;             Arg2: -> ANSI server hostname for CN/SAN check (or NULL to skip hostname check).
; Return:     eax = HRESULT (S_OK on success, CERT_E_xxx on failure).

Method TLS_DefaultCertValidator.Validate, uses xbx xdi xsi, pCertContext:POINTER, pszServerName:POINTER
  local ChainPara:CERT_CHAIN_PARA
  local PolicyPara:CERT_CHAIN_POLICY_PARA
  local PolicyStatus:CERT_CHAIN_POLICY_STATUS
  local pChainContext:PCCERT_CHAIN_CONTEXT
  local SslPolicyPara:SSL_EXTRA_CERT_CHAIN_POLICY_PARA
  local pWideServerName:POINTER

  SetObject xsi
  mov pWideServerName, NULL

  ; --- Validate input ---
  .if pCertContext == NULL
    mov eax, CERT_E_UNTRUSTEDROOT
    jmp @@Exit
  .endif

  ; --- Initialize CERT_CHAIN_PARA ---
  lea xdi, ChainPara
  xor eax, eax
  mov ecx, sizeof(CERT_CHAIN_PARA)
  push xdi
  ;Zero-fill the structure
  if TARGET_BITNESS eq 32
    shr ecx, 2
    rep stosd
  else
    shr ecx, 3
    rep stosq
  endif
  pop xdi
  mov ChainPara.cbSize, sizeof(CERT_CHAIN_PARA)

  ; --- Build the certificate chain ---
  mov pChainContext, NULL
  invoke CertGetCertificateChain, \
         NULL, \                                ; hChainEngine (NULL = default engine)
         pCertContext, \                        ; pCertContext
         NULL, \                                ; pTime (NULL = current time)
         NULL, \                                ; hAdditionalStore (none)
         addr ChainPara, \                      ; pChainPara
         0, \                                   ; dwFlags (no revocation check for performance)
         NULL, \                                ; pvReserved
         addr pChainContext                     ; ppChainContext (output)

  .if eax == FALSE
    ; CertGetCertificateChain failed - cannot build chain
    mov eax, CERT_E_UNTRUSTEDROOT
    jmp @@Exit
  .endif

  ; --- Initialize CERT_CHAIN_POLICY_PARA ---
  mov PolicyPara.cbSize, sizeof(CERT_CHAIN_POLICY_PARA)
  mov PolicyPara.dwFlags, 0
  mov PolicyPara.pvExtraPolicyPara, NULL

  ; --- Setup SSL_EXTRA_CERT_CHAIN_POLICY_PARA for hostname verification ---
  .if pszServerName != NULL
    ; Convert ANSI hostname to WIDE (required by SSL_EXTRA_CERT_CHAIN_POLICY_PARA.pwszServerName)
    invoke StrA2NewStrW, pszServerName
    mov pWideServerName, xax
    .if xax != NULL
      mov SslPolicyPara.cbSize, sizeof(SSL_EXTRA_CERT_CHAIN_POLICY_PARA)
      mov SslPolicyPara.dwAuthType, AUTHTYPE_SERVER
      mov SslPolicyPara.fdwChecks, 0
      m2m SslPolicyPara.pwszServerName, pWideServerName, xax
      lea xax, SslPolicyPara
      mov PolicyPara.pvExtraPolicyPara, xax
    .endif
  .endif

  ; --- Initialize CERT_CHAIN_POLICY_STATUS ---
  mov PolicyStatus.cbSize, sizeof(CERT_CHAIN_POLICY_STATUS)
  mov PolicyStatus.dwError, 0
  mov PolicyStatus.lChainIndex, 0
  mov PolicyStatus.lElementIndex, 0
  mov PolicyStatus.pvExtraPolicyStatus, NULL

  ; --- Verify certificate chain policy (CERT_CHAIN_POLICY_SSL) ---
  invoke CertVerifyCertificateChainPolicy, \
         CERT_CHAIN_POLICY_SSL, \              ; pszPolicyOID (MAKEINTRESOURCE-style)
         pChainContext, \                       ; pChainContext
         addr PolicyPara, \                     ; pPolicyPara
         addr PolicyStatus                      ; pPolicyStatus

  .if eax == FALSE
    ; CertVerifyCertificateChainPolicy API call itself failed
    invoke CertFreeCertificateChain, pChainContext
    .if pWideServerName != NULL
      invoke StrDispose, pWideServerName
    .endif
    mov eax, CERT_E_UNTRUSTEDROOT
    jmp @@Exit
  .endif

  ; --- Evaluate policy status ---
  mov eax, PolicyStatus.dwError
  .if eax == 0
    ; Validation successful
    invoke CertFreeCertificateChain, pChainContext
    .if pWideServerName != NULL
      invoke StrDispose, pWideServerName
    .endif
    xor eax, eax                                ; S_OK = 0
    jmp @@Exit
  .endif

  ; --- Map policy errors to structured HRESULT codes ---
  ; The dwError already contains a meaningful HRESULT from the chain policy engine.
  ; We pass it through directly, as it maps to CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT,
  ; CERT_E_CN_NO_MATCH, etc. depending on the specific failure.
  mov ebx, eax                                  ; Save error code

  ; Free resources before returning
  invoke CertFreeCertificateChain, pChainContext
  .if pWideServerName != NULL
    invoke StrDispose, pWideServerName
  .endif

  mov eax, ebx                                  ; Return the policy status error as HRESULT

@@Exit:
MethodEnd

endif
