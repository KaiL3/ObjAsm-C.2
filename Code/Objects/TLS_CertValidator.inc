; ==================================================================================================
; Title:      TLS_CertValidator.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm abstract base class for TLS certificate validation (Strategy-Pattern).
;             Defines the interface that custom validation classes must implement.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy
; Notes:      Version C.1.0
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:     TLS_CertValidator
; Purpose:    Abstract base class for certificate validation (Strategy-Pattern).
;             Defines the Validate method that derived classes must implement to perform
;             certificate chain validation. The caller passes a PCCERT_CONTEXT and expects
;             an HRESULT return value (S_OK = success, error HRESULT = failure reason).
; Notes:      This is a pure abstract class – Validate must be overridden by derived classes.

Object TLS_CertValidator, TLS_CertValidatorID, Primer
  VirtualAbstract   Validate,         POINTER, POINTER ; pCertContext, pszServerName (ANSI or NULL) -> HRESULT in eax
  VirtualMethod     ValidateClient,   POINTER          ; pCertContext (client cert, server side) -> HRESULT in eax
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_CertValidator implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertValidator.ValidateClient
; Purpose:    Validates a CLIENT certificate (server side, mutual authentication).
;             Default implementation: delegates to Validate without hostname, so existing
;             validators keep working. Override it to apply client specific rules
;             (e.g. AUTHTYPE_CLIENT / Client Authentication EKU).
; Arguments:  Arg1: -> CERT_CONTEXT of the client certificate.
; Return:     eax = HRESULT (S_OK on success).

Method TLS_CertValidator.ValidateClient, uses xsi, pCertContext:POINTER
  SetObject xsi
  OCall xsi.Validate, pCertContext, NULL
MethodEnd

endif
