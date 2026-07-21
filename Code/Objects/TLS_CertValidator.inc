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
  VirtualAbstract   Validate,         POINTER         ; pCertContext -> HRESULT in eax
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_CertValidator implementation
;    (No concrete methods – Validate is abstract)
; ==================================================================================================

endif
