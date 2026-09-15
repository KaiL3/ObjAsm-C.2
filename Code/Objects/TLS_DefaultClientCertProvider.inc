; ==================================================================================================
; Title:      TLS_DefaultClientCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm standard implementation of TLS_ClientCertProvider.
;             Loads the client certificate from the Windows CurrentUser certificate store
;             using the inherited TLS_CertProvider.FindCert method.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants and error codes).
;             Requires TLS_ClientCertProvider.inc (parent class).
;             Requires TLS_CertProvider.inc (grandparent class: shared state + FindCert).
;             Version C.2.0
;               - Initial release.
;               - Refactored: search state, setters and store lookup moved to the shared
;                 TLS_CertProvider base class. Only GetClientCert remains here.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:     TLS_DefaultClientCertProvider
; Purpose:    Standard implementation of TLS_ClientCertProvider.
;             Searches the Windows CurrentUser certificate store for a client certificate
;             matching the configured search criteria (inherited from TLS_CertProvider).
;             Verifies private key association before returning the certificate.
; Notes:      - Call SetSearchCriteria (inherited) before GetClientCert to configure the search.
;             - Call SetStoreName (inherited) to change the certificate store (default: "MY").
;             - GetClientCert opens and closes the store on each call.
;             - The caller is responsible for calling CertFreeCertificateContext on the
;               returned CERT_CONTEXT when it is no longer needed.

Object TLS_DefaultClientCertProvider, TLS_DefaultClientCertProviderID, TLS_ClientCertProvider
  RedefineMethod    GetClientCert                       ; Return in xax: -> CERT_CONTEXT or NULL
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_DefaultClientCertProvider implementation
; ==================================================================================================

.code

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.GetClientCert
; Purpose:    Search the configured certificate store for a client certificate matching the
;             configured search criteria. Delegates to the inherited TLS_CertProvider.FindCert
;             method, which uses the configured store scope (default CurrentUser, set in the
;             base class Init; overridable via SetStoreScope).
; Arguments:  None.
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.

Method TLS_DefaultClientCertProvider.GetClientCert, uses xsi
  SetObject xsi
  ACall xsi.FindCert
MethodEnd

endif
