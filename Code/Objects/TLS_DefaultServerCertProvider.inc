; ==================================================================================================
; Title:      TLS_DefaultServerCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm standard implementation of TLS_ServerCertProvider.
;             Loads the server certificate from the Windows LocalMachine certificate store
;             using the inherited TLS_CertProvider.FindCert method.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants and error codes).
;             Requires TLS_ServerCertProvider.inc (parent class).
;             Requires TLS_CertProvider.inc (grandparent class: shared state + FindCert).
;             Version C.2.0
;               - Initial release.
;               - Refactored: search state, setters and store lookup moved to the shared
;                 TLS_CertProvider base class. Only GetServerCert remains here.
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Object:     TLS_DefaultServerCertProvider
; Purpose:    Standard implementation of TLS_ServerCertProvider.
;             Searches the Windows LocalMachine certificate store for a server certificate
;             matching the configured search criteria (inherited from TLS_CertProvider).
;             Verifies private key association before returning the certificate. Returns NULL
;             if no matching certificate is found or if it lacks an associated private key.
; Notes:      - Call SetSearchCriteria (inherited) before GetServerCert to configure the search.
;             - Call SetStoreName (inherited) to change the certificate store (default: "MY").
;             - GetServerCert opens and closes the store on each call.
;             - The caller is responsible for calling CertFreeCertificateContext on the
;               returned CERT_CONTEXT when it is no longer needed.

Object TLS_DefaultServerCertProvider, TLS_DefaultServerCertProviderID, TLS_ServerCertProvider
  RedefineMethod    Init,               POINTER         ; -> Owner
  RedefineMethod    GetServerCert,      POINTER, DWORD  ; pSNIHostname, dSNILen
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_DefaultServerCertProvider implementation
; ==================================================================================================

.code

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.Init
; Purpose:    Initialize the server certificate provider. Sets the store scope to LocalMachine
;             (where server certificates typically reside), overriding the base class default.
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method TLS_DefaultServerCertProvider.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  mov [xsi].dStoreScope, CERT_SYSTEM_STORE_LOCAL_MACHINE
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.GetServerCert
; Purpose:    Search the configured certificate store for a server certificate.
;             Delegates to the inherited TLS_CertProvider.FindCert method, which uses the
;             configured store scope (default LocalMachine, set in Init; overridable via
;             SetStoreScope). The SNI hostname parameters are available for subclasses to
;             override and use for multi-certificate selection. The default implementation
;             ignores them.
; Arguments:  Arg1: -> SNI hostname (may be NULL if no SNI extension present).
;             Arg2: SNI hostname length in bytes.
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.

Method TLS_DefaultServerCertProvider.GetServerCert, uses xsi, pSNIHostname:POINTER, dSNILen:DWORD
  SetObject xsi
  .if pSNIHostname != NULL
    DbgMem pSNIHostname, dSNILen, "SNI"
  .endif
  ACall xsi.FindCert
MethodEnd

endif
