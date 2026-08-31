; ==================================================================================================
; Title:      TLS_DefaultClientCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm standard implementation of TLS_ClientCertProvider.
;             Loads the client certificate from the Windows certificate store (CurrentUser\MY)
;             using the shared TLS_FindCertInStore function.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants and error codes).
;             Requires TLS_ClientCertProvider.inc (parent class).
;             Requires TLS_CertStoreLookup.inc (shared lookup function).
;             Version C.2.0
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:     TLS_DefaultClientCertProvider
; Purpose:    Standard implementation of TLS_ClientCertProvider.
;             Searches the Windows CurrentUser certificate store for a client certificate
;             matching the configured search criteria. Verifies private key association
;             before returning the certificate.
; Notes:      - Call SetSearchCriteria before GetClientCert to configure the search.
;             - Call SetStoreName to change the certificate store (default: "MY").
;             - GetClientCert opens and closes the store on each call.
;             - The caller is responsible for calling CertFreeCertificateContext on the
;               returned CERT_CONTEXT when it is no longer needed.

Object TLS_DefaultClientCertProvider, TLS_DefaultClientCertProviderID, TLS_ClientCertProvider
  RedefineMethod    Init,               POINTER         ; -> Owner
  RedefineMethod    Done
  RedefineMethod    GetClientCert                       ; Return in xax: -> CERT_CONTEXT or NULL

  VirtualMethod     SetSearchCriteria,  DWORD, POINTER  ; dSearchType, pSearchValue
  VirtualMethod     SetStoreName,       POINTER         ; pStoreName (String)

  DefineVariable    dSearchType,        DWORD,          0
  DefineVariable    pSearchValue,       POINTER,        NULL
  DefineVariable    pStoreName,         POINTER,        NULL    ; Default set in Init to "MY"
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_DefaultClientCertProvider implementation
; ==================================================================================================

; Include shared certificate store lookup function (guarded against double-inclusion)
include TLS_CertStoreLookup.inc

.const
  CStr TLS_DCCP_DefaultStoreName, "MY"

.code

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.Init
; Purpose:    Initialize the client certificate provider with default values.
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  lea xax, TLS_DCCP_DefaultStoreName
  mov [xsi].pStoreName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.Done
; Purpose:    Cleanup the client certificate provider.
; Arguments:  None.
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.Done, uses xsi
  SetObject xsi
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.SetSearchCriteria
; Purpose:    Configure the search type and value used to find the client certificate.
; Arguments:  Arg1: Search type (TLS_SEARCH_BY_SUBJECT, TLS_SEARCH_BY_SERIAL,
;                   TLS_SEARCH_BY_THUMBPRINT).
;             Arg2: -> Search value (string for subject, CRYPT_HASH_BLOB for thumbprint/serial).
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.SetSearchCriteria, uses xsi, dSearchType:DWORD, pSearchValue:POINTER
  SetObject xsi
  m2m [xsi].dSearchType, dSearchType, eax
  m2m [xsi].pSearchValue, pSearchValue, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.SetStoreName
; Purpose:    Set the certificate store name to search.
; Arguments:  Arg1: -> Store name string (e.g. "MY", "ROOT").
; Return:     Nothing.
; Note:       The caller must ensure the pointer remains valid for the lifetime of this object.

Method TLS_DefaultClientCertProvider.SetStoreName, uses xsi, pStoreName:POINTER
  SetObject xsi
  m2m [xsi].pStoreName, pStoreName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.GetClientCert
; Purpose:    Search the configured certificate store for a client certificate matching the
;             configured search criteria. Delegates to TLS_FindCertInStore.
; Arguments:  None.
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.

Method TLS_DefaultClientCertProvider.GetClientCert, uses xsi
  SetObject xsi
  invoke TLS_FindCertInStore, CERT_SYSTEM_STORE_CURRENT_USER, \
         [xsi].dSearchType, [xsi].pSearchValue, [xsi].pStoreName
MethodEnd

endif
