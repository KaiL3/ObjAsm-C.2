; ==================================================================================================
; Title:      TLS_DefaultServerCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm standard implementation of TLS_ServerCertProvider.
;             Loads the server certificate from the Windows certificate store using
;             the shared TLS_FindCertInStore function.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants and error codes).
;             Requires TLS_ServerCertProvider.inc (parent class).
;             Requires TLS_CertStoreLookup.inc (shared lookup function).
;             Version C.2.0
;               - Initial release.
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Object:     TLS_DefaultServerCertProvider
; Purpose:    Standard implementation of TLS_ServerCertProvider.
;             Searches the Windows certificate store for a server certificate matching the
;             configured search criteria. Verifies private key association before returning
;             the certificate. Returns NULL if no matching certificate is found or if the
;             certificate lacks an associated private key.
; Notes:      - Call SetSearchCriteria before GetServerCert to configure the search.
;             - Call SetStoreName to change the certificate store (default: "MY").
;             - GetServerCert opens and closes the store on each call.
;             - The caller is responsible for calling CertFreeCertificateContext on the
;               returned CERT_CONTEXT when it is no longer needed.

Object TLS_DefaultServerCertProvider, TLS_DefaultServerCertProviderID, TLS_ServerCertProvider
  RedefineMethod    Init,               POINTER         ; -> Owner
  RedefineMethod    Done
  RedefineMethod    GetServerCert,      POINTER, DWORD  ; pSNIHostname, dSNILen

  VirtualMethod     SetSearchCriteria,  DWORD, POINTER  ; dSearchType, pSearchValue
  VirtualMethod     SetStoreName,       POINTER         ; pStoreName (String)

  DefineVariable    dSearchType,        DWORD,          0
  DefineVariable    pSearchValue,       POINTER,        NULL
  DefineVariable    pStoreName,         POINTER,        NULL    ; Default set in Init to "MY"
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_DefaultServerCertProvider implementation
; ==================================================================================================

; Include shared certificate store lookup function (guarded against double-inclusion)
include TLS_CertStoreLookup.inc

.const
  CStr TLS_DSCP_DefaultStoreName, "MY"

.code

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.Init
; Purpose:    Initialize the server certificate provider with default values.
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method TLS_DefaultServerCertProvider.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  lea xax, TLS_DSCP_DefaultStoreName
  mov [xsi].pStoreName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.Done
; Purpose:    Cleanup the server certificate provider.
; Arguments:  None.
; Return:     Nothing.

Method TLS_DefaultServerCertProvider.Done, uses xsi
  SetObject xsi
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.SetSearchCriteria
; Purpose:    Configure the search type and value used to find the server certificate.
; Arguments:  Arg1: Search type (TLS_SEARCH_BY_SUBJECT, TLS_SEARCH_BY_SERIAL,
;                   TLS_SEARCH_BY_THUMBPRINT).
;             Arg2: -> Search value (string for subject, CRYPT_HASH_BLOB for thumbprint/serial).
; Return:     Nothing.

Method TLS_DefaultServerCertProvider.SetSearchCriteria, uses xsi, dSearchType:DWORD, pSearchValue:POINTER
  SetObject xsi
  m2m [xsi].dSearchType, dSearchType, eax
  m2m [xsi].pSearchValue, pSearchValue, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.SetStoreName
; Purpose:    Set the certificate store name to search.
; Arguments:  Arg1: -> Store name string (e.g. "MY", "ROOT").
; Return:     Nothing.
; Note:       The caller must ensure the pointer remains valid for the lifetime of this object.

Method TLS_DefaultServerCertProvider.SetStoreName, uses xsi, pStoreName:POINTER
  SetObject xsi
  m2m [xsi].pStoreName, pStoreName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultServerCertProvider.GetServerCert
; Purpose:    Search the configured certificate store for a server certificate.
;             Delegates to the shared TLS_FindCertInStore function.
;             The SNI hostname parameters are available for subclasses to override
;             and use for multi-certificate selection. The default implementation ignores them.
; Arguments:  Arg1: -> SNI hostname (may be NULL if no SNI extension present).
;             Arg2: SNI hostname length in bytes.
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.

Method TLS_DefaultServerCertProvider.GetServerCert, uses xsi, pSNIHostname:POINTER, dSNILen:DWORD
  SetObject xsi
  .if pSNIHostname != NULL
    DbgMem pSNIHostname, dSNILen, "SNI"
  .endif
  invoke TLS_FindCertInStore, CERT_SYSTEM_STORE_LOCAL_MACHINE, \
         [xsi].dSearchType, [xsi].pSearchValue, [xsi].pStoreName
MethodEnd

endif
