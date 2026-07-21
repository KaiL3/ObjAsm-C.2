; ==================================================================================================
; Title:      TLS_DefaultClientCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm default implementation of TLS_ClientCertProvider.
;             Loads client certificates from the Windows certificate store using
;             CertOpenStore + CertFindCertificateInStore.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants) and
;             TLS_ClientCertProvider.inc to be loaded.
;             Version C.1.0
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; CertOpenStore / CertFindCertificateInStore constants (from wincrypt.h)
; --------------------------------------------------------------------------------------------------

ifndef CERT_STORE_PROV_SYSTEM
  if TARGET_STR_TYPE eq STR_TYPE_WIDE
    CERT_STORE_PROV_SYSTEM    equ   10    ; CERT_STORE_PROV_SYSTEM_W
  else
    CERT_STORE_PROV_SYSTEM    equ   9     ; CERT_STORE_PROV_SYSTEM_A
  endif
endif
ifndef CERT_SYSTEM_STORE_CURRENT_USER
  CERT_SYSTEM_STORE_CURRENT_USER  equ   00010000h
endif
ifndef X509_ASN_ENCODING
  X509_ASN_ENCODING           equ   00000001h
endif
ifndef PKCS_7_ASN_ENCODING
  PKCS_7_ASN_ENCODING         equ   00010000h
endif
ifndef CERT_FIND_SUBJECT_STR
  if TARGET_STR_TYPE eq STR_TYPE_WIDE
    CERT_FIND_SUBJECT_STR     equ   000F0007h   ; CERT_FIND_SUBJECT_STR_W
  else
    CERT_FIND_SUBJECT_STR     equ   000F0004h   ; CERT_FIND_SUBJECT_STR_A
  endif
endif
ifndef CERT_FIND_HASH
  CERT_FIND_HASH              equ   000D0000h
endif
ifndef CERT_FIND_SERIAL_NUMBER
  CERT_FIND_SERIAL_NUMBER     equ   00000000h   ;Not directly supported; uses CERT_FIND_ANY + manual
endif

; For serial number search, we use CERT_ID structure approach via CERT_FIND_CERT_ID
ifndef CERT_FIND_CERT_ID
  CERT_FIND_CERT_ID           equ   000B0000h
endif

; CERT_ID type for serial number (CERT_ID_ISSUER_SERIAL_NUMBER = 1)
ifndef CERT_ID_ISSUER_SERIAL_NUMBER
  CERT_ID_ISSUER_SERIAL_NUMBER  equ   1
endif

; Encoding type combination commonly used
TLS_ENCODING_TYPE             equ   X509_ASN_ENCODING or PKCS_7_ASN_ENCODING


; --------------------------------------------------------------------------------------------------
; Object:     TLS_DefaultClientCertProvider
; Purpose:    Default implementation of TLS_ClientCertProvider.
;             Searches the Windows certificate store for a client certificate matching the
;             configured search criteria (subject name, serial number, or thumbprint).
; Notes:      - Call SetSearchCriteria to configure what to search for.
;             - Call SetStoreName to change from the default "MY" store.
;             - GetClientCert opens the store, searches, closes store, returns result.

Object TLS_DefaultClientCertProvider, TLS_DefaultClientCertProviderID, TLS_ClientCertProvider
  RedefineMethod  Init,               POINTER         ; pOwner
  RedefineMethod  Done
  RedefineMethod  GetClientCert                       ; Return in xax: -> CERT_CONTEXT or NULL

  VirtualMethod   SetSearchCriteria,  DWORD, POINTER  ; dSearchType, pSearchValue
  VirtualMethod   SetStoreName,       POINTER         ; pStoreName (String)

  DefineVariable  dSearchType,        DWORD,          0
  DefineVariable  pSearchValue,       POINTER,        NULL
  DefineVariable  pStoreName,         POINTER,        NULL    ; Default set in Init to "MY"
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; Default store name string constant: "MY"
CStr szDefaultStoreMY, "MY"


; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.Init
; Purpose:    Initializes the provider with default values.
;             Sets default store name to "MY".
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  ; Set default store name to "MY"
  lea xax, szDefaultStoreMY
  mov [xsi].pStoreName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.Done
; Purpose:    Releases resources and calls parent Done.
; Arguments:  None.
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.Done, uses xsi
  SetObject xsi
  ; pStoreName and pSearchValue are external pointers, not owned by this object.
  ; No heap allocations to free.
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.SetSearchCriteria
; Purpose:    Configures the search type and value for certificate lookup.
; Arguments:  Arg1: Search type (TLS_SEARCH_BY_SUBJECT, TLS_SEARCH_BY_SERIAL,
;                   TLS_SEARCH_BY_THUMBPRINT).
;             Arg2: Pointer to search value:
;                   - For SUBJECT: pointer to string with subject name
;                   - For SERIAL: pointer to CRYPT_INTEGER_BLOB (cbData + pbData)
;                   - For THUMBPRINT: pointer to CRYPT_HASH_BLOB (cbData + pbData)
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.SetSearchCriteria, uses xsi, dType:DWORD, pValue:POINTER
  SetObject xsi
  m2m [xsi].dSearchType, dType, eax
  m2m [xsi].pSearchValue, pValue, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.SetStoreName
; Purpose:    Sets the certificate store name to search in.
; Arguments:  Arg1: Pointer to store name string (e.g. "MY", "ROOT").
; Return:     Nothing.

Method TLS_DefaultClientCertProvider.SetStoreName, uses xsi, pName:POINTER
  SetObject xsi
  m2m [xsi].pStoreName, pName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_DefaultClientCertProvider.GetClientCert
; Purpose:    Opens the configured certificate store, searches for a certificate matching
;             the configured criteria, closes the store, and returns the result.
; Arguments:  None.
; Return:     xax -> CERT_CONTEXT if found, or NULL if not found or on error.
; Notes:      The caller is responsible for eventually calling CertFreeCertificateContext
;             on the returned CERT_CONTEXT when done.
;             CertCloseStore is called after the search; the returned CERT_CONTEXT remains
;             valid because CertFindCertificateInStore duplicates the context internally.

Method TLS_DefaultClientCertProvider.GetClientCert, uses xbx xsi
  local hStore:HANDLE
  local dFindType:DWORD
  local pFindPara:POINTER

  SetObject xsi

  ; Open the system certificate store
  invoke CertOpenStore, CERT_STORE_PROV_SYSTEM, 0, 0, \
                        CERT_SYSTEM_STORE_CURRENT_USER, [xsi].pStoreName
  .if xax == NULL
    ; Store could not be opened - return NULL
    xor eax, eax
    jmp @@Exit
  .endif
  mov hStore, xax

  ; Determine the find type and parameter based on configured search type
  mov eax, [xsi].dSearchType
  .if eax == TLS_SEARCH_BY_SUBJECT
    ; Subject name search: pSearchValue is a string
    mov dFindType, CERT_FIND_SUBJECT_STR
    m2m pFindPara, [xsi].pSearchValue, xax
  .elseif eax == TLS_SEARCH_BY_THUMBPRINT
    ; Thumbprint search: pSearchValue is a pointer to CRYPT_HASH_BLOB
    mov dFindType, CERT_FIND_HASH
    m2m pFindPara, [xsi].pSearchValue, xax
  .elseif eax == TLS_SEARCH_BY_SERIAL
    ; Serial number search: pSearchValue is a pointer to CRYPT_INTEGER_BLOB
    ; Use CERT_FIND_CERT_ID with a CERT_ID structure (type = ISSUER_SERIAL_NUMBER)
    ; For simplicity, we use CERT_FIND_ANY and iterate, but the standard approach
    ; is to pass CRYPT_HASH_BLOB directly. The Windows API does not have a direct
    ; serial number find type, so we use CERT_FIND_CERT_ID.
    mov dFindType, CERT_FIND_CERT_ID
    m2m pFindPara, [xsi].pSearchValue, xax
  .else
    ; Unknown search type - close store and return NULL
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    jmp @@Exit
  .endif

  ; Search for the certificate
  invoke CertFindCertificateInStore, hStore, TLS_ENCODING_TYPE, 0, \
                                     dFindType, pFindPara, NULL
  mov xbx, xax                                         ; Save result (CERT_CONTEXT or NULL)

  ; Close the certificate store
  invoke CertCloseStore, hStore, 0

  ; Return the found certificate context (or NULL)
  mov xax, xbx

@@Exit:
MethodEnd

endif
