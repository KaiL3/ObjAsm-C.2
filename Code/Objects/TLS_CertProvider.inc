; ==================================================================================================
; Title:      TLS_CertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm abstract base class shared by TLS_ClientCertProvider and
;             TLS_ServerCertProvider. Holds the common certificate search state
;             (search type, search value, store name) and the shared Windows certificate
;             store lookup logic (FindCert). Concrete providers derive their respective
;             GetClientCert / GetServerCert abstract interface from the two intermediate
;             classes and reuse FindCert with the appropriate store scope.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants).
;             Requires wincrypt.inc (for CERT_FIND_xxx, CERT_STORE_PROV_SYSTEM, etc.).
;             Version C.2.0
;               - Initial release. Extracted shared state and lookup from
;                 TLS_DefaultServerCertProvider / TLS_DefaultClientCertProvider and the
;                 former TLS_CertStoreLookup.inc helper.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Fallback constants (if wincrypt.inc was not included or lacks these)
; --------------------------------------------------------------------------------------------------

ifndef CERT_SYSTEM_STORE_CURRENT_USER
  CERT_SYSTEM_STORE_CURRENT_USER    equ 00010000h
endif

ifndef CERT_SYSTEM_STORE_LOCAL_MACHINE
  CERT_SYSTEM_STORE_LOCAL_MACHINE   equ 00020000h
endif

ifndef CRYPT_ACQUIRE_COMPARE_KEY_FLAG
  CRYPT_ACQUIRE_COMPARE_KEY_FLAG    equ 00000010h
endif

ifndef CRYPT_ACQUIRE_SILENT_FLAG
  CRYPT_ACQUIRE_SILENT_FLAG         equ 00000040h
endif

ifndef CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG
  CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG equ 00010000h
endif

ifndef CERT_NCRYPT_KEY_SPEC
  CERT_NCRYPT_KEY_SPEC              equ 0FFFFFFFFh
endif


; --------------------------------------------------------------------------------------------------
; Object:     TLS_CertProvider
; Purpose:    Abstract base class for certificate providers. Concentrates the certificate
;             search configuration (type/value/store) and the store lookup routine that both
;             the client and the server default providers share. This class is never
;             instantiated directly; use a concrete derived provider instead.
; Notes:      - Init sets the default store name "MY".
;             - SetSearchCriteria / SetStoreName configure the lookup before GetXxxCert.
;             - FindCert opens the store, searches, verifies private key, and closes the
;               store. The caller frees the returned CERT_CONTEXT via
;               CertFreeCertificateContext.

Object TLS_CertProvider, TLS_CertProviderID, Primer
  RedefineMethod    Init,               POINTER         ; -> Owner
  RedefineMethod    Done

  VirtualMethod     SetSearchCriteria,  DWORD, POINTER  ; dSearchType, pSearchValue
  VirtualMethod     SetStoreName,       POINTER         ; pStoreName (String)
  VirtualMethod     SetStoreScope,      DWORD           ; dStoreScope (CERT_SYSTEM_STORE_xxx)
  StaticMethod      FindCert                            ; -> xax: CERT_CONTEXT or NULL

  DefineVariable    dSearchType,        DWORD,          0
  DefineVariable    pSearchValue,       POINTER,        NULL
  DefineVariable    pStoreName,         POINTER,        NULL    ; Default set in Init to "MY"
  DefineVariable    dStoreScope,        DWORD,          0       ; Default set in Init (CurrentUser)
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_CertProvider implementation
; ==================================================================================================

.const
  CStr TLS_CP_DefaultStoreName, "MY"

.code

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertProvider.Init
; Purpose:    Initialize the certificate provider with default values.
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method TLS_CertProvider.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner
  lea xax, TLS_CP_DefaultStoreName
  mov [xsi].pStoreName, xax
  mov [xsi].dStoreScope, CERT_SYSTEM_STORE_CURRENT_USER   ;Neutral default; concrete providers override
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertProvider.Done
; Purpose:    Cleanup the certificate provider.
; Arguments:  None.
; Return:     Nothing.

Method TLS_CertProvider.Done, uses xsi
  SetObject xsi
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertProvider.SetSearchCriteria
; Purpose:    Configure the search type and value used to find the certificate.
; Arguments:  Arg1: Search type (TLS_SEARCH_BY_SUBJECT, TLS_SEARCH_BY_SERIAL,
;                   TLS_SEARCH_BY_THUMBPRINT).
;             Arg2: -> Search value (string for subject, CRYPT_HASH_BLOB for thumbprint,
;                   CRYPT_INTEGER_BLOB for serial).
; Return:     Nothing.

Method TLS_CertProvider.SetSearchCriteria, uses xsi, dSearchType:DWORD, pSearchValue:POINTER
  SetObject xsi
  m2m [xsi].dSearchType, dSearchType, eax
  m2m [xsi].pSearchValue, pSearchValue, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertProvider.SetStoreName
; Purpose:    Set the certificate store name to search.
; Arguments:  Arg1: -> Store name string (e.g. "MY", "ROOT").
; Return:     Nothing.
; Note:       The caller must ensure the pointer remains valid for the lifetime of this object.

Method TLS_CertProvider.SetStoreName, uses xsi, pStoreName:POINTER
  SetObject xsi
  m2m [xsi].pStoreName, pStoreName, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertProvider.SetStoreScope
; Purpose:    Set the certificate store location scope used by FindCert.
; Arguments:  Arg1: dStoreScope - Store location flags (CERT_SYSTEM_STORE_CURRENT_USER or
;                   CERT_SYSTEM_STORE_LOCAL_MACHINE, etc.).
; Return:     Nothing.

Method TLS_CertProvider.SetStoreScope, uses xsi, dStoreScope:DWORD
  SetObject xsi
  m2m [xsi].dStoreScope, dStoreScope, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_CertProvider.FindCert
; Purpose:    Search the configured Windows certificate store for a certificate matching the
;             instance search criteria (dSearchType / pSearchValue / pStoreName / dStoreScope).
;             Verifies that the found certificate has an associated private key via
;             CryptAcquireCertificatePrivateKey.
; Arguments:  None. The store location is taken from the dStoreScope instance variable
;             (configure via SetStoreScope; default set in Init).
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.
; Note:       The caller is responsible for calling CertFreeCertificateContext on the returned
;             CERT_CONTEXT when it is no longer needed. The store is opened and closed here.

Method TLS_CertProvider.FindCert, uses xbx xdi xsi
  local hStore:HANDLE, dFindType:DWORD, hKey:XWORD, dKeySpec:DWORD, bCallerFree:DWORD
  local pCertSerial:POINTER, pSearchSerial:POINTER, dSerialSize:DWORD

  SetObject xsi
  xor eax, eax
  mov xbx, xax                                       ;xbx = NULL (default return value)

  ; Open the system certificate store
  invoke CertOpenStore, CERT_STORE_PROV_SYSTEM, 0, 0, \
                        [xsi].dStoreScope, [xsi].pStoreName
  .if xax == NULL
    DbgWarning "TLS_CertProvider.FindCert - Cannot open store"
    xor eax, eax
    ExitMethod
  .endif
  mov hStore, xax

  ; Map TLS_SEARCH_BY_xxx to CERT_FIND_xxx flags
  mov eax, [xsi].dSearchType
  .if eax == TLS_SEARCH_BY_SUBJECT
    mov dFindType, CERT_FIND_SUBJECT_STR
  .elseif eax == TLS_SEARCH_BY_THUMBPRINT
    mov dFindType, CERT_FIND_HASH
  .elseif eax == TLS_SEARCH_BY_SERIAL
    mov dFindType, CERT_FIND_ANY
  .else
    ; Unknown search type - close store and return NULL
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    ExitMethod
  .endif

  ; Search for the certificate
  mov xdi, NULL                                       ;xdi = pPrevCertContext (for iteration)

  .if [xsi].dSearchType == TLS_SEARCH_BY_SERIAL
    ; Serial number search: iterate through all certificates and compare serial numbers.
    ; pSearchValue points to a CRYPT_INTEGER_BLOB with the target serial number.
    .while TRUE
      invoke CertFindCertificateInStore, hStore, \
             X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, \
             0, CERT_FIND_ANY, NULL, xdi
      .break .if xax == NULL
      mov xdi, xax                                   ;xdi = current cert context

      ; Get the certificate's serial number blob
      mov xax, [xdi].CERT_CONTEXT.pCertInfo
      mov ecx, [xax].CERT_INFO.SerialNumber.cbData
      mov dSerialSize, ecx
      mov xax, [xax].CERT_INFO.SerialNumber.pbData
      mov pCertSerial, xax

      ; Get the search criteria serial number blob
      mov xdx, [xsi].pSearchValue
      mov eax, [xdx].CRYPT_INTEGER_BLOB.cbData
      .if eax == dSerialSize                         ;same size?
        mov xdx, [xsi].pSearchValue
        mov xdx, [xdx].CRYPT_INTEGER_BLOB.pbData
        mov pSearchSerial, xdx
        invoke MemComp, pCertSerial, pSearchSerial, dSerialSize
        .if eax == 0
          mov xbx, xdi                               ;xbx = found cert
          .break
        .endif
      .endif
    .endw
  .else
    ; Subject or Thumbprint search: direct CertFindCertificateInStore call
    invoke CertFindCertificateInStore, hStore, \
           X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, \
           0, dFindType, [xsi].pSearchValue, NULL
    mov xbx, xax                                     ;xbx = found cert (or NULL)
  .endif

  ; If certificate found, verify private key association
  .if xbx != NULL
    m2z hKey
    m2z dKeySpec
    m2z bCallerFree
    invoke CryptAcquireCertificatePrivateKey, xbx, \
           CRYPT_ACQUIRE_COMPARE_KEY_FLAG or CRYPT_ACQUIRE_SILENT_FLAG or CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, \
           NULL, addr hKey, addr dKeySpec, addr bCallerFree
    .if eax == FALSE
      ; No private key associated - free the cert and return NULL
      DbgWarning "TLS_CertProvider.FindCert - No private key"
      invoke CertFreeCertificateContext, xbx
      mov xbx, NULL
    .else
      ; Private key verified. If caller must free the key handle, do so.
      .if bCallerFree != FALSE
        .if dKeySpec == CERT_NCRYPT_KEY_SPEC
          invoke NCryptFreeObject, hKey
        .else
          invoke CryptReleaseContext, hKey, 0
        .endif
      .endif
    .endif
  .else
    DbgWarning "TLS_CertProvider.FindCert - Certificate not found"
  .endif

  ; Close the certificate store
  invoke CertCloseStore, hStore, 0

  ; Return the certificate context (or NULL)
  mov xax, xbx
MethodEnd

endif
