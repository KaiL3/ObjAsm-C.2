; ==================================================================================================
; Title:      TLS_DefaultServerCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm standard implementation of TLS_ServerCertProvider.
;             Loads the server certificate from the Windows certificate store using
;             CertOpenStore + CertFindCertificateInStore. Additionally verifies that the
;             found certificate has an associated private key via CryptAcquireCertificatePrivateKey.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants and error codes).
;             Requires TLS_ServerCertProvider.inc (parent class).
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

ifndef CERT_FIND_SUBJECT_STR
  if TARGET_STR_TYPE eq STR_TYPE_WIDE
    CERT_FIND_SUBJECT_STR     equ   000F0007h   ; CERT_FIND_SUBJECT_STR_W
  else
    CERT_FIND_SUBJECT_STR     equ   000F0004h   ; CERT_FIND_SUBJECT_STR_A
  endif
endif

ifndef CERT_SYSTEM_STORE_LOCAL_MACHINE
  CERT_SYSTEM_STORE_LOCAL_MACHINE equ 00020000h
endif

ifndef CRYPT_ACQUIRE_COMPARE_KEY_FLAG
  CRYPT_ACQUIRE_COMPARE_KEY_FLAG  equ 00000010h
endif

ifndef CRYPT_ACQUIRE_SILENT_FLAG
  CRYPT_ACQUIRE_SILENT_FLAG       equ 00000040h
endif

ifndef CERT_NCRYPT_KEY_SPEC
  CERT_NCRYPT_KEY_SPEC            equ 0FFFFFFFFh
endif


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
  RedefineMethod    GetServerCert                       ; Return in xax: -> CERT_CONTEXT or NULL

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
; Purpose:    Search the configured certificate store for a server certificate matching the
;             configured search criteria. Verifies that the certificate has an associated
;             private key. Returns a pointer to the CERT_CONTEXT or NULL.
; Arguments:  None.
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.
; Note:       The caller is responsible for calling CertFreeCertificateContext on the returned
;             CERT_CONTEXT when it is no longer needed.
;             The certificate store is opened and closed within this method.

Method TLS_DefaultServerCertProvider.GetServerCert, uses xbx xdi xsi
  local hStore:HANDLE, dFindType:DWORD, hKey:XWORD, dKeySpec:DWORD, bCallerFree:DWORD
  local pCertSerial:POINTER, pSearchSerial:POINTER, dSerialSize:DWORD

  SetObject xsi
  xor eax, eax
  mov xbx, xax                                       ;xbx = NULL (default return value)

  ; Open the system certificate store (Local Machine)
  invoke CertOpenStore, CERT_STORE_PROV_SYSTEM, 0, 0, \
                        CERT_SYSTEM_STORE_LOCAL_MACHINE, [xsi].pStoreName
  .if xax == NULL
    xor eax, eax                                     ;Return NULL - store open failed
    jmp @@Exit
  .endif
  mov hStore, xax

  ; Map TLS_SEARCH_BY_xxx to CERT_FIND_xxx flags
  mov eax, [xsi].dSearchType
  .if eax == TLS_SEARCH_BY_SUBJECT
    mov dFindType, CERT_FIND_SUBJECT_STR
  .elseif eax == TLS_SEARCH_BY_THUMBPRINT
    mov dFindType, CERT_FIND_HASH
  .elseif eax == TLS_SEARCH_BY_SERIAL
    ; For serial number search, we use CERT_FIND_ANY and iterate.
    ; However, the standard approach is to pass a CRYPT_INTEGER_BLOB.
    ; CertFindCertificateInStore does not directly support serial number search
    ; as a single flag. We use CERT_FIND_ANY + manual comparison.
    ; For simplicity and robustness, we map to CERT_FIND_ANY and will iterate below.
    mov dFindType, CERT_FIND_ANY
  .else
    ; Unknown search type - close store and return NULL
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    jmp @@Exit
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
        ; Sizes match - compare the serial number bytes
        mov xdx, [xsi].pSearchValue
        mov xdx, [xdx].CRYPT_INTEGER_BLOB.pbData
        mov pSearchSerial, xdx
        invoke MemComp, pCertSerial, pSearchSerial, dSerialSize
        .if eax == 0
          ; Found matching serial number
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
    ; CryptAcquireCertificatePrivateKey verifies the certificate has a private key
    m2z hKey
    m2z dKeySpec
    m2z bCallerFree
    invoke CryptAcquireCertificatePrivateKey, xbx, \
           CRYPT_ACQUIRE_COMPARE_KEY_FLAG or CRYPT_ACQUIRE_SILENT_FLAG, \
           NULL, addr hKey, addr dKeySpec, addr bCallerFree
    .if eax == FALSE
      ; No private key associated - free the cert and return NULL
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
  .endif

  ; Close the certificate store
  invoke CertCloseStore, hStore, 0

  ; Return the certificate context (or NULL)
  mov xax, xbx

@@Exit:
MethodEnd

endif
