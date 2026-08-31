; ==================================================================================================
; Title:      TLS_CertStoreLookup.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    Shared certificate store lookup function used by both
;             TLS_DefaultServerCertProvider and TLS_DefaultClientCertProvider.
;             Searches a Windows certificate store by subject, thumbprint, or serial number
;             and verifies private key association.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore
;             - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
; Notes:      Requires wincrypt.inc (for CERT_FIND_xxx, CERT_STORE_PROV_SYSTEM, etc.).
;             Requires TLS_Context.inc (for TLS_SEARCH_BY_xxx constants).
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
; Prototype
; --------------------------------------------------------------------------------------------------

TLS_FindCertInStore proto :DWORD, :DWORD, :POINTER, :POINTER


if IMPLEMENT

ifndef TLS_CERT_STORE_LOOKUP_IMPLEMENTED
TLS_CERT_STORE_LOOKUP_IMPLEMENTED equ 1

.code

; --------------------------------------------------------------------------------------------------
; Function:   TLS_FindCertInStore
; Purpose:    Searches the specified Windows certificate store for a certificate matching
;             the given search criteria. Verifies that the found certificate has an
;             associated private key via CryptAcquireCertificatePrivateKey.
; Arguments:  Arg1: dStoreScope - Store location flags (e.g. CERT_SYSTEM_STORE_CURRENT_USER
;                   or CERT_SYSTEM_STORE_LOCAL_MACHINE).
;             Arg2: dSearchType - Search type (TLS_SEARCH_BY_SUBJECT, TLS_SEARCH_BY_SERIAL,
;                   TLS_SEARCH_BY_THUMBPRINT).
;             Arg3: pSearchValue - Pointer to search value (string for subject,
;                   CRYPT_HASH_BLOB for thumbprint, CRYPT_INTEGER_BLOB for serial).
;             Arg4: pStoreName - Pointer to store name string (e.g. "MY").
; Return:     xax = -> CERT_CONTEXT if found and has private key, NULL otherwise.
; Note:       The caller is responsible for calling CertFreeCertificateContext on the returned
;             CERT_CONTEXT when it is no longer needed.
;             The certificate store is opened and closed within this function.

TLS_FindCertInStore proc uses xbx xdi xsi, dStoreScope:DWORD, dSearchType:DWORD, \
                                            pSearchValue:POINTER, pStoreName:POINTER
  local hStore:HANDLE, dFindType:DWORD, hKey:XWORD, dKeySpec:DWORD, bCallerFree:DWORD
  local pCertSerial:POINTER, pSearchSerial:POINTER, dSerialSize:DWORD

  xor eax, eax
  mov xbx, xax                                       ;xbx = NULL (default return value)

  ; Open the system certificate store
  invoke CertOpenStore, CERT_STORE_PROV_SYSTEM, 0, 0, \
                        dStoreScope, pStoreName
  .if xax == NULL
    DbgWarning "TLS_FindCertInStore - Cannot open store"
    xor eax, eax
    jmp @@Exit
  .endif
  mov hStore, xax

  ; Map TLS_SEARCH_BY_xxx to CERT_FIND_xxx flags
  mov eax, dSearchType
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
    jmp @@Exit
  .endif

  ; Search for the certificate
  mov xdi, NULL                                       ;xdi = pPrevCertContext (for iteration)

  .if dSearchType == TLS_SEARCH_BY_SERIAL
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
      mov xdx, pSearchValue
      mov eax, [xdx].CRYPT_INTEGER_BLOB.cbData
      .if eax == dSerialSize                         ;same size?
        mov xdx, pSearchValue
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
           0, dFindType, pSearchValue, NULL
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
      DbgWarning "TLS_FindCertInStore - No private key"
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
    DbgWarning "TLS_FindCertInStore - Certificate not found"
  .endif

  ; Close the certificate store
  invoke CertCloseStore, hStore, 0

  ; Return the certificate context (or NULL)
  mov xax, xbx

@@Exit:
  ret
TLS_FindCertInStore endp

endif ; TLS_CERT_STORE_LOOKUP_IMPLEMENTED
endif
