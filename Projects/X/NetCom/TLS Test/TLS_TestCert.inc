; ==================================================================================================
; Title:      TLS_TestCert.inc
; Author:     Kai Liebenau
; Version:    1.0.0
; Purpose:    Loads a test certificate from a PFX file and installs it into the Windows
;             certificate store (CurrentUser\MY) if not already present.
; Notes:      The certificate is self-signed with subject "CN=ObjAsm TLS Test".
;             The PFX file "ObjAsmTLSTest.pfx" must exist relative to the executable
;             or in the TLS Test folder. Password: "test"
;
;             To regenerate the test certificate (PowerShell):
;               Run GenerateCert.ps1 in the TLS Test folder.
; ==================================================================================================


; Certificate subject name used for searching in the store
CStr szTLS_TestCertSubject, "ObjAsm TLS Test"

; PFX file path (relative to executable or absolute)
CStr szTLS_TestPfxFile, "..\ObjAsmTLSTest.pfx"

; PFX Password (wide string for PFXImportCertStore)
.const
ALIGN 4
szTLS_TestPfxPassword  dw 't','e','s','t',0

% include &IncPath&Windows\wincrypt.inc

; NOTE: CERT_FIND_SUBJECT_STR and CERT_STORE_PROV_SYSTEM are now correctly
; defined in wincrypt.inc based on TARGET_STR_TYPE. No override needed.


; ==================================================================================================
; Procedure:  InstallTestCertificate
; Purpose:    Checks if the test certificate is already in the CurrentUser\MY store.
;             If not found, reads the PFX file from disk and imports it.
; Arguments:  None.
; Return:     eax = TRUE if certificate is available (already existed or successfully installed),
;                   FALSE if installation failed.
; ==================================================================================================

.code
InstallTestCertificate proc uses xbx xdi xsi
  local hStore:HANDLE, hPfxStore:HANDLE
  local PfxBlob:CRYPT_DATA_BLOB
  local pCert:POINTER
  local hFile:HANDLE, dFileSize:DWORD, pFileData:POINTER, dBytesRead:DWORD

  ; Open the CurrentUser "MY" store
  invoke CertOpenStore, CERT_STORE_PROV_SYSTEM, 0, 0, \
                        CERT_SYSTEM_STORE_CURRENT_USER, $OfsCStr("MY")
  .if xax == NULL
    DbgWarning "InstallTestCertificate: Cannot open CurrentUser MY store"
    xor eax, eax
    ret
  .endif
  mov hStore, xax

  ; Check if certificate is already installed (search by subject)
  invoke CertFindCertificateInStore, hStore, \
         X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, \
         0, CERT_FIND_SUBJECT_STR, offset szTLS_TestCertSubject, NULL
  .if xax != NULL
    ; Certificate already exists - free context and return success
    invoke CertFreeCertificateContext, xax
    invoke CertCloseStore, hStore, 0
    DbgText "InstallTestCertificate: Certificate already installed"
    mov eax, TRUE
    ret
  .endif

  ; Certificate not found - load PFX file from disk
  DbgText "InstallTestCertificate: Loading PFX file..."

  ; Open the PFX file
  invoke CreateFile, offset szTLS_TestPfxFile, GENERIC_READ, FILE_SHARE_READ, \
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
  .if xax == INVALID_HANDLE_VALUE
    DbgWarning "InstallTestCertificate: Cannot open PFX file"
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    ret
  .endif
  mov hFile, xax

  ; Get file size
  invoke GetFileSize, hFile, NULL
  .if eax == INVALID_FILE_SIZE || eax == 0
    DbgWarning "InstallTestCertificate: Invalid PFX file size"
    invoke CloseHandle, hFile
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    ret
  .endif
  mov dFileSize, eax

  ; Allocate buffer and read the file
  MemAlloc dFileSize
  .if xax == NULL
    DbgWarning "InstallTestCertificate: Cannot allocate memory for PFX"
    invoke CloseHandle, hFile
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    ret
  .endif
  mov pFileData, xax

  invoke ReadFile, hFile, pFileData, dFileSize, addr dBytesRead, NULL
  invoke CloseHandle, hFile

  ; Set up PFX blob from file data
  mov xax, pFileData
  mov PfxBlob.pbData, xax
  mov eax, dFileSize
  mov PfxBlob.cbData, eax

  ; Import PFX with password "test" (CurrentUser keyset)
  invoke PFXImportCertStore, addr PfxBlob, offset szTLS_TestPfxPassword, \
         CRYPT_USER_KEYSET
  .if xax == NULL
    DbgWarning "InstallTestCertificate: PFXImportCertStore failed"
    MemFree pFileData
    invoke CertCloseStore, hStore, 0
    xor eax, eax
    ret
  .endif
  mov hPfxStore, xax

  ; Free file buffer (no longer needed)
  MemFree pFileData

  ; Enumerate certificates from PFX store and add to MY store
  mov pCert, NULL
  mov xbx, TRUE                                       ;Success flag
  .while TRUE
    invoke CertEnumCertificatesInStore, hPfxStore, pCert
    .break .if xax == NULL
    mov pCert, xax

    ; Add certificate to the CurrentUser MY store
    invoke CertAddCertificateContextToStore, hStore, pCert, \
           CERT_STORE_ADD_REPLACE_EXISTING, NULL
    .if eax == FALSE
      DbgWarning "InstallTestCertificate: CertAddCertificateContextToStore failed"
      mov xbx, FALSE
    .endif
  .endw

  ; Close PFX temporary store
  invoke CertCloseStore, hPfxStore, 0

  ; Close MY store
  invoke CertCloseStore, hStore, 0

  mov xax, xbx                                        ;Return success/failure
  ret
InstallTestCertificate endp
