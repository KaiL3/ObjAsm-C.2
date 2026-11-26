; ==================================================================================================
; Title:      TLS_TestCommon.inc
; Author:     Kai Liebenau
; Version:    1.1.0
; Purpose:    Shared code of the NetCom TLS test server and client:
;               - settings (defaults, INI file next to the executable),
;               - TLS configuration snapshots (TLS_Connection_Config + certificate provider),
;               - NetCom limits and timeouts (supervisor, receive limit),
;               - statistics, message scanning and connection test actions.
; Notes:      The including .asm file must define TLS_TEST_ROLE (TLS_TEST_ROLE_SERVER or
;             TLS_TEST_ROLE_CLIENT) before including this file.
;             Version 1.1.0, November 2026
;               - Initial release.
; ==================================================================================================


TLS_TEST_ROLE_SERVER    equ   1
TLS_TEST_ROLE_CLIENT    equ   2

ifndef TLS_TEST_ROLE
  .err <TLS_TestCommon.inc: TLS_TEST_ROLE is not defined>
endif

;Protocol selection bits stored in the settings (mapped to SP_PROT_xxx_SERVER / _CLIENT)
TTP_TLS10               equ   BIT00
TTP_TLS11               equ   BIT01
TTP_TLS12               equ   BIT02
TTP_TLS13               equ   BIT03

;Certificate store scope stored in the settings
TT_SCOPE_CURRENT_USER   equ   0
TT_SCOPE_LOCAL_MACHINE  equ   1

TT_MAX_SECONDS          equ   429                       ;Max. seconds in 100ns units in a DWORD
TT_MAX_LIMIT_KB         equ   4194303                   ;Max. KB that fit in a DWORD as BYTEs
TT_MAX_CIPHERS          equ   32                        ;Max. ALG_IDs in the cipher list
;IOJob buffer size of the test engines: a full TLS record (16 KB plaintext + header/trailer)
;fits into one IOJob, and a WSARecv fetches up to this many BYTEs at once.
TT_IOJOB_BUFFER_SIZE    equ   16*1024 + 1024
TT_MAX_CERT_BYTES       equ   64                        ;Max. bytes of a thumbprint / serial
TT_STORE_LEN            equ   64                        ;Characters incl. ZTC
TT_TEXT_LEN             equ   256                       ;Characters incl. ZTC

;Connection test actions (TestConnectionsAction)
TTA_PAUSE               equ   1                         ;PauseReceive
TTA_RESUME              equ   2                         ;ResumeReceive
TTA_DISCONNECT          equ   3                         ;Graceful disconnect (close_notify + FIN)
TTA_ABORT               equ   4                         ;Abortive close (RST)
TTA_TRICKLE             equ   5                         ;Send one byte on raw (non-TLS) connections
TTA_COUNT_PAUSED        equ   6                         ;Count paused connections

TLS_TEST_SETTINGS struct
  dPort             DWORD   ?                           ;Server: listening port (host byte order)
  dInactivitySec    DWORD   ?                           ;NetComSupervisor.dInactivityTimeout
  dHandshakeSec     DWORD   ?                           ;NetComSupervisor.dHandshakeTimeout
  dShutdownSec      DWORD   ?                           ;NetComSupervisor.dTLSShutdownTimeout
  dPauseSec         DWORD   ?                           ;NetComSupervisor.dRcvPauseTimeout
  dRcvLimitKB       DWORD   ?                           ;NetComProtocol.dMaxRcvBuffered / 1024
  dProtocols        DWORD   ?                           ;TTP_xxx
  bMutualAuth       DWORD   ?                           ;Server: require, client: provide a cert
  bVerifyName       DWORD   ?                           ;Client: verify the server name
  bEcho             DWORD   ?                           ;Server: echo received messages
  dTrickleSec       DWORD   ?                           ;Client: raw trickle interval
  dCertSearch       DWORD   ?                           ;TLS_SEARCH_BY_xxx
  dCertScope        DWORD   ?                           ;TT_SCOPE_xxx
  cCertStore        CHR     TT_STORE_LEN dup(?)         ;Store name, e.g. "MY"
  cCertValue        CHR     TT_TEXT_LEN dup(?)          ;Subject / thumbprint hex / serial hex
  cTargetName       CHR     TT_TEXT_LEN dup(?)          ;Client: SNI name, empty = server address
  cCiphers          CHR     TT_TEXT_LEN dup(?)          ;ALG_ID hex list, empty = default
TLS_TEST_SETTINGS ends
PTLS_TEST_SETTINGS typedef ptr TLS_TEST_SETTINGS

TLS_TEST_STATS struct
  dHandshakeOK      DWORD   ?
  dHandshakeFailed  DWORD   ?
  dErrors           DWORD   ?
  dLastError        DWORD   ?
  dMessages         DWORD   ?
  dEchoDropped      DWORD   ?
TLS_TEST_STATS ends

;Search data owned by a certificate provider. TLS_CertProvider stores only pointers, so the
;strings and blobs must live as long as the provider.
TT_CERT_SEARCH struct
  cStore            CHR     TT_STORE_LEN dup(?)
  cValue            CHR     TT_TEXT_LEN dup(?)
  Blob              CRYPT_INTEGER_BLOB <>               ;Thumbprint (CRYPT_HASH_BLOB) or serial
  bBytes            BYTE    TT_MAX_CERT_BYTES dup(?)
TT_CERT_SEARCH ends


; --------------------------------------------------------------------------------------------------
; Object:     TestCertProv
; Purpose:    Certificate provider of the own role, configured from the settings (owns its search
;             data). Server: server certificate, client: client certificate. Only one role is built
;             per application, so both share the name; the ancestor depends on the role and must be
;             loaded in the .asm (TLS_DefaultServerCertProvider / TLS_DefaultClientCertProvider).

if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
  TT_CERT_PROV_ANCESTOR textequ <TLS_DefaultServerCertProvider>
else
  TT_CERT_PROV_ANCESTOR textequ <TLS_DefaultClientCertProvider>
endif

%Object TestCertProv,, TT_CERT_PROV_ANCESTOR
  StaticMethod      Setup                               ;Applies the store and search settings

  DefineVariable    Search,     TT_CERT_SEARCH,     {}
ObjectEnd


.data?
  TestSettings      TLS_TEST_SETTINGS   <>              ;Active settings
  TestStats         TLS_TEST_STATS      <>              ;Statistics (updated by worker threads)
  cTT_IniFile       CHR                 MAX_PATH dup(?) ;INI file next to the executable

.const
  CStr szTT_Section, "Settings"
  bTT_TrickleHeader BYTE 16h, 03h, 01h, 02h, 00h        ;TLS record header: handshake, 512 bytes
  bTT_Zero          BYTE 0

.code

; --------------------------------------------------------------------------------------------------
; Procedure:  TestSettingsDefault
; Purpose:    Fills a settings structure with the default values of the current role.
; Arguments:  Arg1: -> TLS_TEST_SETTINGS.
; Return:     Nothing.

TestSettingsDefault proc uses xdi, pSettings:PTLS_TEST_SETTINGS
  mov xdi, pSettings
  invoke MemZero, xdi, sizeof TLS_TEST_SETTINGS
  mov [xdi].TLS_TEST_SETTINGS.dPort, 25774
  mov [xdi].TLS_TEST_SETTINGS.dInactivitySec, 60
  mov [xdi].TLS_TEST_SETTINGS.dHandshakeSec, 15
  mov [xdi].TLS_TEST_SETTINGS.dShutdownSec, 5
  mov [xdi].TLS_TEST_SETTINGS.dPauseSec, 60
  mov [xdi].TLS_TEST_SETTINGS.dRcvLimitKB, 1024
  mov [xdi].TLS_TEST_SETTINGS.dProtocols, TTP_TLS12 or TTP_TLS13
  mov [xdi].TLS_TEST_SETTINGS.bVerifyName, TRUE
  mov [xdi].TLS_TEST_SETTINGS.dTrickleSec, 3
  mov [xdi].TLS_TEST_SETTINGS.dCertSearch, TLS_SEARCH_BY_SUBJECT
  mov [xdi].TLS_TEST_SETTINGS.dCertScope, TT_SCOPE_CURRENT_USER
  invoke StrCopy, addr [xdi].TLS_TEST_SETTINGS.cCertStore, $OfsCStr("MY")
if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
  mov [xdi].TLS_TEST_SETTINGS.bMutualAuth, FALSE
  mov [xdi].TLS_TEST_SETTINGS.bEcho, TRUE
  invoke StrCopy, addr [xdi].TLS_TEST_SETTINGS.cCertValue, $OfsCStr("ObjAsm TLS Test")
else
  mov [xdi].TLS_TEST_SETTINGS.bMutualAuth, TRUE
  invoke StrCopy, addr [xdi].TLS_TEST_SETTINGS.cCertValue, $OfsCStr("ObjAsm Test Client")
endif
  ret
TestSettingsDefault endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestIniInit
; Purpose:    Builds the INI file name: executable path with the extension ".ini".
; Arguments:  None.
; Return:     Nothing.

TestIniInit proc uses xbx xdi
  invoke GetModuleFileName, NULL, offset cTT_IniFile, MAX_PATH - 5
  lea xbx, cTT_IniFile                                  ;xbx -> start of the path
  lea xdi, [xbx + xax*sizeof(CHR)]                      ;xdi -> ZTC
  mov xcx, xdi
  .while xcx > xbx
    sub xcx, sizeof(CHR)
    .if CHR ptr [xcx] == '.'
      mov xdi, xcx                                      ;Replace the extension
      .break
    .endif
    .break .if CHR ptr [xcx] == '\'
  .endw
  invoke StrCopy, xdi, $OfsCStr(".ini")
  ret
TestIniInit endp

;Helper macros for the INI access of a TestSettings field
TT_INI_GETINT macro Field:req, Key:req
  invoke GetPrivateProfileInt, offset szTT_Section, $OfsCStr(Key), \
                               TestSettings.Field, offset cTT_IniFile
  mov TestSettings.Field, eax
endm

TT_INI_GETSTR macro Field:req, Key:req, Chars:req
  invoke StrCopy, addr cDefault, addr TestSettings.Field
  invoke GetPrivateProfileString, offset szTT_Section, $OfsCStr(Key), addr cDefault, \
                                  addr TestSettings.Field, Chars, offset cTT_IniFile
endm

TT_INI_PUTINT macro Field:req, Key:req
  invoke udword2dec, addr cBuffer, TestSettings.Field
  invoke WritePrivateProfileString, offset szTT_Section, $OfsCStr(Key), \
                                    addr cBuffer, offset cTT_IniFile
endm

TT_INI_PUTSTR macro Field:req, Key:req
  invoke WritePrivateProfileString, offset szTT_Section, $OfsCStr(Key), \
                                    addr TestSettings.Field, offset cTT_IniFile
endm

; --------------------------------------------------------------------------------------------------
; Procedure:  TestSettingsLoad
; Purpose:    Sets the defaults and overwrites them with the values found in the INI file.
; Arguments:  None.
; Return:     Nothing.

TestSettingsLoad proc
  local cDefault[TT_TEXT_LEN]:CHR

  invoke TestSettingsDefault, offset TestSettings
  TT_INI_GETINT dPort,          "Port"
  TT_INI_GETINT dInactivitySec, "InactivityTimeout"
  TT_INI_GETINT dHandshakeSec,  "HandshakeTimeout"
  TT_INI_GETINT dShutdownSec,   "TLSShutdownTimeout"
  TT_INI_GETINT dPauseSec,      "RcvPauseTimeout"
  TT_INI_GETINT dRcvLimitKB,    "RcvLimitKB"
  TT_INI_GETINT dProtocols,     "Protocols"
  TT_INI_GETINT bMutualAuth,    "MutualAuth"
  TT_INI_GETINT bVerifyName,    "VerifyServerName"
  TT_INI_GETINT bEcho,          "Echo"
  TT_INI_GETINT dTrickleSec,    "TrickleInterval"
  TT_INI_GETINT dCertSearch,    "CertSearch"
  TT_INI_GETINT dCertScope,     "CertScope"
  TT_INI_GETSTR cCertStore,     "CertStore",  TT_STORE_LEN
  TT_INI_GETSTR cCertValue,     "CertValue",  TT_TEXT_LEN
  TT_INI_GETSTR cTargetName,    "TargetName", TT_TEXT_LEN
  TT_INI_GETSTR cCiphers,       "Ciphers",    TT_TEXT_LEN
  ret
TestSettingsLoad endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestSettingsSave
; Purpose:    Writes the active settings into the INI file.
; Arguments:  None.
; Return:     Nothing.

TestSettingsSave proc
  local cBuffer[32]:CHR

  TT_INI_PUTINT dPort,          "Port"
  TT_INI_PUTINT dInactivitySec, "InactivityTimeout"
  TT_INI_PUTINT dHandshakeSec,  "HandshakeTimeout"
  TT_INI_PUTINT dShutdownSec,   "TLSShutdownTimeout"
  TT_INI_PUTINT dPauseSec,      "RcvPauseTimeout"
  TT_INI_PUTINT dRcvLimitKB,    "RcvLimitKB"
  TT_INI_PUTINT dProtocols,     "Protocols"
  TT_INI_PUTINT bMutualAuth,    "MutualAuth"
  TT_INI_PUTINT bVerifyName,    "VerifyServerName"
  TT_INI_PUTINT bEcho,          "Echo"
  TT_INI_PUTINT dTrickleSec,    "TrickleInterval"
  TT_INI_PUTINT dCertSearch,    "CertSearch"
  TT_INI_PUTINT dCertScope,     "CertScope"
  TT_INI_PUTSTR cCertStore,     "CertStore"
  TT_INI_PUTSTR cCertValue,     "CertValue"
  TT_INI_PUTSTR cTargetName,    "TargetName"
  TT_INI_PUTSTR cCiphers,       "Ciphers"
  ret
TestSettingsSave endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestHexDigit
; Purpose:    Converts a hex digit character.
; Arguments:  Arg1: Character.
; Return:     eax = Value 0..15 or -1 if the character is not a hex digit.

TestHexDigit proc dChar:DWORD
  mov eax, dChar
  .if eax >= '0' && eax <= '9'
    sub eax, '0'
  .elseif eax >= 'a' && eax <= 'f'
    sub eax, 'a' - 10
  .elseif eax >= 'A' && eax <= 'F'
    sub eax, 'A' - 10
  .else
    mov eax, -1
  .endif
  ret
TestHexDigit endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestParseHexBytes
; Purpose:    Converts a hex string (e.g. "A1 B2:C3-d4") into bytes. Blanks, ':' and '-' are
;             ignored.
; Arguments:  Arg1: -> Hex string.
;             Arg2: -> Destination buffer.
;             Arg3: Destination buffer size in bytes.
; Return:     eax = Number of bytes or -1 if the string is invalid or too long.

TestParseHexBytes proc uses xbx xdi xsi, pText:POINTER, pBytes:POINTER, dMax:DWORD
  local dCount:DWORD, dHigh:DWORD

  mov xsi, pText
  mov xdi, pBytes
  mov dCount, 0
  mov dHigh, -1                                         ;-1 = no pending high nibble
  .while TRUE
    movzx ebx, CHR ptr [xsi]
    add xsi, sizeof(CHR)
    .break .if ebx == 0
    .continue .if ebx == ' ' || ebx == ':' || ebx == '-'
    invoke TestHexDigit, ebx
    .if SDWORD ptr eax < 0
      mov eax, -1
      ret
    .endif
    .if dHigh == -1
      mov dHigh, eax
    .else
      mov ecx, dCount
      .if ecx >= dMax
        mov eax, -1
        ret
      .endif
      mov edx, dHigh
      shl edx, 4
      or edx, eax
      mov BYTE ptr [xdi + xcx], dl
      inc dCount
      mov dHigh, -1
    .endif
  .endw
  .if dHigh != -1                                       ;Odd number of digits
    mov eax, -1
  .else
    mov eax, dCount
  .endif
  ret
TestParseHexBytes endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestParseCipherList
; Purpose:    Converts a list of hex ALG_IDs (e.g. "6610, 660E") into a DWORD array.
;             Separators are blanks, ',' and ';'.
; Arguments:  Arg1: -> List string.
;             Arg2: -> DWORD array.
;             Arg3: Max. number of entries.
; Return:     eax = Number of entries (0 = empty list) or -1 if the list is invalid.

TestParseCipherList proc uses xbx xdi xsi, pText:POINTER, pArray:POINTER, dMax:DWORD
  local dCount:DWORD, dValue:DWORD, bInNumber:DWORD

  mov xsi, pText
  mov xdi, pArray
  mov dCount, 0
  mov dValue, 0
  mov bInNumber, FALSE
  .while TRUE
    movzx ebx, CHR ptr [xsi]
    add xsi, sizeof(CHR)
    .if ebx == 0 || ebx == ' ' || ebx == ',' || ebx == ';'
      .if bInNumber != FALSE                            ;End of a number => store it
        mov ecx, dCount
        .if ecx >= dMax
          mov eax, -1
          ret
        .endif
        mov eax, dValue
        mov DWORD ptr [xdi + xcx*sizeof(DWORD)], eax
        inc dCount
        mov dValue, 0
        mov bInNumber, FALSE
      .endif
      .break .if ebx == 0
    .else
      invoke TestHexDigit, ebx
      .if SDWORD ptr eax < 0 || dValue > 0FFFFFFFh
        mov eax, -1
        ret
      .endif
      shl dValue, 4
      or dValue, eax
      mov bInNumber, TRUE
    .endif
  .endw
  mov eax, dCount
  ret
TestParseCipherList endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestProtocolMask
; Purpose:    Converts the TTP_xxx bits of the settings into the SChannel protocol mask of the
;             current role.
; Arguments:  Arg1: TTP_xxx bits.
; Return:     eax = SP_PROT_xxx mask.

TestProtocolMask proc dProtocols:DWORD
  xor eax, eax
  mov ecx, dProtocols
if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
  .ifBitSet ecx, TTP_TLS10
    or eax, 00000040h                                   ;SP_PROT_TLS1_0_SERVER
  .endif
  .ifBitSet ecx, TTP_TLS11
    or eax, 00000100h                                   ;SP_PROT_TLS1_1_SERVER
  .endif
  .ifBitSet ecx, TTP_TLS12
    or eax, 00000400h                                   ;SP_PROT_TLS1_2_SERVER
  .endif
  .ifBitSet ecx, TTP_TLS13
    or eax, 00001000h                                   ;SP_PROT_TLS1_3_SERVER
  .endif
else
  .ifBitSet ecx, TTP_TLS10
    or eax, 00000080h                                   ;SP_PROT_TLS1_0_CLIENT
  .endif
  .ifBitSet ecx, TTP_TLS11
    or eax, 00000200h                                   ;SP_PROT_TLS1_1_CLIENT
  .endif
  .ifBitSet ecx, TTP_TLS12
    or eax, 00000800h                                   ;SP_PROT_TLS1_2_CLIENT
  .endif
  .ifBitSet ecx, TTP_TLS13
    or eax, 00002000h                                   ;SP_PROT_TLS1_3_CLIENT
  .endif
endif
  ret
TestProtocolMask endp

;QueryCredentialsAttributes is declared in sspi.inc, which the TLS objects do not include
ifndef SECPKG_ATTR_SUPPORTED_ALGS
  SECPKG_ATTR_SUPPORTED_ALGS    equ   86

  SecPkgCred_SupportedAlgs struct
    cSupportedAlgs      DWORD   ?
    palgSupportedAlgs   POINTER ?                       ;-> ALG_ID array, free with FreeContextBuffer
  SecPkgCred_SupportedAlgs ends

  QueryCredentialsAttributesA proto WIN_STD_CALL_CONV :POINTER, :DWORD, :POINTER
endif

; --------------------------------------------------------------------------------------------------
; Procedure:  TestEnumStoreCallback
; Purpose:    CertEnumSystemStore callback: adds the store name to a combo box.
; Arguments:  Arg1: -> Store name (WIDE).
;             Arg2: Flags.
;             Arg3: -> CERT_SYSTEM_STORE_INFO.
;             Arg4: Reserved.
;             Arg5: Combo box HANDLE.
; Return:     eax = TRUE to continue the enumeration.

TestEnumStoreCallback proc pvSystemStore:POINTER, dFlags:DWORD, pStoreInfo:POINTER, \
                           pvReserved:POINTER, pvArg:POINTER
  invoke SendMessageW, pvArg, CB_ADDSTRING, 0, pvSystemStore
  mov eax, TRUE
  ret
TestEnumStoreCallback endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestFillStoreCombo
; Purpose:    Fills a combo box with the system certificate stores of a store scope and sets the
;             edit text to the current store name (which may be a custom name).
; Arguments:  Arg1: Combo box HANDLE.
;             Arg2: TT_SCOPE_xxx.
;             Arg3: -> Current store name.
; Return:     Nothing.

TestFillStoreCombo proc uses xbx, hCombo:HWND, dScope:DWORD, pCurrent:POINTER
  invoke SendMessage, hCombo, CB_RESETCONTENT, 0, 0
  .if dScope == TT_SCOPE_LOCAL_MACHINE
    mov ebx, CERT_SYSTEM_STORE_LOCAL_MACHINE
  .else
    mov ebx, CERT_SYSTEM_STORE_CURRENT_USER
  .endif
  invoke CertEnumSystemStore, ebx, NULL, hCombo, offset TestEnumStoreCallback
  invoke SetWindowText, hCombo, pCurrent
  ret
TestFillStoreCombo endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestAlgName
; Purpose:    Returns a display name for an ALG_ID. CryptFindOIDInfo has no name for several
;             algorithms SChannel uses (AES, SHA-2, ECDHE, ECDSA), so these are named here.
; Arguments:  Arg1: ALG_ID.
; Return:     xax -> WIDE name.

TestAlgName proc dAlg:DWORD
  mov eax, dAlg
  .if eax == 660Eh
    mov xax, $OfsCStrW("AES 128")
  .elseif eax == 660Fh
    mov xax, $OfsCStrW("AES 192")
  .elseif eax == 6610h
    mov xax, $OfsCStrW("AES 256")
  .elseif eax == 6611h
    mov xax, $OfsCStrW("AES")
  .elseif eax == 800Ch
    mov xax, $OfsCStrW("SHA-256")
  .elseif eax == 800Dh
    mov xax, $OfsCStrW("SHA-384")
  .elseif eax == 800Eh
    mov xax, $OfsCStrW("SHA-512")
  .elseif eax == 0AE06h
    mov xax, $OfsCStrW("ECDHE")
  .elseif eax == 0AA05h
    mov xax, $OfsCStrW("ECDH")
  .elseif eax == 0AA02h
    mov xax, $OfsCStrW("DHE")
  .elseif eax == 0A400h
    mov xax, $OfsCStrW("RSA")
  .elseif eax == 2203h
    mov xax, $OfsCStrW("ECDSA")
  .else
    ;Name from the OID info, if there is one
    invoke CryptFindOIDInfo, CRYPT_OID_INFO_ALGID_KEY, addr dAlg, 0
    .if xax != NULL
      mov xax, [xax].CRYPT_OID_INFO.pwszName
    .endif
    .if xax == NULL
      mov xax, $OfsCStrW("unnamed")
    .endif
  .endif
  ret
TestAlgName endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestFillAlgList
; Purpose:    Fills a list box with the algorithms SChannel supports on this host. The list is
;             queried from an anonymous outbound credential (QueryCredentialsAttributes with
;             SECPKG_ATTR_SUPPORTED_ALGS). Each item shows class, name and ALG_ID; the item data
;             is the ALG_ID. The ALG_IDs of the given list are selected.
; Arguments:  Arg1: List box HANDLE (LBS_EXTENDEDSEL).
;             Arg2: -> ALG_ID hex list to select (TestParseCipherList format).
; Return:     eax = Number of algorithms listed (0 = enumeration failed).

TestFillAlgList proc uses xbx xdi xsi, hList:HWND, pSelected:POINTER
  local Cred[2]:POINTER, qExpiry:QWORD, SchannelCred:SCHANNEL_CRED, Algs:SecPkgCred_SupportedAlgs
  local Selected[TT_MAX_CIPHERS]:DWORD, dSelCount:DWORD, dRemaining:DWORD, dCount:DWORD
  local dAlg:DWORD, dIndex:DWORD, pName:POINTER, pPrefix:POINTER, wText[160]:CHRW

  mov dCount, 0
  invoke SendMessage, hList, LB_RESETCONTENT, 0, 0
  invoke TestParseCipherList, pSelected, addr Selected, TT_MAX_CIPHERS
  .if SDWORD ptr eax < 0
    xor eax, eax
  .endif
  mov dSelCount, eax

  invoke MemZero, addr SchannelCred, sizeof SCHANNEL_CRED
  mov SchannelCred.dwVersion, SCHANNEL_CRED_VERSION
  mov SchannelCred.dwFlags, SCH_CRED_NO_DEFAULT_CREDS
  invoke AcquireCredentialsHandleA, NULL, $OfsCStrA("Microsoft Unified Security Protocol Provider"), \
                                    SECPKG_CRED_OUTBOUND, NULL, addr SchannelCred, NULL, NULL, \
                                    addr Cred, addr qExpiry
  .if eax != 0
    DbgHex eax, "TestFillAlgList - AcquireCredentialsHandle failed"
    xor eax, eax
    ret
  .endif

  invoke QueryCredentialsAttributesA, addr Cred, SECPKG_ATTR_SUPPORTED_ALGS, addr Algs
  .if eax == 0
    mov xsi, Algs.palgSupportedAlgs
    m2m dRemaining, Algs.cSupportedAlgs, eax
    .while dRemaining != 0
      m2m dAlg, DWORD ptr [xsi], eax

      invoke TestAlgName, dAlg
      mov pName, xax

      ;Algorithm class
      mov eax, dAlg
      and eax, 7 shl 13                                 ;GET_ALG_CLASS
      .if eax == ALG_CLASS_DATA_ENCRYPT
        mov xax, $OfsCStrW("Cipher")
      .elseif eax == ALG_CLASS_HASH
        mov xax, $OfsCStrW("Hash")
      .elseif eax == ALG_CLASS_KEY_EXCHANGE
        mov xax, $OfsCStrW("KeyEx")
      .elseif eax == ALG_CLASS_SIGNATURE
        mov xax, $OfsCStrW("Signature")
      .else
        mov xax, $OfsCStrW("Other")
      .endif
      mov pPrefix, xax

      invoke wsprintfW, addr wText, $OfsCStrW("%s: %s (%04X)"), pPrefix, pName, dAlg
      invoke SendMessageW, hList, LB_ADDSTRING, 0, addr wText
      .if SDWORD ptr eax >= 0
        mov dIndex, eax
        inc dCount
        invoke SendMessage, hList, LB_SETITEMDATA, dIndex, dAlg
        ;Select it if it is in the given list
        xor ebx, ebx
        .while ebx < dSelCount
          mov eax, Selected[xbx*sizeof(DWORD)]
          .if eax == dAlg
            invoke SendMessage, hList, LB_SETSEL, TRUE, dIndex
            .break
          .endif
          inc ebx
        .endw
      .endif
      add xsi, sizeof(DWORD)
      dec dRemaining
    .endw
    invoke FreeContextBuffer, Algs.palgSupportedAlgs
  .else
    DbgHex eax, "TestFillAlgList - QueryCredentialsAttributes failed"
  .endif

  invoke FreeCredentialsHandle, addr Cred
  mov eax, dCount
  ret
TestFillAlgList endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestGetAlgSelection
; Purpose:    Builds the ALG_ID hex list (e.g. "6610, 800C") from the selected list box items.
; Arguments:  Arg1: List box HANDLE.
;             Arg2: -> Destination buffer (TT_TEXT_LEN characters).
; Return:     eax = Number of selected items, -1 if more than TT_MAX_CIPHERS are selected.

TestGetAlgSelection proc uses xbx xdi xsi, hList:HWND, pDest:POINTER
  local Items[TT_MAX_CIPHERS]:DWORD, dCount:DWORD, dAlg:DWORD

  mov xdi, pDest
  mov CHR ptr [xdi], 0
  invoke SendMessage, hList, LB_GETSELCOUNT, 0, 0
  .if SDWORD ptr eax <= 0
    xor eax, eax
    ret
  .endif
  .if eax > TT_MAX_CIPHERS
    mov eax, -1
    ret
  .endif
  mov dCount, eax
  invoke SendMessage, hList, LB_GETSELITEMS, dCount, addr Items

  xor ebx, ebx
  .while ebx < dCount
    mov eax, Items[xbx*sizeof(DWORD)]
    invoke SendMessage, hList, LB_GETITEMDATA, eax, 0
    mov dAlg, eax
    .if ebx != 0
      invoke StrCopy, xdi, $OfsCStr(", ")
      add xdi, 2*sizeof(CHR)
    .endif
    invoke wsprintf, xdi, $OfsCStr("%X"), dAlg
    lea xdi, [xdi + xax*sizeof(CHR)]
    inc ebx
  .endw
  mov eax, dCount
  ret
TestGetAlgSelection endp

if IMPLEMENT

; --------------------------------------------------------------------------------------------------
; Method:     TestCertProv.Setup
; Purpose:    Configures the provider from the active settings. The search strings and blobs are
;             copied into the own TT_CERT_SEARCH structure (TLS_CertProvider stores only pointers).
; Arguments:  None.
; Return:     eax = TRUE if succeeded, FALSE if the search value is invalid.

Method TestCertProv.Setup, uses xbx xdi
  local dSearchType:DWORD

  SetObject xbx
  lea xdi, [xbx].Search

  ;Store scope and name
  .if TestSettings.dCertScope == TT_SCOPE_LOCAL_MACHINE
    OCall xbx.SetStoreScope, CERT_SYSTEM_STORE_LOCAL_MACHINE
  .else
    OCall xbx.SetStoreScope, CERT_SYSTEM_STORE_CURRENT_USER
  .endif
  invoke StrCCopy, addr [xdi].TT_CERT_SEARCH.cStore, offset TestSettings.cCertStore, TT_STORE_LEN - 1
  OCall xbx.SetStoreName, addr [xdi].TT_CERT_SEARCH.cStore

  ;Search criteria
  m2m dSearchType, TestSettings.dCertSearch, eax
  invoke StrCCopy, addr [xdi].TT_CERT_SEARCH.cValue, offset TestSettings.cCertValue, TT_TEXT_LEN - 1
  .if dSearchType == TLS_SEARCH_BY_THUMBPRINT || dSearchType == TLS_SEARCH_BY_SERIAL
    invoke TestParseHexBytes, addr [xdi].TT_CERT_SEARCH.cValue, \
                              addr [xdi].TT_CERT_SEARCH.bBytes, TT_MAX_CERT_BYTES
    .if SDWORD ptr eax <= 0
      xor eax, eax
      ExitMethod
    .endif
    mov [xdi].TT_CERT_SEARCH.Blob.cbData, eax
    lea xcx, [xdi].TT_CERT_SEARCH.bBytes
    mov [xdi].TT_CERT_SEARCH.Blob.pbData, xcx

    .if dSearchType == TLS_SEARCH_BY_SERIAL
      ;The serial number is displayed big-endian, but stored little-endian in CERT_INFO
      mov ecx, [xdi].TT_CERT_SEARCH.Blob.cbData
      lea xax, [xdi].TT_CERT_SEARCH.bBytes                ;xax -> first byte
      lea xdx, [xax + xcx - 1]                            ;xdx -> last byte
      .while xax < xdx
        mov cl, [xax]
        mov ch, [xdx]
        mov [xax], ch
        mov [xdx], cl
        inc xax
        dec xdx
      .endw
    .endif
    OCall xbx.SetSearchCriteria, dSearchType, addr [xdi].TT_CERT_SEARCH.Blob
  .else
    OCall xbx.SetSearchCriteria, TLS_SEARCH_BY_SUBJECT, addr [xdi].TT_CERT_SEARCH.cValue
  .endif
  mov eax, TRUE
MethodEnd

endif

; --------------------------------------------------------------------------------------------------
; Procedure:  TestNewTLSConfig
; Purpose:    Creates a new TLS_Connection_Config snapshot (and certificate provider) from the
;             active settings. Running connections keep using the previous snapshot, so the caller
;             must keep the old objects alive (see the protocol graveyards).
; Arguments:  Arg1: -> Owner object.
;             Arg2: -> POINTER that receives the certificate provider (or NULL).
;             Arg3: -> Target name (client: server address, used if no target name is set) or NULL.
; Return:     xax -> TLS_Connection_Config or NULL if failed.

TestNewTLSConfig proc uses xbx xdi xsi, pOwner:POINTER, ppProvider:POINTER, pTargetName:POINTER
  local dCount:DWORD, dMask:DWORD, bWithCert:DWORD, Ciphers[TT_MAX_CIPHERS]:DWORD

  mov xax, ppProvider
  mov POINTER ptr [xax], NULL

  New TLS_Connection_Config
  .if xax == NULL
    ret
  .endif
  mov xbx, xax
  OCall xbx::TLS_Connection_Config.Init, pOwner

  ;Protocol versions
  invoke TestProtocolMask, TestSettings.dProtocols
  mov dMask, eax
  OCall xbx::TLS_Connection_Config.SetAllowedProtocols, dMask

  ;Cipher suites (the config copies the array)
  invoke TestParseCipherList, offset TestSettings.cCiphers, addr Ciphers, TT_MAX_CIPHERS
  .if SDWORD ptr eax > 0
    mov dCount, eax
    OCall xbx::TLS_Connection_Config.SetCipherSuites, addr Ciphers, dCount
  .endif

if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
  ;Mutual authentication: request and require a client certificate
  OCall xbx::TLS_Connection_Config.SetMutualAuth, TestSettings.bMutualAuth
  mov bWithCert, TRUE                                   ;The server always needs its certificate
else
  ;Server name verification and SNI
  OCall xbx::TLS_Connection_Config.SetVerifyServerName, TestSettings.bVerifyName
  .if TestSettings.cTargetName != 0
    OCall xbx::TLS_Connection_Config.SetTargetName, offset TestSettings.cTargetName
  .elseif pTargetName != NULL
    mov xax, pTargetName
    .if CHR ptr [xax] != 0
      OCall xbx::TLS_Connection_Config.SetTargetName, pTargetName
    .endif
  .endif
  m2m bWithCert, TestSettings.bMutualAuth, eax          ;Client certificate only for mutual auth
endif

  ;Certificate provider of the own role
  .if bWithCert != FALSE
    New TestCertProv
    .if xax != NULL
      mov xdi, xax
      OCall xdi::TestCertProv.Init, pOwner
      OCall xdi::TestCertProv.Setup
      .if eax == FALSE
        DbgWarning "TestNewTLSConfig - invalid certificate search value"
      .endif
if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
      OCall xbx::TLS_Connection_Config.SetServerCertProvider, xdi
else
      OCall xbx::TLS_Connection_Config.SetClientCertProvider, xdi
endif
      mov xax, ppProvider
      mov [xax], xdi
    .endif
  .endif

  mov xax, xbx
  ret
TestNewTLSConfig endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestApplyNetCom
; Purpose:    Applies the NetCom limits and timeouts of the active settings. The supervisor reads
;             its timeouts every cycle and the protocol limit is read after every receive, so the
;             new values take effect immediately.
; Arguments:  Arg1: -> NetComSupervisor (the instance passed to NetComEngine.Init).
;             Arg2: -> NetComProtocol.
; Return:     Nothing.

;Helper macro: eax = TestSettings.Field (seconds) in 100ns units, clipped to TT_MAX_SECONDS
TT_SEC2TICKS macro Field:req
  mov eax, TestSettings.Field
  .if eax > TT_MAX_SECONDS
    mov eax, TT_MAX_SECONDS
  .endif
  imul eax, eax, 10000000                               ;Seconds => 100ns units
endm

TestApplyNetCom proc uses xbx xdi, pSupervisor:POINTER, pProtocol:POINTER
  mov xbx, pSupervisor
  mov xdi, pProtocol

  TT_SEC2TICKS dInactivitySec
  mov [xbx].$Obj(NetComSupervisor).dInactivityTimeout, eax
  TT_SEC2TICKS dHandshakeSec
  mov [xbx].$Obj(NetComSupervisor).dHandshakeTimeout, eax
  TT_SEC2TICKS dShutdownSec
  mov [xbx].$Obj(NetComSupervisor).dTLSShutdownTimeout, eax
  TT_SEC2TICKS dPauseSec
  mov [xbx].$Obj(NetComSupervisor).dRcvPauseTimeout, eax

  mov eax, TestSettings.dRcvLimitKB
  .if eax > TT_MAX_LIMIT_KB
    mov eax, TT_MAX_LIMIT_KB
  .endif
  shl eax, 10                                           ;KB => BYTEs
  mov [xdi].$Obj(NetComProtocol).dMaxRcvBuffered, eax
  ret
TestApplyNetCom endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestGetChain
; Purpose:    Returns the chain that holds the received application data.
; Arguments:  Arg1: -> NetComConnection.
; Return:     xax -> SDLL_SENTINEL (PlaintextChain for TLS, RcvIOJobChain otherwise).
;             ecx = TRUE if only completed IOJobs contain data (RcvIOJobChain).

TestGetChain proc pConnection:POINTER
  mov xdx, pConnection
  .if [xdx].$Obj(NetComConnection).pTLSContext != NULL
    lea xax, [xdx].$Obj(NetComConnection).PlaintextChain
    xor ecx, ecx
  .else
    lea xax, [xdx].$Obj(NetComConnection).RcvIOJobChain
    mov ecx, TRUE
  .endif
  ret
TestGetChain endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestFindDelimiter
; Purpose:    Scans the received data for ZTC message delimiters.
; Arguments:  Arg1: -> NetComConnection.
; Return:     eax = Number of BYTEs up to and including the last delimiter (0 = none).

TestFindDelimiter proc uses xbx xdi xsi, pConnection:POINTER
  local pSentinel:POINTER, bCompletedOnly:DWORD, dLast:DWORD

  invoke TestGetChain, pConnection
  mov pSentinel, xax
  mov bCompletedOnly, ecx
  mov dLast, 0
  xor edx, edx                                          ;edx = BYTE position
  mov xbx, [xax].SDLL_SENTINEL.pFirstItem
  .while xbx != pSentinel
    lea xsi, [xbx - IOJOB_HEADER_SIZE]                  ;xsi -> IOJOB
    .if bCompletedOnly != FALSE
      test [xsi].IOJOB.wFlags, IOF_JOB_COMPLETED
      .break .if ZERO?                                  ;Receive still pending
    .endif
    mov xdi, [xsi].IOJOB.WSABuf.buf
    mov ecx, [xsi].IOJOB.dBytesConsumed
    .while ecx != 0
      inc edx
      .if BYTE ptr [xdi] == 0
        mov dLast, edx
      .endif
      inc xdi
      dec ecx
    .endw
    mov xbx, [xbx].SDLL_ITEM.pNextItem
  .endw
  mov eax, dLast
  ret
TestFindDelimiter endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestCopyData
; Purpose:    Copies the first received BYTEs into a buffer and counts the delimiters.
; Arguments:  Arg1: -> NetComConnection.
;             Arg2: -> Destination buffer (NULL = count only).
;             Arg3: Number of BYTEs.
; Return:     eax = Number of ZTC delimiters (messages) in the copied BYTEs.

TestCopyData proc uses xbx xdi xsi, pConnection:POINTER, pDest:POINTER, dSize:DWORD
  local pSentinel:POINTER, dMessages:DWORD

  invoke TestGetChain, pConnection
  mov pSentinel, xax
  mov dMessages, 0
  mov xdi, pDest
  mov xbx, [xax].SDLL_SENTINEL.pFirstItem
  .while xbx != pSentinel && dSize != 0
    lea xdx, [xbx - IOJOB_HEADER_SIZE]                  ;xdx -> IOJOB
    mov xsi, [xdx].IOJOB.WSABuf.buf
    mov ecx, [xdx].IOJOB.dBytesConsumed
    .while ecx != 0 && dSize != 0
      mov al, [xsi]
      .if al == 0
        inc dMessages
      .endif
      .if xdi != NULL
        mov [xdi], al
        inc xdi
      .endif
      inc xsi
      dec ecx
      dec dSize
    .endw
    mov xbx, [xbx].SDLL_ITEM.pNextItem
  .endw
  mov eax, dMessages
  ret
TestCopyData endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestConnectionsAction
; Purpose:    Applies a test action to all established connections of an engine.
;             Pending acceptors, closed and destroyed connections are skipped. A connection that is
;             busy (CritSect owned by a worker thread) is skipped as well, so the UI thread never
;             blocks while it holds the connection pool lock.
; Arguments:  Arg1: -> NetComEngine.
;             Arg2: Action (TTA_xxx).
; Return:     eax = Number of connections the action was applied to.

TestConnectionsAction proc uses xbx xdi xsi, pEngine:POINTER, dAction:DWORD
  local dCount:DWORD, pConn:POINTER

  mov dCount, 0
  mov xsi, pEngine
  invoke EnterCriticalSection, addr [xsi].$Obj(NetComEngine).ConnectionPool.CritSect
  lea xdi, [xsi].$Obj(NetComEngine).ConnectionChain
  mov xbx, [xdi].SDLL_SENTINEL.pFirstItem
  .while xbx != xdi
    lea xcx, [xbx - offset $Obj(NetComConnection).ChainItem]
    mov pConn, xcx
    mov xbx, [xbx].SDLL_ITEM.pNextItem

    ;Skip pending acceptors and connections that are going away
    mov eax, [xcx].$Obj(NetComConnection).dFlags
    mov edx, eax
    and edx, NCC_QUEUE_ACCEPT or NCC_ACCEPTED
    .continue .if edx == NCC_QUEUE_ACCEPT
    test eax, NCC_CLOSED or NCC_QUEUE_DESTROY
    .continue .if !ZERO?

    .if dAction == TTA_COUNT_PAUSED
      test eax, NCC_RCV_PAUSED
      .if !ZERO?
        inc dCount
      .endif
      .continue
    .endif

    .if dAction == TTA_TRICKLE
      ;Only established raw (non-TLS) connections
      test eax, NCC_CONNECTED
      .continue .if ZERO?
      .continue .if [xcx].$Obj(NetComConnection).pTLSContext != NULL
    .endif

    .continue .if [xcx].$Obj(NetComConnection).pCritSect == NULL    ;Init not done yet
    invoke TryEnterCriticalSection, [xcx].$Obj(NetComConnection).pCritSect
    .continue .if eax == FALSE

    .if dAction == TTA_PAUSE
      OCall pConn::NetComConnection.PauseReceive
    .elseif dAction == TTA_RESUME
      OCall pConn::NetComConnection.ResumeReceive
    .elseif dAction == TTA_DISCONNECT
      OCall pConn::NetComConnection.Disconnect, SD_SEND
    .elseif dAction == TTA_ABORT
      OCall pConn::NetComConnection.QueueDestroy
      OCall pConn::NetComConnection.Close, TRUE
    .elseif dAction == TTA_TRICKLE
      OCall pConn::NetComConnection.QueueSend, offset bTT_Zero, 1
    .endif
    inc dCount

    mov xcx, pConn
    invoke LeaveCriticalSection, [xcx].$Obj(NetComConnection).pCritSect
  .endw
  invoke LeaveCriticalSection, addr [xsi].$Obj(NetComEngine).ConnectionPool.CritSect
  mov eax, dCount
  ret
TestConnectionsAction endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestStatsError
; Purpose:    Records an error in the statistics (called from worker threads).
; Arguments:  Arg1: Error code.
; Return:     Nothing.

TestStatsError proc dError:DWORD
  lock inc TestStats.dErrors
  m2m TestStats.dLastError, dError, eax
  ret
TestStatsError endp

; --------------------------------------------------------------------------------------------------
; Procedure:  TestPrintStats
; Purpose:    Prints the common statistics lines into a window DC.
; Arguments:  Arg1: Device context.
;             Arg2: X position.
;             Arg3: Y position of the first line.
;             Arg4: Number of paused connections.
; Return:     eax = Y position after the last line.

TestPrintStats proc uses xbx xdi, hDC:HDC, dXPos:DWORD, dYPos:DWORD, dPaused:DWORD
  local cBuffer[256]:CHR

  lea xdi, cBuffer
  mov ebx, dYPos

  invoke wsprintf, xdi, $OfsCStr("#Handshakes ok = %lu, failed = %lu          "), \
                   TestStats.dHandshakeOK, TestStats.dHandshakeFailed
  invoke StrLength, xdi
  invoke TextOut, hDC, dXPos, ebx, xdi, eax
  add ebx, 20

  invoke wsprintf, xdi, $OfsCStr("#Errors = %lu, last = %lu (0x%08X)          "), \
                   TestStats.dErrors, TestStats.dLastError, TestStats.dLastError
  invoke StrLength, xdi
  invoke TextOut, hDC, dXPos, ebx, xdi, eax
  add ebx, 20

  invoke wsprintf, xdi, $OfsCStr("#Messages = %lu, echo dropped = %lu          "), \
                   TestStats.dMessages, TestStats.dEchoDropped
  invoke StrLength, xdi
  invoke TextOut, hDC, dXPos, ebx, xdi, eax
  add ebx, 20

  invoke wsprintf, xdi, $OfsCStr("#Paused connections = %lu          "), dPaused
  invoke StrLength, xdi
  invoke TextOut, hDC, dXPos, ebx, xdi, eax
  add ebx, 20

  mov eax, ebx
  ret
TestPrintStats endp
