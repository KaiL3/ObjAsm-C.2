; ==================================================================================================
; Title:      TLS_TestSettingsDlg.inc
; Author:     Kai Liebenau
; Version:    1.1.0
; Purpose:    Settings dialog of the NetCom TLS test server and client.
; Notes:      Requires TLS_TestCommon.inc. The resource is TLS_TestSettingsDlg.rc (same IDs).
;             The dialog edits a working copy; TestSettings is only changed on OK.
;             Version 1.1.0, November 2026
;               - Initial release.
; ==================================================================================================


IDD_DLG_SETTINGS        equ   4000

IDC_SET_GRP_TLS         equ   4001
IDC_SET_CHK_TLS10       equ   4002
IDC_SET_CHK_TLS11       equ   4003
IDC_SET_CHK_TLS12       equ   4004
IDC_SET_CHK_TLS13       equ   4005
IDC_SET_CHK_MUTUAL      equ   4006
IDC_SET_CHK_VERIFY      equ   4007
IDC_SET_STC_TARGET      equ   4008
IDC_SET_EDT_TARGET      equ   4009

IDC_SET_GRP_ALGS        equ   4012
IDC_SET_LST_ALGS        equ   4013
IDC_SET_BTN_ALGCLEAR    equ   4014
IDC_SET_STC_ALGINFO     equ   4015

IDC_SET_GRP_CERT        equ   4020
IDC_SET_STC_SEARCH      equ   4021
IDC_SET_CBO_SEARCH      equ   4022
IDC_SET_STC_VALUE       equ   4023
IDC_SET_EDT_VALUE       equ   4024
IDC_SET_STC_SCOPE       equ   4025
IDC_SET_CBO_SCOPE       equ   4026
IDC_SET_STC_STORE       equ   4027
IDC_SET_CBO_STORE       equ   4028

IDC_SET_GRP_NET         equ   4040
IDC_SET_STC_PORT        equ   4041
IDC_SET_EDT_PORT        equ   4042
IDC_SET_STC_INACT       equ   4043
IDC_SET_EDT_INACT       equ   4044
IDC_SET_STC_HSHAKE      equ   4045
IDC_SET_EDT_HSHAKE      equ   4046
IDC_SET_STC_SHUTDN      equ   4047
IDC_SET_EDT_SHUTDN      equ   4048
IDC_SET_STC_PAUSE       equ   4049
IDC_SET_EDT_PAUSE       equ   4050
IDC_SET_STC_LIMIT       equ   4051
IDC_SET_EDT_LIMIT       equ   4052

IDC_SET_GRP_TEST        equ   4060
IDC_SET_CHK_ECHO        equ   4061
IDC_SET_STC_TRICKLE     equ   4062
IDC_SET_EDT_TRICKLE     equ   4063

IDC_SET_BTN_DEFAULTS    equ   4070
IDC_SET_STC_INFO        equ   4071


; --------------------------------------------------------------------------------------------------
; Object:     TestSettingsDlg
; Purpose:    Modal dialog to edit the TLS test settings.

Object TestSettingsDlg,, DialogModal
  RedefineMethod    CtlsGet
  RedefineMethod    CtlsSet
  RedefineMethod    Init,           POINTER, HWND
  RedefineMethod    OnCommand,      WPARAM, LPARAM
  StaticMethod      ShowRole
  StaticMethod      RefillStores

  DefineVariable    bAccepted,      DWORD,              FALSE   ;TRUE if closed with OK
  DefineVariable    Work,           TLS_TEST_SETTINGS,  {}      ;Working copy
  DefineVariable    bAlgsListed,    DWORD,              FALSE   ;TRUE if the host algorithms are listed
ObjectEnd


if IMPLEMENT

; --------------------------------------------------------------------------------------------------
; Method:     TestSettingsDlg.Init
; Purpose:    Initializes the dialog with a working copy of the active settings.
; Arguments:  Arg1: -> Owner.
;             Arg2: Parent window HANDLE.
; Return:     Nothing.

Method TestSettingsDlg.Init, uses xsi, pOwner:POINTER, hParent:HWND
  SetObject xsi
  ACall xsi.Init, pOwner, hParent, IDD_DLG_SETTINGS
  mov [xsi].bAccepted, FALSE
  invoke MemClone, addr [xsi].Work, offset TestSettings, sizeof TLS_TEST_SETTINGS
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TestSettingsDlg.ShowRole
; Purpose:    Hides the controls that do not apply to the current role and sets role specific
;             captions.
; Arguments:  None.
; Return:     Nothing.

Method TestSettingsDlg.ShowRole, uses xbx xsi
  SetObject xsi

  TT_HIDE macro CtlID:req
    invoke GetDlgItem, [xsi].hWnd, CtlID
    invoke ShowWindow, xax, SW_HIDE
  endm

if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
  invoke SetWindowText, [xsi].hWnd, $OfsCStr("Server Settings")
  invoke SetDlgItemText, [xsi].hWnd, IDC_SET_CHK_MUTUAL, $OfsCStr("&Require client certificate")
  invoke SetDlgItemText, [xsi].hWnd, IDC_SET_GRP_CERT, $OfsCStr("Server certificate")
  TT_HIDE IDC_SET_CHK_VERIFY
  TT_HIDE IDC_SET_STC_TARGET
  TT_HIDE IDC_SET_EDT_TARGET
  TT_HIDE IDC_SET_STC_TRICKLE
  TT_HIDE IDC_SET_EDT_TRICKLE
else
  invoke SetWindowText, [xsi].hWnd, $OfsCStr("Client Settings")
  invoke SetDlgItemText, [xsi].hWnd, IDC_SET_CHK_MUTUAL, $OfsCStr("Send client certificate if &requested")
  invoke SetDlgItemText, [xsi].hWnd, IDC_SET_GRP_CERT, $OfsCStr("Client certificate")
  TT_HIDE IDC_SET_STC_PORT
  TT_HIDE IDC_SET_EDT_PORT
  TT_HIDE IDC_SET_CHK_ECHO
endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TestSettingsDlg.RefillStores
; Purpose:    Lists the system stores of the scope selected in the dialog and keeps the store name
;             currently entered.
; Arguments:  None.
; Return:     Nothing.

Method TestSettingsDlg.RefillStores, uses xbx xsi
  local cStore[TT_STORE_LEN]:CHR

  SetObject xsi
  invoke GetDlgItemText, [xsi].hWnd, IDC_SET_CBO_STORE, addr cStore, TT_STORE_LEN
  invoke SendDlgItemMessage, [xsi].hWnd, IDC_SET_CBO_SCOPE, CB_GETCURSEL, 0, 0
  mov ebx, eax
  invoke GetDlgItem, [xsi].hWnd, IDC_SET_CBO_STORE
  invoke TestFillStoreCombo, xax, ebx, addr cStore
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TestSettingsDlg.CtlsSet
; Purpose:    Transfers the working copy into the dialog controls.
; Arguments:  None.
; Return:     Nothing.

Method TestSettingsDlg.CtlsSet, uses xbx xdi xsi
  SetObject xsi
  lea xdi, [xsi].Work

  OCall xsi.ShowRole

  TT_CHECK macro CtlID:req, Value:req
    invoke CheckDlgButton, [xsi].hWnd, CtlID, Value
  endm

  TT_CHECK_BIT macro CtlID:req, Bit:req
    xor eax, eax
    test [xdi].TLS_TEST_SETTINGS.dProtocols, Bit
    setnz al
    invoke CheckDlgButton, [xsi].hWnd, CtlID, eax
  endm

  TT_CHECK_BIT IDC_SET_CHK_TLS10, TTP_TLS10
  TT_CHECK_BIT IDC_SET_CHK_TLS11, TTP_TLS11
  TT_CHECK_BIT IDC_SET_CHK_TLS12, TTP_TLS12
  TT_CHECK_BIT IDC_SET_CHK_TLS13, TTP_TLS13
  TT_CHECK IDC_SET_CHK_MUTUAL, [xdi].TLS_TEST_SETTINGS.bMutualAuth
  TT_CHECK IDC_SET_CHK_VERIFY, [xdi].TLS_TEST_SETTINGS.bVerifyName
  TT_CHECK IDC_SET_CHK_ECHO,   [xdi].TLS_TEST_SETTINGS.bEcho

  invoke SetDlgItemText, [xsi].hWnd, IDC_SET_EDT_TARGET,  addr [xdi].TLS_TEST_SETTINGS.cTargetName
  invoke SetDlgItemText, [xsi].hWnd, IDC_SET_EDT_VALUE,   addr [xdi].TLS_TEST_SETTINGS.cCertValue

  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_PORT,    [xdi].TLS_TEST_SETTINGS.dPort, FALSE
  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_INACT,   [xdi].TLS_TEST_SETTINGS.dInactivitySec, FALSE
  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_HSHAKE,  [xdi].TLS_TEST_SETTINGS.dHandshakeSec, FALSE
  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_SHUTDN,  [xdi].TLS_TEST_SETTINGS.dShutdownSec, FALSE
  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_PAUSE,   [xdi].TLS_TEST_SETTINGS.dPauseSec, FALSE
  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_LIMIT,   [xdi].TLS_TEST_SETTINGS.dRcvLimitKB, FALSE
  invoke SetDlgItemInt, [xsi].hWnd, IDC_SET_EDT_TRICKLE, [xdi].TLS_TEST_SETTINGS.dTrickleSec, FALSE

  ;Search type combo: item index = TLS_SEARCH_BY_xxx - 1 (SUBJECT = 1, SERIAL = 2, THUMBPRINT = 3)
  mov xbx, $invoke(GetDlgItem, [xsi].hWnd, IDC_SET_CBO_SEARCH)
  invoke SendMessage, xbx, CB_RESETCONTENT, 0, 0
  invoke SendMessage, xbx, CB_ADDSTRING, 0, $OfsCStr("Subject (substring)")
  invoke SendMessage, xbx, CB_ADDSTRING, 0, $OfsCStr("Serial number (hex)")
  invoke SendMessage, xbx, CB_ADDSTRING, 0, $OfsCStr("Thumbprint SHA-1 (hex)")
  mov eax, [xdi].TLS_TEST_SETTINGS.dCertSearch
  .if eax < TLS_SEARCH_BY_SUBJECT || eax > TLS_SEARCH_BY_THUMBPRINT
    mov eax, TLS_SEARCH_BY_SUBJECT
  .endif
  dec eax
  invoke SendMessage, xbx, CB_SETCURSEL, eax, 0

  ;Store scope combo: item index = TT_SCOPE_xxx
  mov xbx, $invoke(GetDlgItem, [xsi].hWnd, IDC_SET_CBO_SCOPE)
  invoke SendMessage, xbx, CB_RESETCONTENT, 0, 0
  invoke SendMessage, xbx, CB_ADDSTRING, 0, $OfsCStr("Current user")
  invoke SendMessage, xbx, CB_ADDSTRING, 0, $OfsCStr("Local machine")
  mov eax, [xdi].TLS_TEST_SETTINGS.dCertScope
  .if eax > TT_SCOPE_LOCAL_MACHINE
    mov eax, TT_SCOPE_CURRENT_USER
  .endif
  invoke SendMessage, xbx, CB_SETCURSEL, eax, 0

  ;System stores of the selected scope (the edit field keeps a custom name)
  invoke GetDlgItem, [xsi].hWnd, IDC_SET_CBO_STORE
  invoke TestFillStoreCombo, xax, [xdi].TLS_TEST_SETTINGS.dCertScope, \
                             addr [xdi].TLS_TEST_SETTINGS.cCertStore

  ;Algorithms offered by SChannel on this host, the configured ones are selected
  invoke GetDlgItem, [xsi].hWnd, IDC_SET_LST_ALGS
  invoke TestFillAlgList, xax, addr [xdi].TLS_TEST_SETTINGS.cCiphers
  mov [xsi].bAlgsListed, eax
  .if eax == 0
    invoke SetDlgItemText, [xsi].hWnd, IDC_SET_STC_ALGINFO, \
           $OfsCStr("The algorithm list is not available. The stored list is kept unchanged.")
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TestSettingsDlg.CtlsGet
; Purpose:    Reads and validates the dialog controls into the working copy.
; Arguments:  None.
; Return:     eax = TRUE if all values are valid, otherwise FALSE (a message was shown).

Method TestSettingsDlg.CtlsGet, uses xbx xdi xsi
  local dValue:DWORD, bOk:DWORD, Bytes[TT_MAX_CERT_BYTES]:BYTE

  SetObject xsi
  lea xdi, [xsi].Work

  ;Protocols
  xor ebx, ebx
  .if $32($invoke(IsDlgButtonChecked, [xsi].hWnd, IDC_SET_CHK_TLS10)) == BST_CHECKED
    or ebx, TTP_TLS10
  .endif
  .if $32($invoke(IsDlgButtonChecked, [xsi].hWnd, IDC_SET_CHK_TLS11)) == BST_CHECKED
    or ebx, TTP_TLS11
  .endif
  .if $32($invoke(IsDlgButtonChecked, [xsi].hWnd, IDC_SET_CHK_TLS12)) == BST_CHECKED
    or ebx, TTP_TLS12
  .endif
  .if $32($invoke(IsDlgButtonChecked, [xsi].hWnd, IDC_SET_CHK_TLS13)) == BST_CHECKED
    or ebx, TTP_TLS13
  .endif
  .if ebx == 0
    invoke MessageBox, [xsi].hWnd, $OfsCStr("Select at least one TLS version."), \
                       $OfsCStr("Settings"), MB_OK or MB_ICONERROR
    xor eax, eax
    ExitMethod
  .endif
  mov [xdi].TLS_TEST_SETTINGS.dProtocols, ebx

  ;Check boxes
  TT_GETCHECK macro CtlID:req, Field:req
    invoke IsDlgButtonChecked, [xsi].hWnd, CtlID
    xor ecx, ecx
    .if eax == BST_CHECKED
      inc ecx
    .endif
    mov [xdi].TLS_TEST_SETTINGS.Field, ecx
  endm

  TT_GETCHECK IDC_SET_CHK_MUTUAL, bMutualAuth
  TT_GETCHECK IDC_SET_CHK_VERIFY, bVerifyName
  TT_GETCHECK IDC_SET_CHK_ECHO,   bEcho

  ;Texts
  invoke GetDlgItemText, [xsi].hWnd, IDC_SET_EDT_TARGET,  addr [xdi].TLS_TEST_SETTINGS.cTargetName, TT_TEXT_LEN
  invoke StrLRTrim, addr [xdi].TLS_TEST_SETTINGS.cTargetName, addr [xdi].TLS_TEST_SETTINGS.cTargetName
  invoke GetDlgItemText, [xsi].hWnd, IDC_SET_EDT_VALUE,   addr [xdi].TLS_TEST_SETTINGS.cCertValue, TT_TEXT_LEN
  invoke StrLRTrim, addr [xdi].TLS_TEST_SETTINGS.cCertValue, addr [xdi].TLS_TEST_SETTINGS.cCertValue
  invoke GetDlgItemText, [xsi].hWnd, IDC_SET_CBO_STORE,   addr [xdi].TLS_TEST_SETTINGS.cCertStore, TT_STORE_LEN
  invoke StrLRTrim, addr [xdi].TLS_TEST_SETTINGS.cCertStore, addr [xdi].TLS_TEST_SETTINGS.cCertStore
  .if [xdi].TLS_TEST_SETTINGS.cCertStore == 0
    invoke StrCopy, addr [xdi].TLS_TEST_SETTINGS.cCertStore, $OfsCStr("MY")
  .endif

  ;Algorithms: hex list of the selected ALG_IDs (kept unchanged if the list is not available)
  .if [xsi].bAlgsListed != FALSE
    invoke GetDlgItem, [xsi].hWnd, IDC_SET_LST_ALGS
    invoke TestGetAlgSelection, xax, addr [xdi].TLS_TEST_SETTINGS.cCiphers
    .if SDWORD ptr eax < 0
      invoke MessageBox, [xsi].hWnd, $OfsCStr("Select at most 32 algorithms."), \
                         $OfsCStr("Settings"), MB_OK or MB_ICONERROR
      xor eax, eax
      ExitMethod
    .endif
  .endif

  ;Combos
  invoke SendDlgItemMessage, [xsi].hWnd, IDC_SET_CBO_SEARCH, CB_GETCURSEL, 0, 0
  .if SDWORD ptr eax < 0
    xor eax, eax
  .endif
  inc eax
  mov [xdi].TLS_TEST_SETTINGS.dCertSearch, eax
  invoke SendDlgItemMessage, [xsi].hWnd, IDC_SET_CBO_SCOPE, CB_GETCURSEL, 0, 0
  .if eax != TT_SCOPE_LOCAL_MACHINE
    mov eax, TT_SCOPE_CURRENT_USER
  .endif
  mov [xdi].TLS_TEST_SETTINGS.dCertScope, eax

  .if [xdi].TLS_TEST_SETTINGS.dCertSearch != TLS_SEARCH_BY_SUBJECT
    invoke TestParseHexBytes, addr [xdi].TLS_TEST_SETTINGS.cCertValue, addr Bytes, TT_MAX_CERT_BYTES
    .if SDWORD ptr eax <= 0
      invoke MessageBox, [xsi].hWnd, \
             $OfsCStr("Invalid certificate value. Serial number and thumbprint must be hex bytes."), \
             $OfsCStr("Settings"), MB_OK or MB_ICONERROR
      xor eax, eax
      ExitMethod
    .endif
  .endif

  ;Numbers
  TT_GETNUM macro CtlID:req, Field:req, MaxValue:req, Text:req
    invoke GetDlgItemInt, [xsi].hWnd, CtlID, addr bOk, FALSE
    .if bOk == FALSE || eax > MaxValue
      invoke MessageBox, [xsi].hWnd, $OfsCStr(Text), $OfsCStr("Settings"), MB_OK or MB_ICONERROR
      xor eax, eax
      ExitMethod
    .endif
    mov [xdi].TLS_TEST_SETTINGS.Field, eax
  endm

if TLS_TEST_ROLE eq TLS_TEST_ROLE_SERVER
  TT_GETNUM IDC_SET_EDT_PORT,    dPort,          65535,           "Invalid port (1..65535)."
  .if [xdi].TLS_TEST_SETTINGS.dPort == 0
    invoke MessageBox, [xsi].hWnd, $OfsCStr("Invalid port (1..65535)."), \
                       $OfsCStr("Settings"), MB_OK or MB_ICONERROR
    xor eax, eax
    ExitMethod
  .endif
else
  TT_GETNUM IDC_SET_EDT_TRICKLE, dTrickleSec,    3600,            "Invalid trickle interval (0..3600 s)."
endif
  TT_GETNUM IDC_SET_EDT_INACT,   dInactivitySec, TT_MAX_SECONDS,  "Invalid inactivity timeout (0..429 s)."
  TT_GETNUM IDC_SET_EDT_HSHAKE,  dHandshakeSec,  TT_MAX_SECONDS,  "Invalid handshake timeout (0..429 s)."
  TT_GETNUM IDC_SET_EDT_SHUTDN,  dShutdownSec,   TT_MAX_SECONDS,  "Invalid TLS shutdown timeout (0..429 s)."
  TT_GETNUM IDC_SET_EDT_PAUSE,   dPauseSec,      TT_MAX_SECONDS,  "Invalid receive pause timeout (0..429 s)."
  TT_GETNUM IDC_SET_EDT_LIMIT,   dRcvLimitKB,    TT_MAX_LIMIT_KB, "Invalid receive limit (0..4194303 KB)."

  mov eax, TRUE
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TestSettingsDlg.OnCommand
; Purpose:    Event procedure for WM_COMMAND message.
; Arguments:  Arg1: First message parameter.
;             Arg2: Second message parameter.
; Return:     eax = Zero if handled.

Method TestSettingsDlg.OnCommand, uses xsi, wParam:WPARAM, lParam:LPARAM
  SetObject xsi
  mov xax, wParam
  .if ax == IDOK
    OCall xsi.CtlsGet
    .if eax != FALSE
      invoke MemClone, offset TestSettings, addr [xsi].Work, sizeof TLS_TEST_SETTINGS
      mov [xsi].bAccepted, TRUE
      OCall xsi.DestroyDialog, wParam
    .endif
    xor eax, eax
  .elseif ax == IDCANCEL
    OCall xsi.DestroyDialog, wParam
    xor eax, eax
  .elseif ax == IDC_SET_BTN_ALGCLEAR
    invoke SendDlgItemMessage, [xsi].hWnd, IDC_SET_LST_ALGS, LB_SETSEL, FALSE, -1
    xor eax, eax
  .elseif ax == IDC_SET_CBO_SCOPE
    ;Scope changed => list the stores of the new scope, keep the entered store name
    mov xax, wParam
    shr eax, 16
    .if eax == CBN_SELCHANGE
      OCall xsi.RefillStores
    .endif
    xor eax, eax
  .elseif ax == IDC_SET_BTN_DEFAULTS
    invoke TestSettingsDefault, addr [xsi].Work
    OCall xsi.CtlsSet
    xor eax, eax
  .else
    xor eax, eax
    inc eax
  .endif
MethodEnd

endif
