; ==================================================================================================
; Title:      NetComTLSClient_Main.inc
; Author:     Kai Liebenau
; Version:    See NetComTLSClient.asm
; Purpose:    NetCom TLS Client Application.
; ==================================================================================================


CLSSTYLE equ CS_BYTEALIGNWINDOW or CS_BYTEALIGNCLIENT or CS_VREDRAW or CS_HREDRAW

CStr szNetComTLSClient, "OAC_NetComTLSClient"           ;Creates szNetComTLSClient string in .const

BUFFERSIZE  equ   2048

DEFAULT_SERVER_LISTENING_PORT equ $htons(25774)

SDF_ERROR         equ  BIT00
SDF_CTRLS_ENABLED equ  BIT01

;Custom message for thread-safe UI update from worker thread
WM_NETCOM_ENABLE_CTRLS  equ  WM_APP + 1   ;wParam = TRUE/FALSE

; --------------------------------------------------------------------------------------------------
; Object:     SendDlg
; Purpose:    Modal dialog for controlling outbound TLS connections and message transmission.

Object SendDlg,, DialogModal
  VirtualMethod     CtlsEnable,     DWORD
  RedefineMethod    CtlsGet
  RedefineMethod    CtlsSet
  RedefineMethod    Done
  RedefineMethod    Init,           POINTER, HWND
  RedefineMethod    OnInitDialog,   WPARAM, LPARAM
  RedefineMethod    OnCommand,      WPARAM, LPARAM
  VirtualEvent      OnNetComEnableCtrls, WM_NETCOM_ENABLE_CTRLS
  VirtualMethod     UpdateDataGrp

  DefineVariable    dFlags,         DWORD,      SDF_CTRLS_ENABLED
  DefineVariable    dComboIndex,    DWORD,      0
  DefineVariable    dConnections,   DWORD,      1
  DefineVariable    dRepetitions,   DWORD,      1
  DefineVariable    cText,          CHRA,       BUFFERSIZE dup(0)
  DefineVariable    cHostName,      CHRA,       256 dup(0)  ;Server hostname for TLS SNI
  DefineVariable    bNoDelimiter,   DWORD,      FALSE       ;Send without ZTC (limit test)
  DefineVariable    bTrickle,       DWORD,      FALSE       ;Raw TCP handshake trickle
ObjectEnd

; --------------------------------------------------------------------------------------------------
; Object:     NetComTLSClient
; Purpose:    Main TLS client application object implementing a Windows SDI client.

Object NetComTLSClient, ApplicationID, SdiApp
  RedefineMethod    Done
  RedefineMethod    Init
  StaticMethod      Startup

  VirtualEvent      OnCommand,  WM_COMMAND
  VirtualEvent      OnTimer,    WM_TIMER

  Embed  Client,    NetComEngine
  Embed  SndDlg,    SendDlg

  DefineVariable    dTrickleTicks,  DWORD,      0           ;Timer ticks since the last trickle
ObjectEnd


include NetComTLSClient_Protocol.inc


.code

if IMPLEMENT

TimerID equ 5361785

.const

; Default payload text
bPayload db "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod ",
            "tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At ",
            "vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, ",
            "no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit ",
            "amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut ",
            "labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam ",
            "et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata ",
            "sanctus est Lorem ipsum dolor sit amet."
.code

; ==================================================================================================
;    NetComTLSClient implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClient.Done

Method NetComTLSClient.Done, uses xsi
  SetObject xsi
  invoke KillTimer, [xsi].hWnd, TimerID
  OCall [xsi].Client::NetComEngine.Done
  ;Free the TLS config snapshots after all connections are gone
  OCall $ObjTmpl(NetComTLSClientProtocol)::NetComTLSClientProtocol.Done
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClient.Init

Method NetComTLSClient.Init, uses xsi
  local dWndPosX:DWORD, dWndPosY:DWORD, dWndWidth:DWORD, dWndHeight:DWORD
  local cCaption[512]:CHR, cAddrStr[100]:CHR, dLength:DWORD

  SetObject xsi
  ACall xsi.Init

  ;Load the settings (defaults + INI file next to the executable)
  invoke TestIniInit
  invoke TestSettingsLoad

  mov dWndWidth, 550
  mov dWndHeight, 470
  mov dWndPosX, $32($invoke(CenterForm, dWndWidth, $32($invoke(GetSystemMetrics, SM_CXSCREEN))))
  sub dWndPosX, 450
  mov dWndPosY, $32($invoke(CenterForm, dWndHeight, $32($invoke(GetSystemMetrics, SM_CYSCREEN))))

  invoke CreateWindowEx, WS_EX_LEFT or WS_EX_APPWINDOW, \
                         offset szNetComTLSClient, offset szAppTitle, WS_OVERLAPPEDWINDOW, \
                         dWndPosX, dWndPosY, dWndWidth, dWndHeight, NULL, NULL, hInstance, xsi

  invoke ShowWindow, [xsi].hWnd, SW_SHOWNORMAL
  invoke UpdateWindow, [xsi].hWnd

  OCall [xsi].Client::NetComEngine.Init, xsi, offset $ObjTmpl(NetComSupervisor), \
                                              5, 5, TT_IOJOB_BUFFER_SIZE
  OCall $ObjTmpl(NetComTLSClientProtocol)::NetComTLSClientProtocol.Init, xsi
  ;Timeouts and receive limit from the settings
  invoke TestApplyNetCom, offset $ObjTmpl(NetComSupervisor), offset $ObjTmpl(NetComTLSClientProtocol)

  ;Set the transmitted text
  lea xdx, [xsi].SndDlg
  invoke MemClone, addr [xdx].$Obj(SendDlg).cText, offset bPayload, sizeof bPayload

  invoke SetWindowText, [xsi].hWnd, offset szAppTitle
  invoke SetTimer, [xsi].hWnd, TimerID, 500, NULL
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClient.OnCommand

Method NetComTLSClient.OnCommand, uses xsi, wParam:WPARAM, lParam:LPARAM
  local cBuffer[MAX_PATH]:CHR, Dlg:$Obj(DialogAbout), hIcon:HICON
  local SetDlg:$Obj(TestSettingsDlg)

  SetObject xsi
  mov xax, wParam
  .if ax == IDM_EXIT
    invoke SendMessage, [xsi].hWnd, WM_SYSCOMMAND, SC_CLOSE, NULL
    xor eax, eax

  .elseif ax == IDM_SETTINGS
    New SetDlg::TestSettingsDlg
    OCall SetDlg::TestSettingsDlg.Init, xsi, [xsi].hWnd
    OCall SetDlg::TestSettingsDlg.Show
    OCall SetDlg::TestSettingsDlg.Done
    .if SetDlg.bAccepted != FALSE
      invoke TestSettingsSave
      ;Timeouts and receive limit apply immediately, TLS settings with the next Connect
      invoke TestApplyNetCom, offset $ObjTmpl(NetComSupervisor), \
                              offset $ObjTmpl(NetComTLSClientProtocol)
    .endif
    xor eax, eax

  .elseif ax == IDM_RESET_STATS
    invoke MemZero, offset TestStats, sizeof TLS_TEST_STATS
    xor eax, eax

  .elseif ax == IDM_SEND
    OCall [xsi].SndDlg::SendDlg.Init, xsi, [xsi].hWnd
    OCall [xsi].SndDlg::SendDlg.Show
    OCall [xsi].SndDlg::SendDlg.Done
    xor eax, eax

  .elseif ax == IDM_ABOUT
    New Dlg::DialogAbout
    mov hIcon, $invoke(LoadIcon, hInstance, $OfsCStr("ICON_APP"))
    OCall Dlg::DialogAbout.Init, xsi, [xsi].hWnd, hIcon, offset szAboutText
    OCall Dlg::DialogAbout.Show
    OCall Dlg::DialogAbout.Done
    invoke DestroyIcon, hIcon
    xor eax, eax

  .elseif ax == IDM_HELP
    invoke ExpandEnvironmentStrings, $OfsCStr("%OBJASM_PATH%\Help\ObjAsm_Reference_Volume-I.pdf"), \
                                     addr cBuffer, lengthof(cBuffer)
    invoke PdfView, [xsi].hWnd, addr cBuffer, $OfsCStr("Introduction")
    xor eax, eax

  .else
    invoke DefWindowProc, [xsi].hWnd, WM_COMMAND, wParam, lParam
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClient.OnTimer

Method NetComTLSClient.OnTimer, uses xbx xdi xsi, wParam:WPARAM, lParam:LPARAM
  local cBuffer[1024]:CHR

  SetObject xsi
  mov xbx, $invoke(GetDC, [xsi].hWnd)
  invoke GetSysColor, COLOR_WINDOWTEXT
  invoke SetTextColor, xbx, eax

  lea xdi, cBuffer

  XPOS = 20
  YPOS = -10

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#Workers = %lu         "), [xsi].Client.dWorkerCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#Listeners = %lu         "), [xsi].Client.Listeners.dCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 20
  invoke wsprintf, xdi, $OfsCStr("#Connections = %lu       "), [xsi].Client.ConnectionPool.dCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#IOJobs = %lu            "), [xsi].Client.IOJobPool.dCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#In Bytes = %lu          "), [xsi].Client.dBytesIn
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 20
  invoke wsprintf, xdi, $OfsCStr("#In Rate = %lu kbit/s           "), [xsi].Client.dRateIn
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#Out Bytes = %lu          "), [xsi].Client.dBytesOut
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 20
  invoke wsprintf, xdi, $OfsCStr("#Out Rate = %lu kbit/s           "), [xsi].Client.dRateOut
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  ;TLS test statistics
  YPOS = YPOS + 30
  invoke TestConnectionsAction, addr [xsi].Client, TTA_COUNT_PAUSED
  invoke TestPrintStats, xbx, XPOS, YPOS, eax

  invoke ReleaseDC, [xsi].hWnd, xbx

  ;Raw handshake trickle: one byte per interval on every raw connection (timer = 500 ms)
  .if TestSettings.dTrickleSec != 0
    inc [xsi].dTrickleTicks
    mov eax, TestSettings.dTrickleSec
    add eax, eax                                        ;Seconds => 500 ms ticks
    .if [xsi].dTrickleTicks >= eax
      mov [xsi].dTrickleTicks, 0
      invoke TestConnectionsAction, addr [xsi].Client, TTA_TRICKLE
    .endif
  .endif
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     NetComTLSClient.Startup

Method NetComTLSClient.Startup
  local WC:WNDCLASSEX

  mov WC.cbSize, sizeof WNDCLASSEX
  mov WC.style, CLSSTYLE
  m2m WC.lpfnWndProc, $MethodAddr(NetComTLSClient.WndProc), xax
  mov WC.cbClsExtra, 0
  mov WC.cbWndExtra, 0
  m2m WC.hInstance, hInstance, xax
  mov WC.hbrBackground, COLOR_WINDOW + 1
  c2m WC.lpszMenuName, $OfsCStr("MENU_APP"), xax
  c2m WC.lpszClassName, offset szNetComTLSClient, xax
  mov WC.hIcon, $invoke(LoadIcon, hInstance, $OfsCStr("ICON_APP"))
  mov WC.hCursor, $invoke(LoadCursor, NULL, IDC_ARROW)
  mov WC.hIconSm, 0

  invoke RegisterClassEx, addr WC
MethodEnd


; ==================================================================================================
;    SendDlg implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.CtlsEnable

Method SendDlg.CtlsEnable, uses xbx xdi xsi, dEnable:DWORD
  SetObject xsi

  .if dEnable == FALSE
    .ifBitSet [xsi].dFlags, SDF_CTRLS_ENABLED
      BitClr [xsi].dFlags, SDF_CTRLS_ENABLED
    .else
      ExitMethod
    .endif
  .else
    .ifBitClr [xsi].dFlags, SDF_CTRLS_ENABLED
      BitSet [xsi].dFlags, SDF_CTRLS_ENABLED
    .else
      ExitMethod
    .endif
  .endif

  invoke GetDlgItem, [xsi].hWnd, IDC_CBO_ADDR
  invoke EnableWindow, xax, dEnable

  invoke GetDlgItem, [xsi].hWnd, IDC_EDT_PORT
  invoke EnableWindow, xax, dEnable
  invoke GetDlgItem, [xsi].hWnd, IDC_UDN_PORT
  invoke EnableWindow, xax, dEnable

  invoke GetDlgItem, [xsi].hWnd, IDC_EDT_CONNECTIONS
  invoke EnableWindow, xax, dEnable
  invoke GetDlgItem, [xsi].hWnd, IDC_UDN_CONNECTIONS
  invoke EnableWindow, xax, dEnable

  invoke GetDlgItem, [xsi].hWnd, IDC_EDT_DATA
  invoke EnableWindow, xax, dEnable

  invoke GetDlgItem, [xsi].hWnd, IDC_EDT_REPETITIONS
  invoke EnableWindow, xax, dEnable
  invoke GetDlgItem, [xsi].hWnd, IDC_UDN_REPETITIONS
  invoke EnableWindow, xax, dEnable

  ;The raw trickle mode is selected before connecting
  invoke GetDlgItem, [xsi].hWnd, IDC_CHK_TRICKLE
  invoke EnableWindow, xax, dEnable

  invoke GetDlgItem, [xsi].hWnd, IDC_BTN_SEND
  xor edx, edx
  .if dEnable == FALSE
    inc edx
  .endif
  invoke EnableWindow, xax, edx

  .if dEnable != FALSE
    mov ebx, IDC_BTN_CONNECT
    mov edx, IDC_BTN_DISCONNECT
  .else
    mov ebx, IDC_BTN_DISCONNECT
    mov edx, IDC_BTN_CONNECT
  .endif
  invoke GetDlgItem, [xsi].hWnd, edx
  invoke EnableWindow, xax, FALSE
  invoke GetDlgItem, [xsi].hWnd, ebx
  invoke EnableWindow, xax, TRUE
  invoke SendMessage, [xsi].hWnd, DM_SETDEFID, ebx, 0
  invoke GetDlgItem, [xsi].hWnd, ebx
  invoke SetFocus, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.CtlsGet

Method SendDlg.CtlsGet, uses xdi xsi
  local dRetValue:DWORD, cAddress[100]:CHR, Hints:ADDRINFOT, pResult:PADDRINFOT
  local hComboServerAddr:HANDLE, cServiceName[100]:CHR

  SetObject xsi
  mov dRetValue, FALSE

  mov hComboServerAddr, $invoke(GetDlgItem, [xsi].hWnd, IDC_CBO_ADDR)
  lea xdi, cAddress
  invoke GetWindowText, hComboServerAddr, xdi, lengthof cAddress
  invoke StrLRTrim, xdi, xdi

  ; Store hostname for TLS SNI
  invoke StrCopyA, addr [xsi].cHostName, addr cAddress
  DbgStrA [xsi].cHostName

  invoke SendMessage, hComboServerAddr, CB_GETCURSEL, 0, 0
  mov [xsi].dComboIndex, eax

  lea xdi, cServiceName
  invoke GetDlgItemText, [xsi].hWnd, IDC_EDT_PORT, xdi, lengthof cServiceName
  invoke StrLRTrim, xdi, xdi
  invoke dec2dword, xdi
  .if SDWORD ptr eax <= 0 || SDWORD ptr eax > 0FFFFh
    invoke MessageBox, [xsi].hWnd, $OfsCStr("Incorrect server port number"), \
                       addr cError, MB_OK or MB_ICONERROR
    xor eax, eax
    ExitMethod
  .endif

  mov [xsi].dConnections, $32($invoke(GetDlgItemInt, [xsi].hWnd, IDC_EDT_CONNECTIONS, NULL, FALSE))
  invoke GetDlgItemTextA, [xsi].hWnd, IDC_EDT_DATA, addr [xsi].cText, BUFFERSIZE
  mov [xsi].dRepetitions, $32($invoke(GetDlgItemInt, [xsi].hWnd, IDC_EDT_REPETITIONS, NULL, FALSE))

  ;Test options
  invoke IsDlgButtonChecked, [xsi].hWnd, IDC_CHK_NODELIM
  xor ecx, ecx
  .if eax == BST_CHECKED
    inc ecx
  .endif
  mov [xsi].bNoDelimiter, ecx
  invoke IsDlgButtonChecked, [xsi].hWnd, IDC_CHK_TRICKLE
  xor ecx, ecx
  .if eax == BST_CHECKED
    inc ecx
  .endif
  mov [xsi].bTrickle, ecx

  mov Hints.ai_flags, 0
  mov Hints.ai_family, AF_INETX
  mov Hints.ai_socktype, SOCK_STREAM
  mov Hints.ai_protocol, IPPROTO_TCP
  mov Hints.ai_addrlen, 0
  mov Hints.ai_canonname, NULL
  mov Hints.ai_addr, NULL
  mov Hints.ai_next, NULL
  invoke GetAddrInfo, addr cAddress, addr cServiceName, addr Hints, addr pResult
  .if eax != 0
    mov dRetValue, eax
    invoke MessageBox, [xsi].hWnd, $OfsCStr("Incorrect server address or port number"), \
                       addr cError, MB_OK or MB_ICONERROR
    jmp @@Exit
  .endif
  mov xax, pResult
  lea xcx, $ObjTmpl(NetComTLSClientProtocol).ServerRemoteAddr
  invoke MemClone, xcx, [xax].ADDRINFOT.ai_addr, DWORD ptr [xax].ADDRINFOT.ai_addrlen
  invoke FreeAddrInfo, pResult
  mov dRetValue, TRUE

@@Exit:
  mov eax, dRetValue
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.CtlsSet

Method SendDlg.CtlsSet, uses xbx xsi
  local cBuffer[100]:CHR, dBufferLength:DWORD, pMibTable:PMIB_IPNET_TABLE2
  local hComboServerAddr:HANDLE, dSize:DWORD, dPort:DWORD, pAdapter:POINTER, cPortStr[20]:CHR

  SetObject xsi

  mov hComboServerAddr, $invoke(GetDlgItem, [xsi].hWnd, IDC_CBO_ADDR)
  invoke SendMessage, hComboServerAddr, CB_RESETCONTENT, 0, 0

  ;Add local adapter IPs
  invoke GetAdaptersAddresses, AF_INETX, 0, NULL, NULL, addr dSize
  MemAlloc dSize
  .if xax != NULL
    mov pAdapter, xax
    invoke GetAdaptersAddresses, AF_INETX, 0, NULL, pAdapter, addr dSize
    .if eax == ERROR_SUCCESS
      mov xbx, pAdapter
      .while xbx != NULL
        mov xdi, [xbx].IP_ADAPTER_ADDRESSES.FirstUnicastAddress
        .while xdi != NULL
          invoke getnameinfo, [xdi].IP_ADAPTER_UNICAST_ADDRESS.Address.lpSockaddr, \
                              [xdi].IP_ADAPTER_UNICAST_ADDRESS.Address.iSockaddrLength, \
                              addr cBuffer, sizeof cBuffer, \
                              NULL, 0, \
                              NI_NUMERICHOST
          .break .if eax != ERROR_SUCCESS
          invoke SendMessage, hComboServerAddr, CB_ADDSTRING, 0, addr cBuffer
          mov xdi, [xdi].IP_ADAPTER_UNICAST_ADDRESS.Next
        .endw
        mov xbx, [xbx].IP_ADAPTER_ADDRESSES.Next
      .endw
    .endif
    MemFree pAdapter
  .endif

  ;Add known neighbor IPs
  invoke GetIpNetTable2, AF_INETX, addr pMibTable
  .if eax == NO_ERROR
    mov xdi, pMibTable
    mov ebx, [xdi].MIB_IPNET_TABLE2.NumEntries
    lea xdi, [xdi].MIB_IPNET_TABLE2.Table
    test ebx, ebx
    .while !ZERO?
      mov dBufferLength, lengthof(cBuffer)
      invoke WSAAddressToString, addr [xdi].MIB_IPNET_ROW2.Address, sizeof SOCKADDR_INET, \
                                 NULL, addr cBuffer, addr dBufferLength
      .if eax == NO_ERROR
        invoke SendMessage, hComboServerAddr, CB_ADDSTRING, 0, addr cBuffer
      .endif
      add xdi, sizeof(MIB_IPNET_ROW2)
      dec ebx
    .endw
    invoke FreeMibTable, pMibTable
  .endif

  invoke SendMessage, hComboServerAddr, CB_SETCURSEL, [xsi].dComboIndex, 0

  ;Set port
  invoke htons, $ObjTmpl(NetComTLSClientProtocol).ServerRemoteAddr.wPort
  mov dPort, eax
  invoke udword2dec, addr cPortStr, dPort
  invoke SetDlgItemText, [xsi].hWnd, IDC_EDT_PORT, addr cPortStr

  mov xbx, $invoke(GetDlgItem, [xsi].hWnd, IDC_UDN_PORT)
  invoke SendMessage, xbx, UDM_SETBASE, 10, 0
  invoke SendMessage, xbx, UDM_SETRANGE32, 1, 0FFFFh
  invoke SendMessage, xbx, UDM_SETPOS32, 0, dPort

  ;Set number of connections
  invoke SetDlgItemInt, [xsi].hWnd, IDC_EDT_CONNECTIONS, [xsi].dConnections, FALSE
  mov xbx, $invoke(GetDlgItem, [xsi].hWnd, IDC_UDN_CONNECTIONS)
  invoke SendMessage, xbx, UDM_SETBASE, 10, 0
  invoke SendMessage, xbx, UDM_SETRANGE32, 1, 07FFFFFFFh
  invoke SendMessage, xbx, UDM_SETPOS32, 0, [xsi].dConnections

  ;Set data
  invoke SetDlgItemTextA, [xsi].hWnd, IDC_EDT_DATA, addr [xsi].cText
  OCall xsi.UpdateDataGrp

  ;Set repetitions
  invoke SetDlgItemInt, [xsi].hWnd, IDC_EDT_REPETITIONS, [xsi].dRepetitions, FALSE
  mov xbx, $invoke(GetDlgItem, [xsi].hWnd, IDC_UDN_REPETITIONS)
  invoke SendMessage, xbx, UDM_SETBASE, 10, 0
  invoke SendMessage, xbx, UDM_SETRANGE32, 1, 07FFFFFFFh
  invoke SendMessage, xbx, UDM_SETPOS32, 0, [xsi].dRepetitions

  ;Test options
  invoke CheckDlgButton, [xsi].hWnd, IDC_CHK_NODELIM, [xsi].bNoDelimiter
  invoke CheckDlgButton, [xsi].hWnd, IDC_CHK_TRICKLE, [xsi].bTrickle
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.Done

Method SendDlg.Done, uses xsi
  SetObject xsi
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.Init

Method SendDlg.Init, uses xsi, pOwner:POINTER, hParent:HWND
  SetObject xsi
  ACall xsi.Init, pOwner, hParent, IDD_DLG_SEND
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.OnInitDialog

Method SendDlg.OnInitDialog, uses xsi, wParam:WPARAM, lParam:LPARAM
  SetObject xsi
  ACall xsi.OnInitDialog, wParam, lParam
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.OnCommand

Method SendDlg.OnCommand, uses xbx xdi xsi, wParam:WPARAM, lParam:LPARAM
  local pItem:PSDLL_ITEM, cBuffer[BUFFERSIZE + 20]:CHRA, dSize:DWORD

  SetObject xsi
  mov xdi, [xsi].pOwner
  LoWord wParam

  ;Handle Connect button
  .if eax == IDC_BTN_CONNECT
    BitClr [xsi].dFlags, SDF_ERROR
    .if $OCall(xsi.CtlsGet) != FALSE
      OCall xsi.CtlsEnable, FALSE

      ; New TLS config snapshot from the settings, the server address is the default target
      ; name. Running connections keep their snapshot (no shared config is mutated).
      OCall $ObjTmpl(NetComTLSClientProtocol)::NetComTLSClientProtocol.Reconfigure, \
            addr [xsi].cHostName
      m2m $ObjTmpl(NetComTLSClientProtocol).bRawMode, [xsi].bTrickle, eax

      mov ebx, [xsi].dConnections
      test ebx, ebx
      .while !ZERO?
        .ifBitSet [xsi].dFlags, SDF_ERROR
          .break
        .endif
        OCall [xdi].$Obj(NetComTLSClient).Client::NetComEngine.ConnectTo, \
                                         offset $ObjTmpl(NetComTLSClientProtocol), \
                                         addr $ObjTmpl(NetComTLSClientProtocol).ServerRemoteAddr, \
                                         addr $ObjTmpl(NetComTLSClientProtocol).ClientLocalAddr
        dec ebx
      .endw
    .endif
    xor eax, eax

  ;Handle Send button
  .elseif eax == IDC_BTN_SEND
    BitClr [xsi].dFlags, SDF_ERROR
    .if $OCall(xsi.CtlsGet) != FALSE
      xor ebx, ebx
      .while ebx < [xsi].dRepetitions
        .ifBitSet [xsi].dFlags, SDF_ERROR
          .break
        .endif
        inc ebx
        lea xdi, cBuffer
        invoke udword2decA, xdi, ebx
        lea xcx, [xdi + xax*sizeof(CHRA) - sizeof(CHRA)]
        FillTextA [xcx], < - >
        add xcx, ??StrSize
        invoke StrECopyA, xcx, addr [xsi].cText
        sub xax, xdi
        .if [xsi].bNoDelimiter == FALSE
          inc eax                                       ;Include the ZTC delimiter
        .endif
        mov dSize, eax

        mov xcx, [xsi].pOwner
        invoke EnterCriticalSection, addr [xcx].$Obj(NetComTLSClient).Client.ConnectionPool.CritSect

        mov xcx, [xsi].pOwner
        lea xdi, [xcx].$Obj(NetComTLSClient).Client.ConnectionChain
        SDLL_GetFirst xdi, xax
        .while !ZERO?
          .ifBitSet [xsi].dFlags, SDF_ERROR
            .break
          .endif
          mov pItem, xax
          lea xcx, [xax - offset $Obj(NetComConnection).ChainItem]
          OCall xcx::NetComConnection.QueueSend, addr cBuffer, dSize
          mov xax, pItem
          SDLL_GetNext xax, xdi
        .endw

        mov xcx, [xsi].pOwner
        invoke LeaveCriticalSection, addr [xcx].$Obj(NetComTLSClient).Client.ConnectionPool.CritSect
      .endw
    .endif
    xor eax, eax

  ;Handle Disconnect button
  .elseif eax == IDC_BTN_DISCONNECT
    mov xcx, [xsi].pOwner
    lea xbx, [xcx].$Obj(NetComTLSClient).Client
    OCall xbx::NetComEngine.ConnectionsDisconnect
    ;Allow time for TLS close_notify exchange before teardown
    invoke Sleep, 200
    OCall xbx::NetComEngine.ConnectionsDestroy
    OCall xbx::NetComEngine.ConnectionsClose
    OCall xsi.CtlsEnable, TRUE
    xor eax, eax

  ;Handle test buttons
  .elseif eax == IDC_BTN_PAUSE
    mov xcx, [xsi].pOwner
    invoke TestConnectionsAction, addr [xcx].$Obj(NetComTLSClient).Client, TTA_PAUSE
    DbgDec eax, "Receive paused on connections"
    xor eax, eax

  .elseif eax == IDC_BTN_RESUME
    mov xcx, [xsi].pOwner
    invoke TestConnectionsAction, addr [xcx].$Obj(NetComTLSClient).Client, TTA_RESUME
    DbgDec eax, "Receive resumed on connections"
    xor eax, eax

  .elseif eax == IDC_BTN_ABORT
    mov xcx, [xsi].pOwner
    invoke TestConnectionsAction, addr [xcx].$Obj(NetComTLSClient).Client, TTA_ABORT
    DbgDec eax, "Aborted connections"
    OCall xsi.CtlsEnable, TRUE
    xor eax, eax

  ;Handle Cancel button
  .elseif eax == IDCANCEL
    mov xcx, [xsi].pOwner
    lea xbx, [xcx].$Obj(NetComTLSClient).Client
    OCall xbx::NetComEngine.ConnectionsDisconnect
    invoke Sleep, 200
    OCall xbx::NetComEngine.ConnectionsDestroy
    OCall xbx::NetComEngine.ConnectionsClose
    invoke EndDialog, [xsi].hWnd, IDCANCEL
    xor eax, eax

  .else
    invoke DefWindowProc, [xsi].hWnd, WM_COMMAND, wParam, lParam
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.OnNetComEnableCtrls
; Purpose:    Thread-safe handler for CtlsEnable — posted from worker thread via PostMessage.
; Arguments:  wParam = TRUE (enable) or FALSE (disable).

Method SendDlg.OnNetComEnableCtrls, uses xsi, wParam:WPARAM, lParam:LPARAM
  SetObject xsi
  mov xax, wParam
  OCall xsi.CtlsEnable, eax
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     SendDlg.UpdateDataGrp

Method SendDlg.UpdateDataGrp, uses xsi
  local cBuffer[100]:CHR
  SetObject xsi
  invoke GetDlgItemTextA, [xsi].hWnd, IDC_EDT_DATA, addr [xsi].cText, BUFFERSIZE
  invoke StrLengthA, addr [xsi].cText
  inc eax                                               ;Include ZTC
  invoke wsprintf, addr cBuffer, $OfsCStr("Data [%lu bytes]"), eax
  invoke SetDlgItemText, [xsi].hWnd, IDC_GRP_DATA, addr cBuffer
MethodEnd

endif
