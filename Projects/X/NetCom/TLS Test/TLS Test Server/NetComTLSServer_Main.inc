; ==================================================================================================
; Title:      NetComTLSServer_Main.inc
; Author:     Kai Liebenau
; Version:    See NetComTLSServer.asm
; Purpose:    NetCom TLS Server Application.
; ==================================================================================================


CLSSTYLE equ CS_BYTEALIGNWINDOW or CS_BYTEALIGNCLIENT or CS_VREDRAW or CS_HREDRAW

CStr szNetComTLSServer, "OAC_NetComTLSServer"           ;Creates class name string in .const

DEFAULT_SERVER_LISTENING_PORT equ $htons(25774)         ;TLS server listening port


Object NetComTLSServer, ApplicationID, SdiApp           ;Single Document Interface App
  RedefineMethod    Done                                ;Finalize application object
  RedefineMethod    Init                                ;Initialize application object
  StaticMethod      Startup                             ;Registers object class with OS
  StaticMethod      UpdateCaption                       ;Shows host and listening port

  VirtualEvent      OnCommand,  WM_COMMAND              ;WM_COMMAND handler (menu and controls)
  VirtualEvent      OnTimer,    WM_TIMER                ;WM_TIMER handler for status updates

  Embed  Server,    NetComEngine                        ;Embedded NetCom engine instance
ObjectEnd


include NetComTLSServer_Protocol.inc                    ;Include server-specific protocol


.code
; ==================================================================================================
;    NetComTLSServer implementation
; ==================================================================================================

if IMPLEMENT

TimerID equ 5361784                                     ;Timer ID for periodic status updates

; --------------------------------------------------------------------------------------------------
; Method:    NetComTLSServer.Done
; Purpose:   Finalize the application object.
; Arguments: None.
; Return:    Nothing.

Method NetComTLSServer.Done, uses xsi
  SetObject xsi                                         ;Bind object context
  invoke KillTimer, [xsi].hWnd, TimerID                 ;Stop status update timer
  OCall [xsi].Server::NetComEngine.Done                 ;Shutdown NetCom engine
  ;Free the TLS config snapshots after all connections are gone
  OCall $ObjTmpl(NetComTLSServerProtocol)::NetComTLSServerProtocol.Done
  ACall xsi.Done                                        ;Call ancestor Done method
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:    NetComTLSServer.Init
; Purpose:   Initialize the SDI application object.
; Arguments: None.
; Return:    Nothing.

Method NetComTLSServer.Init, uses xsi
  local dWndPosX:DWORD, dWndPosY:DWORD, dWndWidth:DWORD, dWndHeight:DWORD
  local cCaption[512]:CHR, cPortStr[100]:CHR, dLength:DWORD

  SetObject xsi                                         ;Bind object context
  ACall xsi.Init                                        ;Call ancestor Init method

  ;Load the settings (defaults + INI file next to the executable)
  invoke TestIniInit
  invoke TestSettingsLoad

  mov dWndWidth, 550                                    ;Default window width
  mov dWndHeight, 470                                   ;Default window height
  mov dWndPosX, $32($invoke(CenterForm, dWndWidth, $32($invoke(GetSystemMetrics, SM_CXSCREEN))))
  add dWndPosX, 450                                     ;Offset to adjust window placement
  mov dWndPosY, $32($invoke(CenterForm, dWndHeight, $32($invoke(GetSystemMetrics, SM_CYSCREEN))))

  ;Create main window
  invoke CreateWindowEx, WS_EX_LEFT or WS_EX_APPWINDOW, \
                         offset szNetComTLSServer, offset szAppTitle, WS_OVERLAPPEDWINDOW, \
                         dWndPosX, dWndPosY, dWndWidth, dWndHeight, NULL, NULL, hInstance, xsi

  invoke ShowWindow, [xsi].hWnd, SW_SHOWNORMAL          ;Show application window
  invoke UpdateWindow, [xsi].hWnd                       ;Update window client area

  ;Listening port, timeouts and receive limit from the settings
  invoke htons, WORD ptr TestSettings.dPort
  mov $ObjTmpl(NetComTLSServerProtocol).ListeningAddr.wPort, ax
  invoke TestApplyNetCom, offset $ObjTmpl(NetComSupervisor), offset $ObjTmpl(NetComTLSServerProtocol)

  ;Initialize NetCom engine
  OCall [xsi].Server::NetComEngine.Init, xsi, offset $ObjTmpl(NetComSupervisor), \
                                              50, 1000, MSS_ETHERNET_IPVX
  .if eax == 0
    ;Initialize server protocol
    OCall $ObjTmpl(NetComTLSServerProtocol)::NetComTLSServerProtocol.Init, xsi
    .if eax == 0
      ;Start listening for connections
      OCall [xsi].Server::NetComEngine.StartListening, 3, addr $ObjTmpl(NetComTLSServerProtocol)
      DbgText "TLS Server is running"                   ;Debug message: server started
    .else
      DbgWarning "NetComTLSServerProtocol initialization failed"
    .endif
  .else
    DbgWarning "NetComEngine initialization failed"     ;Warn if engine init failed
  .endif

  OCall xsi.UpdateCaption                               ;Show host and listening info

  DbgLine                                               ;Insert debug line for readability

  invoke SetTimer, [xsi].hWnd, TimerID, 100, NULL       ;Start timer for periodic status updates
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:    NetComTLSServer.OnCommand
; Purpose:   Event procedure for WM_COMMAND message.
; Arguments: Arg1: First message parameter.
;            Arg2: Second message parameter.
; Return:    eax = Zero if handled.

Method NetComTLSServer.OnCommand, uses xsi, wParam:WPARAM, lParam:LPARAM
  local cBuffer[MAX_PATH]:CHR, Dlg:$Obj(DialogAbout), hIcon:HICON
  local SetDlg:$Obj(TestSettingsDlg), dOldPort:DWORD

  SetObject xsi                                         ;Bind object context
  mov xax, wParam                                       ;Extract command ID
  .if ax == IDM_EXIT
    invoke SendMessage, [xsi].hWnd, WM_SYSCOMMAND, SC_CLOSE, NULL ;Close application
    xor eax, eax                                        ;Indicate handled

  .elseif ax == IDM_SETTINGS
    m2m dOldPort, TestSettings.dPort, eax
    New SetDlg::TestSettingsDlg
    OCall SetDlg::TestSettingsDlg.Init, xsi, [xsi].hWnd
    OCall SetDlg::TestSettingsDlg.Show
    OCall SetDlg::TestSettingsDlg.Done
    .if SetDlg.bAccepted != FALSE
      invoke TestSettingsSave
      ;Timeouts and receive limit apply immediately
      invoke TestApplyNetCom, offset $ObjTmpl(NetComSupervisor), \
                              offset $ObjTmpl(NetComTLSServerProtocol)
      ;TLS settings apply to connections accepted from now on
      OCall $ObjTmpl(NetComTLSServerProtocol)::NetComTLSServerProtocol.Reconfigure
      ;A new port needs new listeners
      mov eax, TestSettings.dPort
      .if eax != dOldPort
        OCall [xsi].Server::NetComEngine.StopListening
        invoke htons, WORD ptr TestSettings.dPort
        mov $ObjTmpl(NetComTLSServerProtocol).ListeningAddr.wPort, ax
        OCall [xsi].Server::NetComEngine.StartListening, 3, addr $ObjTmpl(NetComTLSServerProtocol)
        OCall xsi.UpdateCaption
      .endif
    .endif
    xor eax, eax

  .elseif ax == IDM_PAUSE
    invoke TestConnectionsAction, addr [xsi].Server, TTA_PAUSE
    DbgDec eax, "Receive paused on connections"
    xor eax, eax

  .elseif ax == IDM_RESUME
    invoke TestConnectionsAction, addr [xsi].Server, TTA_RESUME
    DbgDec eax, "Receive resumed on connections"
    xor eax, eax

  .elseif ax == IDM_DISCONNECT
    invoke TestConnectionsAction, addr [xsi].Server, TTA_DISCONNECT
    DbgDec eax, "Gracefully disconnected connections"
    xor eax, eax

  .elseif ax == IDM_ABORT
    invoke TestConnectionsAction, addr [xsi].Server, TTA_ABORT
    DbgDec eax, "Aborted connections"
    xor eax, eax

  .elseif ax == IDM_RESET_STATS
    invoke MemZero, offset TestStats, sizeof TLS_TEST_STATS
    xor eax, eax

  .elseif ax == IDM_ABOUT
    New Dlg::DialogAbout                                ;Create About dialog
    mov hIcon, $invoke(LoadIcon, hInstance, $OfsCStr("ICON_APP")) ;Load application icon
    OCall Dlg::DialogAbout.Init, xsi, [xsi].hWnd, hIcon, offset szAboutText ;Init dialog
    OCall Dlg::DialogAbout.Show                         ;Show dialog
    OCall Dlg::DialogAbout.Done                         ;Release dialog resources
    invoke DestroyIcon, hIcon                           ;Free icon
    xor eax, eax                                        ;Indicate handled

  .elseif ax == IDM_HELP
    invoke ExpandEnvironmentStrings, $OfsCStr("%OBJASM_PATH%\Help\ObjAsm_Reference_Volume-I.pdf"), \
                                     addr cBuffer, lengthof(cBuffer)  ;Resolve PDF path
    invoke PdfView, [xsi].hWnd, addr cBuffer, NULL      ;Display help PDF
    xor eax, eax                                        ;Indicate handled

  .else
    invoke DefWindowProc, [xsi].hWnd, WM_COMMAND, wParam, lParam  ;Default processing
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:    NetComTLSServer.OnTimer
; Purpose:   Event procedure for WM_TIMER message.
; Arguments: Arg1: First message parameter.
;            Arg2: Second message parameter.
; Return:    eax = Zero if handled.

Method NetComTLSServer.OnTimer, uses xbx xdi xsi, wParam:WPARAM, lParam:LPARAM
  local cBuffer[1024]:CHR                               ;Local string buffer for status output

  SetObject xsi                                         ;Bind object context
  mov xbx, $invoke(GetDC, [xsi].hWnd)                   ;Get device context
  invoke GetSysColor, COLOR_WINDOWTEXT                  ;Retrieve default text color
  invoke SetTextColor, xbx, eax                         ;Set text color

  lea xdi, cBuffer                                      ;xdi -> cBuffer

  XPOS = 20                                             ;X offset for text output
  YPOS = -10                                            ;Initial Y position

  ;Output server statistics line by line
  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#Workers = %lu         "), [xsi].Server.dWorkerCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#Listeners = %lu         "), [xsi].Server.Listeners.dCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 20
  invoke wsprintf, xdi, $OfsCStr("#Connections = %lu       "), [xsi].Server.ConnectionPool.dCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#IOJobs = %lu            "), [xsi].Server.IOJobPool.dCount
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#In Bytes = %lu          "), [xsi].Server.dBytesIn
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 20
  invoke wsprintf, xdi, $OfsCStr("#In Rate = %lu kbit/s           "), [xsi].Server.dRateIn
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 30
  invoke wsprintf, xdi, $OfsCStr("#Out Bytes = %lu          "), [xsi].Server.dBytesOut
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  YPOS = YPOS + 20
  invoke wsprintf, xdi, $OfsCStr("#Out Rate = %lu kbit/s           "), [xsi].Server.dRateOut
  invoke StrLength, xdi
  invoke TextOut, xbx, XPOS, YPOS, xdi, eax

  ;TLS test statistics
  YPOS = YPOS + 30
  invoke TestConnectionsAction, addr [xsi].Server, TTA_COUNT_PAUSED
  invoke TestPrintStats, xbx, XPOS, YPOS, eax

  invoke ReleaseDC, [xsi].hWnd, xbx                     ;Release device context
  xor eax, eax                                          ;Return zero to indicate handled
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:    NetComTLSServer.Startup
; Purpose:   Registers the object class with the OS.
; Arguments: None.
; Return:    Nothing.

Method NetComTLSServer.Startup
  local WC:WNDCLASSEX

  mov WC.cbSize, sizeof WNDCLASSEX                      ;Structure size
  mov WC.style, CLSSTYLE                                ;Window class style
  m2m WC.lpfnWndProc, $MethodAddr(NetComTLSServer.WndProc), xax ;Window procedure
  and WC.cbClsExtra, 0                                  ;No extra class bytes
  and WC.cbWndExtra, 0                                  ;No extra window bytes
  m2m WC.hInstance, hInstance, xax                      ;Application instance
  mov WC.hbrBackground, COLOR_WINDOW + 1                ;Default window background
  c2m WC.lpszMenuName, $OfsCStr("MENU_APP"), xax        ;Menu resource
  c2m WC.lpszClassName, offset szNetComTLSServer, xax   ;Window class name
  mov WC.hIcon, $invoke(LoadIcon, hInstance, $OfsCStr("ICON_APP")) ;Load main icon
  mov WC.hCursor, $invoke(LoadCursor, NULL, IDC_ARROW)  ;Set arrow cursor
  and WC.hIconSm, 0                                     ;No small icon

  invoke RegisterClassEx, addr WC                       ;Register window class
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:    NetComTLSServer.UpdateCaption
; Purpose:   Sets the window caption with the host name and the listening port.
; Arguments: None.
; Return:    Nothing.

Method NetComTLSServer.UpdateCaption, uses xsi
  local cCaption[512]:CHR, cPortStr[100]:CHR

  SetObject xsi
  invoke htons, $ObjTmpl(NetComTLSServerProtocol).ListeningAddr.wPort
  invoke udword2dec, addr cPortStr, eax
  invoke StrECopy, addr cCaption, offset szAppTitle
  invoke StrECopy, xax, $OfsCStr(" on ")
  invoke StrECopy, xax, [xsi].Server.pLocalHostName
  invoke StrECopy, xax, $OfsCStr(", TLS listening at port ")
  invoke StrCopy, xax, addr cPortStr
  invoke SetWindowText, [xsi].hWnd, addr cCaption
MethodEnd

endif
