; ==================================================================================================
; Title:      NetComTLSServer.asm
; Author:     Kai Liebenau
; Version:    1.1.0
; Purpose:    NetCom TLS Server Application.
; Notes:      Version 1.0.0, June 2026
;               - Initial release with TLS/SChannel support.
;             Version 1.1.0, November 2026
;               - Settings dialog + INI file (TLS, certificate, limits, timeouts), echo,
;                 test actions (pause/resume receive, disconnect, abort), statistics.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Summary:
;   This module implements a NetCom TLS server application that accepts incoming TCP connections,
;   performs TLS handshakes using Windows SChannel/SSPI, manages multiple concurrent TLS clients,
;   and monitors network I/O activity.
;
;   The application provides a Windows SDI graphical user interface showing server status,
;   including active workers, listeners, connections, IO jobs, and data throughput.
;
;   TLS is enabled per connection via the Protocol's Allocate method, which creates a
;   TLS_SChannelContext for each new connection. The server certificate is provided from
;   the Windows certificate store (CurrentUser\MY) using a hard-coded test certificate.
;
;   The test certificate is automatically installed from the embedded PFX blob if not already
;   present in the store.
;
; --------------------------------------------------------------------------------------------------


WIN32_LEAN_AND_MEAN         equ 1                       ;Exclude rarely-used Windows headers
INCL_WINSOCK_API_PROTOTYPES equ 1                       ;Enable WinSock API prototypes

PROTOCOL_WND_NAME           textequ <TLS Server Protocol> ;Debug/protocol window title
TLS_TEST_ROLE               equ 1                       ;TLS_TEST_ROLE_SERVER (TLS_TestCommon.inc)
INTERNET_PROTOCOL_VERSION   equ 4                       ;Select IP version (4 or 6)

% include @Environ(OBJASM_PATH)\Code\Macros\Model.inc   ;Include & initialize standard modules
SysSetup OOP, WIN64, ANSI_STRING, DEBUG(WND)            ;Load OOP files and OS related objects

% include &MacPath&fMath.inc                            ;Floating-point math helpers
% include &MacPath&SDLL.inc                             ;Linked list support macros

% include &IncPath&Windows\WinSock2.inc                 ;WinSock core definitions
% include &IncPath&Windows\ws2ipdef.inc                 ;IP protocol definitions
% include &IncPath&Windows\ws2tcpip.inc                 ;TCP/IP helper APIs
% include &IncPath&Windows\wincrypt.inc

% include &IncPath&Windows\ShellApi.inc                 ;Shell API declarations
% include &IncPath&Windows\CommCtrl.inc                 ;Common controls support

% includelib &LibPath&Windows\Ws2_32.lib                ;WinSock 2 library
% includelib &LibPath&Windows\Mswsock.lib               ;Microsoft WinSock extensions
% includelib &LibPath&Windows\Kernel32.lib              ;Core Windows kernel functions
% includelib &LibPath&Windows\Shell32.lib               ;Shell functionality
% includelib &LibPath&Windows\Shlwapi.lib               ;Shell lightweight utilities
% includelib &LibPath&Windows\secur32.lib               ;SSPI/SChannel TLS functions
% includelib &LibPath&Windows\schannel.lib              ;SslGetServerIdentity (SNI extraction)
% includelib &LibPath&Windows\crypt32.lib               ;Certificate store functions
% includelib &LibPath&Windows\ncrypt.lib               ;NCryptFreeObject (CNG key handles)

if INTERNET_PROTOCOL_VERSION eq 4
  AF_INETX  equ   AF_INET                               ;Use IPv4 address family
elseif INTERNET_PROTOCOL_VERSION eq 6
  AF_INETX  equ   AF_INET6                              ;Use IPv6 address family
else
  %.err <NetComEngine.Init - wrong IP version: $ToStr(%INTERNET_PROTOCOL_VERSION)>
endif


;Load or build the following objects
MakeObjects Primer, Stream, DiskStream, Collection, DataPool, StopWatch
MakeObjects DataCollection, XWCollection, SortedCollection, SortedDataCollection
MakeObjects WinPrimer, Window, Button, Hyperlink
MakeObjects Dialog, DialogModal, DialogAbout
MakeObjects WinApp, SdiApp

MakeObjects NetCom                                      ;NetCom networking framework
MakeObjects TLS_CertProvider
MakeObjects TLS_ClientCertProvider, TLS_ServerCertProvider, TLS_DefaultCertValidator
MakeObjects TLS_DefaultServerCertProvider
MakeObjects TLS_SChannelContext


; Include the hard-coded test certificate data and installer
include ..\TLS_TestCert.inc
include ..\TLS_TestCommon.inc                           ;Settings, TLS config snapshots, test actions
include ..\TLS_TestSettingsDlg.inc                      ;Settings dialog


.code
include NetComTLSServer_Globals.inc                    ;Includes application globals
include NetComTLSServer_Main.inc                       ;Includes NetComTLSServer object

start proc                                              ;Program entry point
  SysInit                                               ;Runtime initialization of OOP model

  DbgClearTxt "NetComTLSServer"                         ;Clear this DbgCenter text window
  DbgClearTxt "&PROTOCOL_WND_NAME"                      ;Clear this DbgCenter text window

  ; Install the test certificate if not already in store
  invoke InstallTestCertificate
  .if eax == FALSE
    DbgWarning "Failed to install test certificate - TLS will not work!"
  .endif

  OCall $ObjTmpl(NetComTLSServer)::NetComTLSServer.Init ;Initializes the object data
  OCall $ObjTmpl(NetComTLSServer)::NetComTLSServer.Run  ;Executes the application
  OCall $ObjTmpl(NetComTLSServer)::NetComTLSServer.Done ;Finalizes it

  SysDone                                               ;Runtime finalization of the OOP model
  invoke ExitProcess, 0                                 ;Exits program returning 0 to the OS
start endp

end
