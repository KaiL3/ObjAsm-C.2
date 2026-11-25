; ==================================================================================================
; Title:      NetComTLSClient.asm
; Author:     Kai Liebenau
; Version:    1.1.0
; Purpose:    NetCom TLS Client Application.
; Notes:      Version 1.0.0, June 2026
;               - Initial release with TLS/SChannel support.
;             Version 1.1.0, November 2026
;               - Settings dialog + INI file (TLS, certificate, limits, timeouts), message
;                 counting, test actions (no delimiter, raw handshake trickle, pause/resume
;                 receive, abort), statistics.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Summary:
;   This module implements a NetCom TLS client application that demonstrates controlled
;   multi-connection TLS message transmission.
;
;   The application provides a Windows SDI GUI that allows the user to:
;     - Configure a remote address and service port for TLS connection establishment
;     - Open and manage multiple parallel TLS connections simultaneously
;     - Transmit a configurable text payload repeatedly across all active TLS connections
;     - Gracefully disconnect and release all resources
;
;   TLS is transparently handled: the TLS handshake occurs automatically after TCP connect
;   completes, and all send/receive operations are encrypted/decrypted by the framework.
;
;   The test certificate is automatically installed from the embedded PFX blob if not already
;   present in the store (needed for the server to find its cert).
;
; --------------------------------------------------------------------------------------------------


WIN32_LEAN_AND_MEAN         equ 1                       ;Exclude rarely-used Windows headers
INCL_WINSOCK_API_PROTOTYPES equ 1                       ;Enable WinSock API prototypes

APP_NAME                    textequ <NetComTLSClient>   ;Application internal name
PROTOCOL_WND_NAME           textequ <TLS Client Protocol> ;Debug/protocol window title
TLS_TEST_ROLE               equ 2                       ;TLS_TEST_ROLE_CLIENT (TLS_TestCommon.inc)
INTERNET_PROTOCOL_VERSION   equ 4                       ;Select IP version (4 or 6)

% include @Environ(OBJASM_PATH)\Code\Macros\Model.inc   ;ObjAsm model macros and setup
SysSetup OOP, WIN64, ANSI_STRING, DEBUG(WND)           ;Initialize OOP model

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
% includelib &LibPath&Windows\Iphlpapi.lib              ;IP Helper API (adapter enumeration, etc.)
% includelib &LibPath&Windows\schannel.lib              ;SslGetServerIdentity (SNI extraction)
% includelib &LibPath&Windows\secur32.lib               ;SSPI/SChannel TLS functions
% includelib &LibPath&Windows\crypt32.lib               ;Certificate store functions
% includelib &LibPath&Windows\ncrypt.lib               ;NCryptFreeObject (CNG key handles)

if INTERNET_PROTOCOL_VERSION eq 4
  AF_INETX  equ   AF_INET                               ;Use IPv4 address family
elseif INTERNET_PROTOCOL_VERSION eq 6
  AF_INETX  equ   AF_INET6                              ;Use IPv6 address family
else
  %.err <NetComEngine.Init - wrong IP version: $ToStr(%INTERNET_PROTOCOL_VERSION)>
endif


; Load or build the following ObjAsm framework objects
MakeObjects Primer, Stream, StopWatch                   ;Core utility and timing objects
MakeObjects Collection, DataCollection, XWCollection    ;Generic container classes
MakeObjects SortedCollection, SortedDataCollection      ;Sorted container variants
MakeObjects WinPrimer, Window, Button, Hyperlink        ;Basic windowing controls
MakeObjects Dialog, DialogModal, DialogAbout            ;Dialog-related classes
MakeObjects DataPool                                    ;Data pool support
MakeObjects WinApp, SdiApp                              ;Windows application base classes
MakeObjects NetCom                                      ;NetCom networking framework
MakeObjects TLS_CertProvider
MakeObjects TLS_ClientCertProvider, TLS_ServerCertProvider, TLS_SChannelContext, TLS_DefaultCertValidator
MakeObjects TLS_DefaultClientCertProvider


; Include the hard-coded test certificate data and installer
include ..\TLS_TestCert.inc
include ..\TLS_TestCommon.inc                           ;Settings, TLS config snapshots, test actions
include ..\TLS_TestSettingsDlg.inc                      ;Settings dialog


.code
include NetComTLSClient_Globals.inc                    ;Application-wide globals
include NetComTLSClient_Main.inc                       ;Main application implementation

start proc                                              ;Program entry point
  SysInit                                               ;Initialize ObjAsm runtime model

  DbgClearTxt "NETCOMTLSCLIENT"                         ;Clear main debug output window
  DbgClearTxt "&PROTOCOL_WND_NAME"                      ;Clear protocol debug window

  ; Install the test certificate if not already in store
  invoke InstallTestCertificate
  .if eax == FALSE
    DbgWarning "Failed to install test certificate!"
  .endif

  OCall $ObjTmpl(NetComTLSClient)::NetComTLSClient.Init ;Initialize NetComTLSClient object
  OCall $ObjTmpl(NetComTLSClient)::NetComTLSClient.Run  ;Enter application message loop
  OCall $ObjTmpl(NetComTLSClient)::NetComTLSClient.Done ;Shutdown and cleanup resources

  SysDone                                               ;Finalize ObjAsm runtime model
  invoke ExitProcess, 0                                 ;Terminate process with success code
start endp                                              ;End of program entry procedure

end                                                     ;End of assembly unit
