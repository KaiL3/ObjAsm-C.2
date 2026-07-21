; ==================================================================================================
; Title:      TLS_SChannelContext.asm
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm compilation file for TLS_SChannelContext object.
; Notes:      Version C.1.0
;             - Initial release.
; ==================================================================================================


WIN32_LEAN_AND_MEAN         equ 1
INCL_WINSOCK_API_PROTOTYPES equ 1
INTERNET_PROTOCOL_VERSION   equ 4

% include Objects.cop

% include &MacPath&SDLL.inc

% include &IncPath&Windows\WinSock2.inc
% include &IncPath&Windows\ws2ipdef.inc
% include &IncPath&Windows\ws2tcpip.inc

if INTERNET_PROTOCOL_VERSION eq 4
  AF_INETX  equ   AF_INET
elseif INTERNET_PROTOCOL_VERSION eq 6
  AF_INETX  equ   AF_INET6
else
  %.err <Wrong IP version: $ToStr(%INTERNET_PROTOCOL_VERSION)>
endif

;Add here all files that build the inheritance path and referenced objects
LoadObjects Primer
LoadObjects Stream
LoadObjects Collection
LoadObjects DataCollection
LoadObjects SortedCollection
LoadObjects SortedDataCollection
LoadObjects XWCollection
LoadObjects DataPool
LoadObjects StopWatch
LoadObjects TLS_Context
LoadObjects TLS_CertValidator
LoadObjects TLS_ClientCertProvider
LoadObjects TLS_ServerCertProvider
LoadObjects NetCom

;Add here the file that defines the object(s) to be included in the library
MakeObjects TLS_SChannelContext

end
