; ==================================================================================================
; Title:      TLS_ServerCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm abstract base class for server certificate provision (Strategy-Pattern).
;             Defines the interface that concrete server certificate provider classes must
;             implement. The TLS_Context calls GetServerCert to obtain the server certificate
;             for TLS listener operations.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions
; Notes:      This file requires TLS_Context.inc to be loaded (for TLS_SEARCH_BY_xxx constants).
;             Version C.1.0
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:     TLS_ServerCertProvider
; Purpose:    Abstract base class for server certificate provision.
;             Derived classes must implement GetServerCert to return a CERT_CONTEXT pointer
;             for the server certificate, or NULL if no certificate is available.
; Notes:      This is a Strategy-Pattern interface. The TLS_SChannelContext calls GetServerCert
;             during server-side handshake initialization to obtain the server certificate.

Object TLS_ServerCertProvider, TLS_ServerCertProviderID, Primer
  VirtualAbstract   GetServerCert         ; Return in xax: -> CERT_CONTEXT or NULL
ObjectEnd

