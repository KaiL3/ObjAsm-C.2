; ==================================================================================================
; Title:      TLS_ClientCertProvider.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm abstract base class for TLS client certificate provision (Strategy-Pattern).
;             Defines the interface that custom client certificate provider classes must implement.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-certificate-store-operations
; Notes:      This file requires TLS_Context.inc to be loaded (for TLS_SEARCH_BY_xxx constants).
;             Version C.1.0
;               - Initial release.
; ==================================================================================================


; --------------------------------------------------------------------------------------------------
; Object:     TLS_ClientCertProvider
; Purpose:    Abstract base class for client certificate provision (Strategy-Pattern).
;             Derived classes implement GetClientCert to provide a CERT_CONTEXT pointer
;             for mutual TLS authentication.
; Notes:      Virtual abstract method must be overridden by derived classes.

Object TLS_ClientCertProvider, TLS_ClientCertProviderID, Primer
  VirtualAbstract   GetClientCert         ; Return in xax: -> CERT_CONTEXT or NULL
ObjectEnd

