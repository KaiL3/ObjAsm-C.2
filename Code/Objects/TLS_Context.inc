; ==================================================================================================
; Title:      TLS_Context.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm TLS/SSL encryption support for the NetCom framework.
;             Defines TLS state constants, search type constants, error codes, and the abstract
;             TLS_Context base class used by NetComConnection for polymorphic TLS operations.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/secauthn/schannel
;             - https://learn.microsoft.com/en-us/windows/win32/secauthn/creating-an-schannel-security-context
; Notes:      This file requires the NetCom framework objects to be loaded.
;             Version C.1.0
;               - Initial release.
; ==================================================================================================


; ==================================================================================================
;    TLS State Constants
; ==================================================================================================

TLS_STATE_NONE              equ   0         ;No TLS activity
TLS_STATE_HANDSHAKE         equ   1         ;TLS handshake in progress
TLS_STATE_DATA              equ   2         ;TLS session established, data transfer active
TLS_STATE_SHUTDOWN          equ   3         ;TLS shutdown in progress
TLS_STATE_ERROR             equ   4         ;TLS error state, connection must be closed


; ==================================================================================================
;    TLS Certificate Search Type Constants
; ==================================================================================================

TLS_SEARCH_BY_SUBJECT       equ   1         ;Search certificate by subject name
TLS_SEARCH_BY_SERIAL        equ   2         ;Search certificate by serial number
TLS_SEARCH_BY_THUMBPRINT    equ   3         ;Search certificate by thumbprint (SHA-1 hash)


; ==================================================================================================
;    TLS Error Codes
; ==================================================================================================

ERROR_BASE = 111111130
AddErrMsg TLS_CREDENTIAL_ERROR,           "TLS Credential-Initialisierung fehlgeschlagen"
AddErrMsg TLS_HANDSHAKE_FAILED,           "TLS-Handshake fehlgeschlagen"
AddErrMsg TLS_ENCRYPT_ERROR,              "TLS-Verschluesselung fehlgeschlagen"
AddErrMsg TLS_DECRYPT_ERROR,              "TLS-Entschluesselung fehlgeschlagen"
AddErrMsg TLS_CERTIFICATE_INVALID,        "TLS-Zertifikat ungueltig"
AddErrMsg TLS_CLIENT_CERT_REQUIRED,       "Client-Zertifikat vom Server angefordert, kein Provider gesetzt"
AddErrMsg TLS_CLIENT_CERT_NOT_PROVIDED,   "Client-Zertifikats-Provider lieferte kein Zertifikat"
AddErrMsg TLS_SERVER_CERT_REQUIRED,       "Server-Zertifikats-Provider nicht gesetzt"
AddErrMsg TLS_SERVER_CERT_NOT_PROVIDED,   "Server-Zertifikats-Provider lieferte kein Zertifikat"
AddErrMsg TLS_SERVER_CERT_NO_PRIVATE_KEY, "Server-Zertifikat ohne privaten Schluessel"
AddErrMsg TLS_BUFFER_ALLOC_FAILED,        "TLS-Puffer-Allokation fehlgeschlagen"
AddErrMsg TLS_CONFIG_DURING_HANDSHAKE,    "TLS-Konfigurationsaenderung waehrend aktivem Handshake nicht erlaubt"


; ==================================================================================================
;    SChannel Protocol Version Constants (Windows SDK)
; ==================================================================================================

ifndef SP_PROT_TLS1_2_CLIENT
  SP_PROT_TLS1_2_CLIENT     equ   00000800h
endif
ifndef SP_PROT_TLS1_2_SERVER
  SP_PROT_TLS1_2_SERVER     equ   00000400h
endif
ifndef SP_PROT_TLS1_2
  SP_PROT_TLS1_2            equ   SP_PROT_TLS1_2_CLIENT or SP_PROT_TLS1_2_SERVER
endif
ifndef SP_PROT_TLS1_3_CLIENT
  SP_PROT_TLS1_3_CLIENT     equ   00002000h
endif
ifndef SP_PROT_TLS1_3_SERVER
  SP_PROT_TLS1_3_SERVER     equ   00001000h
endif
ifndef SP_PROT_TLS1_3
  SP_PROT_TLS1_3            equ   SP_PROT_TLS1_3_CLIENT or SP_PROT_TLS1_3_SERVER
endif


; ==================================================================================================
;    TLS_Context Object Definition
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Object:     TLS_Context
; Purpose:    Abstract base class for TLS operations per connection.
;             Defines the interface through which NetComConnection polymorphically performs
;             TLS operations. Derived classes (e.g. TLS_SChannelContext) implement the
;             concrete behavior.
; Notes:      Virtual abstract methods must be overridden by derived classes.
;             Configuration methods (SetAllowedProtocols, SetAllowedCipherSuites) enforce
;             protection: they return an error if called while a handshake is active.

Object TLS_Context, TLS_ContextID, Primer
  ; --- Abstract methods (must be implemented by derived classes) ---
  VirtualAbstract   Encrypt,              POINTER, DWORD, POINTER, POINTER
                                          ; pPlaintext, dPlaintextSize, ppEncrypted, pdEncryptedSize
  VirtualAbstract   Decrypt,              POINTER, DWORD, POINTER, POINTER
                                          ; pCiphertext, dCiphertextSize, ppPlaintext, pdPlaintextSize
  VirtualAbstract   ProcessHandshakeData, POINTER, DWORD, POINTER
                                          ; pData, dDataSize, pConnection
  VirtualAbstract   StartClientHandshake, POINTER
                                          ; pConnection
  VirtualAbstract   StartServerHandshake, POINTER
                                          ; pConnection
  VirtualAbstract   Shutdown,             POINTER
                                          ; pConnection
  VirtualAbstract   GetState              ; Return in eax: TLS_STATE_xxx

  ; --- Concrete virtual methods (configuration & query) ---
  VirtualMethod     SetCertValidator,       POINTER       ; pTLS_CertValidator
  VirtualMethod     SetClientCertProvider,  POINTER       ; pTLS_ClientCertProvider
  VirtualMethod     SetServerCertProvider,  POINTER       ; pTLS_ServerCertProvider
  VirtualMethod     SetAllowedProtocols,    DWORD         ; dProtocolBitmask
  VirtualMethod     SetAllowedCipherSuites, POINTER, DWORD  ; pAlgIDArray, dCount
  VirtualMethod     SetTargetName,          POINTER       ; pszTargetName (ANSI, for SNI + cert validation)
  VirtualMethod     GetNegotiatedProtocol                 ; Return in eax
  VirtualMethod     GetNegotiatedCipherSuite              ; Return in eax

  ; --- Instance variables ---
  DefineVariable    pCertValidator,       POINTER,  NULL
  DefineVariable    pClientCertProvider,  POINTER,  NULL
  DefineVariable    pServerCertProvider,  POINTER,  NULL
  DefineVariable    dAllowedProtocols,    DWORD,    SP_PROT_TLS1_2 or SP_PROT_TLS1_3
  DefineVariable    pAllowedCipherSuites, POINTER,  NULL
  DefineVariable    dCipherSuiteCount,    DWORD,    0
  DefineVariable    dMaxMessageSize,      DWORD,    0     ;Max plaintext bytes per TLS record (set after handshake)
  DefineVariable    pTargetName,          POINTER,  NULL  ;Server hostname for SNI (ANSI string, caller-owned)

  ; Reassembly buffer (managed by derived class, accessed by NetComConnection)
  DefineVariable    pReassemblyBuffer,    POINTER,  NULL
  DefineVariable    dReassemblyCapacity,  DWORD,    0
  DefineVariable    dReassemblyUsed,      DWORD,    0
  DefineVariable    pDeferredExtra,       POINTER,  NULL  ;Deferred EXTRA shift pointer (set by Decrypt)
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_Context implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.SetCertValidator
; Purpose:    Sets the certificate validator instance used for peer certificate validation.
; Arguments:  Arg1: -> TLS_CertValidator instance (or NULL to clear).
; Return:     Nothing.

Method TLS_Context.SetCertValidator, uses xsi, pValidator:POINTER
  SetObject xsi
  m2m [xsi].pCertValidator, pValidator, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.SetClientCertProvider
; Purpose:    Sets the client certificate provider instance used for mutual authentication.
; Arguments:  Arg1: -> TLS_ClientCertProvider instance (or NULL to clear).
; Return:     Nothing.

Method TLS_Context.SetClientCertProvider, uses xsi, pProvider:POINTER
  SetObject xsi
  m2m [xsi].pClientCertProvider, pProvider, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.SetServerCertProvider
; Purpose:    Sets the server certificate provider instance used for server-side TLS.
; Arguments:  Arg1: -> TLS_ServerCertProvider instance (or NULL to clear).
; Return:     Nothing.

Method TLS_Context.SetServerCertProvider, uses xsi, pProvider:POINTER
  SetObject xsi
  m2m [xsi].pServerCertProvider, pProvider, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.SetAllowedProtocols
; Purpose:    Sets the allowed TLS protocol version bitmask.
;             Returns an error if called while a handshake is in progress.
; Arguments:  Arg1: Protocol bitmask (combination of SP_PROT_TLS1_x constants).
; Return:     eax = OBJ_OK on success, TLS_CONFIG_DURING_HANDSHAKE if handshake active.

Method TLS_Context.SetAllowedProtocols, uses xsi, dProtocolMask:DWORD
  SetObject xsi
  ; Check configuration protection: reject if handshake is active
  OCall xsi.GetState
  .if eax == TLS_STATE_HANDSHAKE
    mov eax, TLS_CONFIG_DURING_HANDSHAKE
  .else
    m2m [xsi].dAllowedProtocols, dProtocolMask, eax
    mov eax, OBJ_OK
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.SetAllowedCipherSuites
; Purpose:    Sets the allowed cipher suite algorithm ID array.
;             Returns an error if called while a handshake is in progress.
; Arguments:  Arg1: -> ALG_ID array.
;             Arg2: Number of elements in the array.
; Return:     eax = OBJ_OK on success, TLS_CONFIG_DURING_HANDSHAKE if handshake active.

Method TLS_Context.SetAllowedCipherSuites, uses xsi, pAlgIDs:POINTER, dCount:DWORD
  SetObject xsi
  ; Check configuration protection: reject if handshake is active
  OCall xsi.GetState
  .if eax == TLS_STATE_HANDSHAKE
    mov eax, TLS_CONFIG_DURING_HANDSHAKE
  .else
    m2m [xsi].pAllowedCipherSuites, pAlgIDs, xax
    m2m [xsi].dCipherSuiteCount, dCount, eax
    mov eax, OBJ_OK
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.GetNegotiatedProtocol
; Purpose:    Returns the negotiated TLS protocol version after a successful handshake.
; Arguments:  None.
; Return:     eax = Negotiated protocol version (0 if no handshake completed).
; Note:       Derived classes should set a member variable with the negotiated value and
;             override this method. Base implementation returns 0.

Method TLS_Context.GetNegotiatedProtocol
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.GetNegotiatedCipherSuite
; Purpose:    Returns the negotiated cipher suite after a successful handshake.
; Arguments:  None.
; Return:     eax = Negotiated cipher suite ALG_ID (0 if no handshake completed).
; Note:       Derived classes should set a member variable with the negotiated value and
;             override this method. Base implementation returns 0.

Method TLS_Context.GetNegotiatedCipherSuite
  xor eax, eax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_Context.SetTargetName
; Purpose:    Sets the target server hostname for SNI (Server Name Indication) and
;             certificate validation. The pointer must remain valid for the lifetime
;             of the TLS session (caller-owned string, not copied).
; Arguments:  Arg1: -> ANSI hostname string (or NULL to disable SNI).
; Return:     Nothing.

Method TLS_Context.SetTargetName, uses xsi, pszName:POINTER
  SetObject xsi
  m2m [xsi].pTargetName, pszName, xax
MethodEnd

endif
