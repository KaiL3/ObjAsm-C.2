; ==================================================================================================
; Title:      TLS_SChannelContext.inc
; Author:     Kai Liebenau
; Version:    C.2.1
; Purpose:    ObjAsm SChannel/SSPI-based implementation of TLS_Context.
;             Manages SSPI credentials, security contexts, internal reassembly and encryption
;             buffers for TLS record processing.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/secauthn/schannel
;             - https://learn.microsoft.com/en-us/windows/win32/api/sspi/
; Notes:      Requires TLS_Context.inc to be loaded before this file.
;             Version C.2.1
;               - bHandshakeDone moved to TLS_Context (used by the NetComSupervisor handshake
;                 timeout).
;             Version C.1.0
;               - Initial release.
; ==================================================================================================


; ==================================================================================================
;    SSPI Structure Definitions (from sspi.h / schannel.h)
;    These are not available in the project's Windows includes and must be defined here.
; ==================================================================================================

ifndef SECPKG_CRED_INBOUND
  SECPKG_CRED_INBOUND       equ   1
endif
ifndef SECPKG_CRED_OUTBOUND
  SECPKG_CRED_OUTBOUND      equ   2
endif
ifndef SCHANNEL_CRED_VERSION
  SCHANNEL_CRED_VERSION     equ   4
endif
ifndef SCH_CRED_NO_DEFAULT_CREDS
  SCH_CRED_NO_DEFAULT_CREDS equ   00000010h
endif
ifndef SCH_USE_STRONG_CRYPTO
  SCH_USE_STRONG_CRYPTO     equ   00400000h
endif

ifndef SecHandle
  SecHandle struct
    dwLower   POINTER   ?
    dwUpper   POINTER   ?
  SecHandle ends
endif

ifndef CredHandle
  CredHandle typedef SecHandle
endif

ifndef CtxtHandle
  CtxtHandle typedef SecHandle
endif

ifndef SecPkgContext_StreamSizes
  SecPkgContext_StreamSizes struct
    cbHeader          DWORD   ?
    cbTrailer         DWORD   ?
    cbMaximumMessage  DWORD   ?
    cBuffers          DWORD   ?
    cbBlockSize       DWORD   ?
  SecPkgContext_StreamSizes ends
endif

ifndef SCHANNEL_CRED
  SCHANNEL_CRED struct
    dwVersion               DWORD   ?    ; SCHANNEL_CRED_VERSION = 4
    cCreds                  DWORD   ?    ; Number of certificates
    paCred                  POINTER ?    ; Array of PCCERT_CONTEXT
    hRootStore              HANDLE  ?
    cMappers                DWORD   ?
    aphMappers              POINTER ?
    cSupportedAlgs          DWORD   ?
    palgSupportedAlgs       POINTER ?
    grBitEnabledProtocols   DWORD   ?
    dwMinimumCipherStrength DWORD   ?
    dwMaximumCipherStrength DWORD   ?
    dwSessionLifespan       DWORD   ?
    dwFlags                 DWORD   ?
    dwCredFormat            DWORD   ?
  SCHANNEL_CRED ends
endif

ifndef TimeStamp
  TimeStamp typedef QWORD
endif


; ==================================================================================================
;    SSPI Function Prototypes (from secur32.dll / sspicli.dll)
; ==================================================================================================

; SecBuffer types for EncryptMessage / DecryptMessage / Handshake
ifndef SECBUFFER_STREAM_HEADER
  SECBUFFER_STREAM_HEADER     equ   7
endif
ifndef SECBUFFER_DATA
  SECBUFFER_DATA              equ   1
endif
ifndef SECBUFFER_STREAM_TRAILER
  SECBUFFER_STREAM_TRAILER    equ   6
endif
ifndef SECBUFFER_EMPTY
  SECBUFFER_EMPTY             equ   0
endif
ifndef SECBUFFER_EXTRA
  SECBUFFER_EXTRA             equ   5
endif
ifndef SECBUFFER_TOKEN
  SECBUFFER_TOKEN             equ   2
endif
ifndef SECBUFFER_VERSION
  SECBUFFER_VERSION           equ   0
endif

; InitializeSecurityContext request flags (Client)
ifndef ISC_REQ_SEQUENCE_DETECT
  ISC_REQ_SEQUENCE_DETECT     equ   00000008h
endif
ifndef ISC_REQ_REPLAY_DETECT
  ISC_REQ_REPLAY_DETECT       equ   00000004h
endif
ifndef ISC_REQ_CONFIDENTIALITY
  ISC_REQ_CONFIDENTIALITY     equ   00000010h
endif
ifndef ISC_REQ_EXTENDED_ERROR
  ISC_REQ_EXTENDED_ERROR      equ   00004000h
endif
ifndef ISC_REQ_ALLOCATE_MEMORY
  ISC_REQ_ALLOCATE_MEMORY     equ   00000100h
endif
ifndef ISC_REQ_STREAM
  ISC_REQ_STREAM              equ   00008000h
endif
ifndef ISC_REQ_MANUAL_CRED_VALIDATION
  ISC_REQ_MANUAL_CRED_VALIDATION equ 00080000h
endif
ifndef ISC_REQ_USE_SUPPLIED_CREDS
  ISC_REQ_USE_SUPPLIED_CREDS  equ   00000080h
endif

; ISC_RET output flags
ifndef ISC_RET_MUTUAL_AUTH
  ISC_RET_MUTUAL_AUTH         equ   00000002h
endif

; AcceptSecurityContext request flags (Server)
ifndef ASC_REQ_SEQUENCE_DETECT
  ASC_REQ_SEQUENCE_DETECT     equ   00000008h
endif
ifndef ASC_REQ_REPLAY_DETECT
  ASC_REQ_REPLAY_DETECT       equ   00000004h
endif
ifndef ASC_REQ_CONFIDENTIALITY
  ASC_REQ_CONFIDENTIALITY     equ   00000010h
endif
ifndef ASC_REQ_EXTENDED_ERROR
  ASC_REQ_EXTENDED_ERROR      equ   00008000h
endif
ifndef ASC_REQ_ALLOCATE_MEMORY
  ASC_REQ_ALLOCATE_MEMORY     equ   00000100h
endif
ifndef ASC_REQ_STREAM
  ASC_REQ_STREAM              equ   00010000h
endif
ifndef ASC_REQ_MUTUAL_AUTH
  ASC_REQ_MUTUAL_AUTH         equ   00000002h       ;sspi.h (00020000h would be ASC_REQ_INTEGRITY!)
endif

; QueryContextAttributes attribute IDs
ifndef SECPKG_ATTR_STREAM_SIZES
  SECPKG_ATTR_STREAM_SIZES    equ   4
endif
ifndef SECPKG_ATTR_REMOTE_CERT_CONTEXT
  SECPKG_ATTR_REMOTE_CERT_CONTEXT equ 53h
endif

; SChannel shutdown token type
ifndef SCHANNEL_SHUTDOWN
  SCHANNEL_SHUTDOWN           equ   1
endif

; SslGetServerIdentity prototype (SNI extraction from ClientHello)
ifndef __SCHANNEL_INC__
  SslGetServerIdentity proto WIN_STD_CALL_CONV :POINTER, :DWORD, :POINTER, :POINTER, :DWORD
endif

; Security status codes for DecryptMessage / Handshake
ifndef SEC_E_OK
  SEC_E_OK                    equ   00000000h
endif
ifndef SEC_E_INCOMPLETE_MESSAGE
  SEC_E_INCOMPLETE_MESSAGE    equ   80090318h
endif
ifndef SEC_I_CONTINUE_NEEDED
  SEC_I_CONTINUE_NEEDED       equ   00090312h
endif
ifndef SEC_I_RENEGOTIATE
  SEC_I_RENEGOTIATE           equ   00090321h
endif
ifndef SEC_I_CONTEXT_EXPIRED
  SEC_I_CONTEXT_EXPIRED       equ   00090317h
endif
ifndef SEC_I_INCOMPLETE_CREDENTIALS
  SEC_I_INCOMPLETE_CREDENTIALS equ  00090320h
endif

; Additional SECURITY_STATUS codes for TranslateError
ifndef SEC_E_WRONG_PRINCIPAL
  SEC_E_WRONG_PRINCIPAL       equ   80090322h
endif
ifndef SEC_E_UNTRUSTED_ROOT
  SEC_E_UNTRUSTED_ROOT        equ   80090325h
endif
ifndef SEC_E_CERT_EXPIRED
  SEC_E_CERT_EXPIRED          equ   80090328h
endif
ifndef SEC_E_ALGORITHM_MISMATCH
  SEC_E_ALGORITHM_MISMATCH    equ   80090331h
endif
ifndef SEC_E_INSUFFICIENT_MEMORY
  SEC_E_INSUFFICIENT_MEMORY   equ   80090300h
endif
ifndef SEC_E_CERT_UNKNOWN
  SEC_E_CERT_UNKNOWN          equ   80090327h
endif
ifndef CERT_E_UNTRUSTEDROOT
  CERT_E_UNTRUSTEDROOT        equ   800B0109h
endif
ifndef CERT_E_CN_NO_MATCH
  CERT_E_CN_NO_MATCH          equ   800B010Fh
endif

ifndef SecBuffer
  SecBuffer struct
    cbBuffer    DWORD   ?
    BufferType  DWORD   ?
    pvBuffer    POINTER ?
  SecBuffer ends
endif

ifndef SecBufferDesc
  SecBufferDesc struct
    ulVersion   DWORD   ?     ; SECBUFFER_VERSION = 0
    cBuffers    DWORD   ?
    pBuffers    POINTER ?
  SecBufferDesc ends
endif


; ISC_REQ flags combined for client handshake
TLS_CLIENT_ISC_FLAGS equ ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or \
                         ISC_REQ_CONFIDENTIALITY or ISC_REQ_EXTENDED_ERROR or \
                         ISC_REQ_STREAM or ISC_REQ_MANUAL_CRED_VALIDATION

; ASC_REQ flags combined for server handshake
TLS_SERVER_ASC_FLAGS equ ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or \
                         ASC_REQ_CONFIDENTIALITY or ASC_REQ_EXTENDED_ERROR or \
                         ASC_REQ_STREAM or ASC_REQ_ALLOCATE_MEMORY


ifndef __SSPI_INC__
ifndef SSPI_PROTOS_DEFINED
  SSPI_PROTOS_DEFINED equ 1
  DeleteSecurityContext proto WIN_STD_CALL_CONV :POINTER
  FreeCredentialsHandle proto WIN_STD_CALL_CONV :POINTER
  AcquireCredentialsHandleA proto WIN_STD_CALL_CONV :POINTER, :POINTER, :DWORD, :POINTER, :POINTER, :POINTER, :POINTER, :POINTER, :POINTER
  AcquireCredentialsHandleW proto WIN_STD_CALL_CONV :POINTER, :POINTER, :DWORD, :POINTER, :POINTER, :POINTER, :POINTER, :POINTER, :POINTER
  InitializeSecurityContextA proto WIN_STD_CALL_CONV :POINTER, :POINTER, :POINTER, :DWORD, :DWORD, :DWORD, :POINTER, :DWORD, :POINTER, :POINTER, :POINTER, :POINTER
  InitializeSecurityContextW proto WIN_STD_CALL_CONV :POINTER, :POINTER, :POINTER, :DWORD, :DWORD, :DWORD, :POINTER, :DWORD, :POINTER, :POINTER, :POINTER, :POINTER
  AcceptSecurityContext proto WIN_STD_CALL_CONV :POINTER, :POINTER, :POINTER, :DWORD, :DWORD, :POINTER, :POINTER, :POINTER, :POINTER
  ApplyControlToken proto WIN_STD_CALL_CONV :POINTER, :POINTER
  QueryContextAttributesA proto WIN_STD_CALL_CONV :POINTER, :DWORD, :POINTER
  QueryContextAttributesW proto WIN_STD_CALL_CONV :POINTER, :DWORD, :POINTER
  FreeContextBuffer proto WIN_STD_CALL_CONV :POINTER
  EncryptMessage proto WIN_STD_CALL_CONV :POINTER, :DWORD, :POINTER, :DWORD
  DecryptMessage proto WIN_STD_CALL_CONV :POINTER, :POINTER, :DWORD, :POINTER

  if TARGET_STR_TYPE eq STR_TYPE_WIDE
    AcquireCredentialsHandle textequ <AcquireCredentialsHandleW>
    InitializeSecurityContext textequ <InitializeSecurityContextW>
    QueryContextAttributes textequ <QueryContextAttributesW>
  else
    AcquireCredentialsHandle textequ <AcquireCredentialsHandleA>
    InitializeSecurityContext textequ <InitializeSecurityContextA>
    QueryContextAttributes textequ <QueryContextAttributesA>
  endif
endif
endif
; Note: pTargetName is always ANSI, therefore the ANSI variants of AcquireCredentialsHandle,
;       InitializeSecurityContext and QueryContextAttributes are called explicitly.


; ==================================================================================================
;    Handshake Buffer Constants
; ==================================================================================================

TLS_MAX_RECORD_SIZE         equ   18437     ;5 Header + 16384 max. fragment + 2048 max. expansion (RFC 5246)
TLS_HANDSHAKE_BUFFER_SIZE   equ   TLS_MAX_RECORD_SIZE


; ==================================================================================================
;    TLS_SChannelContext Object Definition
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Object:     TLS_SChannelContext
; Purpose:    SChannel/SSPI-based implementation of TLS_Context.
;             Manages per-connection SSPI credential and security context handles,
;             internal reassembly buffer (receive direction) and encryption buffer
;             (send direction) for TLS record processing.
; Notes:      - Call Init to initialize all variables.
;             - After a successful handshake, call AllocateBuffers to set up internal buffers
;               based on the negotiated StreamSizes.
;             - Call Done or FreeBuffers to release allocated memory.
;             - Encrypt, Decrypt, ProcessHandshakeData, StartClientHandshake,
;               StartServerHandshake, Shutdown and InitCredentials are implemented in
;               subsequent tasks (stubs here).

Object TLS_SChannelContext, TLS_SChannelContextID, TLS_Context
  RedefineMethod  Init,               POINTER         ; pOwner
  RedefineMethod  Done

  RedefineMethod  Encrypt,            POINTER, DWORD, POINTER, POINTER
  RedefineMethod  Decrypt,            POINTER, DWORD, POINTER, POINTER
  RedefineMethod  ProcessHandshakeData, POINTER, DWORD, POINTER
  RedefineMethod  StartClientHandshake, POINTER
  RedefineMethod  StartServerHandshake, POINTER
  RedefineMethod  Shutdown,           POINTER
  RedefineMethod  GetState

  VirtualMethod   InitCredentials,    DWORD, POINTER, DWORD  ; dUsage, pSNIHostname, dSNILen
  VirtualMethod   AllocateBuffers
  VirtualMethod   FreeBuffers
  VirtualMethod   TranslateError,     DWORD           ; dSecurityStatus -> xax = -> error string
  StaticMethod    SendToken,          POINTER         ; -> SecBuffer (send + free SSPI token)
  StaticMethod    FreeToken,          POINTER         ; -> SecBuffer (free SSPI token)
  StaticMethod    KeepExtra,          POINTER, POINTER, DWORD ; -> SecBuffer, pData, dDataSize
  StaticMethod    ValidatePeer                        ; -> eax = OBJ_OK / TLS_CERTIFICATE_INVALID

  ; SSPI-Handles
  DefineVariable  hCredential,        CredHandle,     {}
  DefineVariable  hSecurityContext,    CtxtHandle,     {}
  DefineVariable  bCredentialValid,   DWORD,          FALSE
  DefineVariable  bContextValid,      DWORD,          FALSE

  ; TLS-Zustand
  DefineVariable  dState,             DWORD,          TLS_STATE_NONE
  DefineVariable  dLastError,         DWORD,          0

  ; Stream-Sizes (nach erfolgreichem Handshake)
  DefineVariable  StreamSizes,        SecPkgContext_StreamSizes, {}

  ; Verschluesselungspuffer (Senderichtung)
  DefineVariable  pEncryptBuffer,     POINTER,        NULL
  DefineVariable  dEncryptBufferSize, DWORD,          0

  ; Ausgehandelte Parameter
  DefineVariable  dNegotiatedProtocol, DWORD,         0
  DefineVariable  dNegotiatedCipher,  DWORD,          0

  ; Client/Server mode flag (set during StartClientHandshake / StartServerHandshake)
  DefineVariable  bIsClient,          DWORD,          FALSE

  ; bHandshakeDone is defined in TLS_Context (TRUE after the first completed handshake)

  ; Stored connection pointer (for handshake callbacks)
  DefineVariable  pConnection,        POINTER,        NULL
ObjectEnd


; ==================================================================================================

if IMPLEMENT

; ==================================================================================================
;    TLS_SChannelContext implementation
; ==================================================================================================

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.Init
; Purpose:    Initializes the TLS_SChannelContext instance.
;             Calls parent TLS_Context.Init, then zeros all SChannel-specific variables.
; Arguments:  Arg1: -> Owner object.
; Return:     Nothing.

Method TLS_SChannelContext.Init, uses xsi, pOwner:POINTER
  SetObject xsi
  ACall xsi.Init, pOwner

  ; Zero SSPI handles
  xor eax, eax
  mov [xsi].hCredential.dwLower, xax
  mov [xsi].hCredential.dwUpper, xax
  mov [xsi].hSecurityContext.dwLower, xax
  mov [xsi].hSecurityContext.dwUpper, xax

  ; Reset validity flags
  mov [xsi].bCredentialValid, FALSE
  mov [xsi].bContextValid, FALSE

  ; Reset state
  mov [xsi].dState, TLS_STATE_NONE
  mov [xsi].dLastError, 0

  ; Zero StreamSizes
  lea xax, [xsi].StreamSizes
  mov DWORD ptr [xax], 0                               ; cbHeader
  mov DWORD ptr [xax + 4], 0                           ; cbTrailer
  mov DWORD ptr [xax + 8], 0                           ; cbMaximumMessage
  mov DWORD ptr [xax + 12], 0                          ; cBuffers
  mov DWORD ptr [xax + 16], 0                          ; cbBlockSize

  ; Reset buffer pointers and sizes
  mov [xsi].pReassemblyBuffer, NULL
  mov [xsi].dReassemblyCapacity, 0
  mov [xsi].dReassemblyUsed, 0
  mov [xsi].pEncryptBuffer, NULL
  mov [xsi].dEncryptBufferSize, 0
  mov [xsi].pDeferredExtra, NULL

  ; Reset negotiated parameters
  mov [xsi].dNegotiatedProtocol, 0
  mov [xsi].dNegotiatedCipher, 0

  ; Reset client/server mode and connection pointer
  mov [xsi].bIsClient, FALSE
  mov [xsi].bHandshakeDone, FALSE
  mov [xsi].pConnection, NULL

  ; Set default certificate validator (can be overridden via SetCertValidator)
  lea xax, $ObjTmpl(TLS_DefaultCertValidator)
  mov [xsi].pCertValidator, xax
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.Done
; Purpose:    Releases all resources: buffers, SSPI security context, and credentials.
;             Then calls parent Done.
; Arguments:  None.
; Return:     Nothing.

Method TLS_SChannelContext.Done, uses xbx xsi
  SetObject xsi

  ; Free owned TargetName string
  .if [xsi].pTargetName != NULL
    invoke StrDispose, [xsi].pTargetName
    mov [xsi].pTargetName, NULL
  .endif

  ; Free internal buffers
  OCall xsi.FreeBuffers

  ; Delete security context if valid
  .if [xsi].bContextValid != FALSE
    lea xbx, [xsi].hSecurityContext
    invoke DeleteSecurityContext, xbx
    mov [xsi].bContextValid, FALSE
  .endif

  ; Free credentials handle if valid
  .if [xsi].bCredentialValid != FALSE
    lea xbx, [xsi].hCredential
    invoke FreeCredentialsHandle, xbx
    mov [xsi].bCredentialValid, FALSE
  .endif

  ; Call parent Done
  ACall xsi.Done
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.AllocateBuffers
; Purpose:    Ensures that the internal reassembly buffer and encryption buffer are large enough
;             for the current StreamSizes values (cbHeader + cbMaximumMessage + cbTrailer, at
;             least TLS_MAX_RECORD_SIZE).
;             - The reassembly buffer is grown PRESERVING its content (it may already hold
;               data that followed the last handshake message).
;             - Existing buffers that are large enough are reused (no leak on re-handshake).
; Arguments:  None.
; Return:     eax = OBJ_OK on success, TLS_BUFFER_ALLOC_FAILED on failure.
; Notes:      StreamSizes must be filled (e.g. via QueryContextAttributes after handshake)
;             before calling this method.

Method TLS_SChannelContext.AllocateBuffers, uses xbx xsi
  local dRequiredSize:DWORD, pNewBuffer:POINTER

  SetObject xsi

  ; Calculate required size: cbHeader + cbMaximumMessage + cbTrailer (min. TLS_MAX_RECORD_SIZE)
  mov eax, [xsi].StreamSizes.cbHeader
  add eax, [xsi].StreamSizes.cbMaximumMessage
  add eax, [xsi].StreamSizes.cbTrailer
  .if eax < TLS_MAX_RECORD_SIZE
    mov eax, TLS_MAX_RECORD_SIZE
  .endif
  mov dRequiredSize, eax

  ; --- Reassembly buffer: grow if needed, keeping dReassemblyUsed BYTEs ---
  .if [xsi].pReassemblyBuffer == NULL || eax > [xsi].dReassemblyCapacity
    MemAlloc dRequiredSize, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov pNewBuffer, xax
    .if [xsi].pReassemblyBuffer != NULL
      .if [xsi].dReassemblyUsed != 0
        invoke MemClone, pNewBuffer, [xsi].pReassemblyBuffer, [xsi].dReassemblyUsed
      .endif
      MemFree [xsi].pReassemblyBuffer
    .endif
    m2m [xsi].pReassemblyBuffer, pNewBuffer, xax
    m2m [xsi].dReassemblyCapacity, dRequiredSize, eax
  .endif

  ; --- Encryption buffer: (re)allocate only if missing or too small ---
  mov eax, dRequiredSize
  .if [xsi].pEncryptBuffer == NULL || eax > [xsi].dEncryptBufferSize
    .if [xsi].pEncryptBuffer != NULL
      MemFree [xsi].pEncryptBuffer
      mov [xsi].pEncryptBuffer, NULL
      mov [xsi].dEncryptBufferSize, 0
    .endif
    MemAlloc dRequiredSize, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov [xsi].pEncryptBuffer, xax
    m2m [xsi].dEncryptBufferSize, dRequiredSize, eax
  .endif

  ; Success
  mov eax, OBJ_OK

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.FreeBuffers
; Purpose:    Frees the reassembly and encryption buffers if allocated.
;             Sets pointers to NULL and capacities to 0.
; Arguments:  None.
; Return:     Nothing.

Method TLS_SChannelContext.FreeBuffers, uses xsi
  SetObject xsi

  ; Free reassembly buffer if allocated
  .if [xsi].pReassemblyBuffer != NULL
    MemFree [xsi].pReassemblyBuffer
    mov [xsi].pReassemblyBuffer, NULL
    mov [xsi].dReassemblyCapacity, 0
    mov [xsi].dReassemblyUsed, 0
  .endif

  ; Free encryption buffer if allocated
  .if [xsi].pEncryptBuffer != NULL
    MemFree [xsi].pEncryptBuffer
    mov [xsi].pEncryptBuffer, NULL
    mov [xsi].dEncryptBufferSize, 0
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.GetState
; Purpose:    Returns the current TLS state.
; Arguments:  None.
; Return:     eax = TLS_STATE_xxx constant.

Method TLS_SChannelContext.GetState, uses xsi
  SetObject xsi
  mov eax, [xsi].dState
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.Encrypt
; Purpose:    Encrypts plaintext data using SChannel EncryptMessage.
;             Validates that dSize does not exceed cbMaximumMessage (caller is responsible for
;             fragmenting larger payloads). Copies plaintext into the encryption buffer at the
;             correct offset, builds a SecBufferDesc with 4 SecBuffers (STREAM_HEADER, DATA,
;             STREAM_TRAILER, EMPTY), and calls EncryptMessage. On success, ppOutput receives
;             a pointer to pEncryptBuffer and pdOutputSize receives the total encrypted size
;             (header + data + trailer). The caller must copy/send the output before the next
;             Encrypt call, as pEncryptBuffer is reused.
; Arguments:  Arg1: -> Plaintext data.
;             Arg2: Plaintext size in bytes (must be <= cbMaximumMessage).
;             Arg3: -> POINTER to receive encrypted output pointer.
;             Arg4: -> DWORD to receive encrypted output size.
; Return:     eax = OBJ_OK on success, TLS_ENCRYPT_ERROR on failure.

Method TLS_SChannelContext.Encrypt, uses xbx xdi xsi, pPlaintext:POINTER, dSize:DWORD, ppOutput:POINTER, pdOutputSize:POINTER
  local Buffers[4]:SecBuffer
  local BufferDesc:SecBufferDesc

  SetObject xsi

  ; Only an established session can encrypt
  .if [xsi].pEncryptBuffer == NULL || [xsi].dState != TLS_STATE_DATA
    mov eax, TLS_ENCRYPT_ERROR
    jmp @@Exit
  .endif

  ; Validate: dSize must not exceed cbMaximumMessage
  mov eax, dSize
  .if eax > [xsi].StreamSizes.cbMaximumMessage
    mov eax, TLS_ENCRYPT_ERROR
    jmp @@Exit
  .endif

  ; Copy plaintext data to pEncryptBuffer + cbHeader
  mov xdi, [xsi].pEncryptBuffer
  mov eax, [xsi].StreamSizes.cbHeader
  add xdi, xax                                    ; xdi = destination for plaintext
  invoke MemClone, xdi, pPlaintext, dSize          ; Copy plaintext to encryption buffer

  ; Set up SecBufferDesc with 4 SecBuffers
  mov BufferDesc.ulVersion, SECBUFFER_VERSION
  mov BufferDesc.cBuffers, 4
  lea xax, Buffers
  mov BufferDesc.pBuffers, xax

  ; Buffer 0: Stream Header
  m2m Buffers[0 * sizeof SecBuffer].cbBuffer, [xsi].StreamSizes.cbHeader, eax
  mov Buffers[0 * sizeof SecBuffer].BufferType, SECBUFFER_STREAM_HEADER
  m2m Buffers[0 * sizeof SecBuffer].pvBuffer, [xsi].pEncryptBuffer, xax

  ; Buffer 1: Data (plaintext to encrypt)
  m2m Buffers[1 * sizeof SecBuffer].cbBuffer, dSize, eax
  mov Buffers[1 * sizeof SecBuffer].BufferType, SECBUFFER_DATA
  mov Buffers[1 * sizeof SecBuffer].pvBuffer, xdi ; Points to plaintext position in encrypt buffer

  ; Buffer 2: Stream Trailer
  m2m Buffers[2 * sizeof SecBuffer].cbBuffer, [xsi].StreamSizes.cbTrailer, eax
  mov Buffers[2 * sizeof SecBuffer].BufferType, SECBUFFER_STREAM_TRAILER
  ; Trailer position = pEncryptBuffer + cbHeader + dSize
  mov xax, [xsi].pEncryptBuffer
  mov ebx, [xsi].StreamSizes.cbHeader
  add xax, xbx
  mov ebx, dSize
  add xax, xbx
  mov Buffers[2 * sizeof SecBuffer].pvBuffer, xax

  ; Buffer 3: Empty
  mov Buffers[3 * sizeof SecBuffer].cbBuffer, 0
  mov Buffers[3 * sizeof SecBuffer].BufferType, SECBUFFER_EMPTY
  mov Buffers[3 * sizeof SecBuffer].pvBuffer, NULL

  ; Call EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo)
  lea xbx, [xsi].hSecurityContext
  invoke EncryptMessage, xbx, 0, addr BufferDesc, 0

  ; Check result (SEC_E_OK = 0)
  .if eax != 0
    mov [xsi].dLastError, eax
;   DbgWarning "TLS: EncryptMessage failed"
    mov eax, TLS_ENCRYPT_ERROR
    jmp @@Exit
  .endif

  ; Calculate total output size: header + data + trailer
  mov eax, Buffers[0 * sizeof SecBuffer].cbBuffer
  add eax, Buffers[1 * sizeof SecBuffer].cbBuffer
  add eax, Buffers[2 * sizeof SecBuffer].cbBuffer

  ; Store output pointer and size
  mov xbx, ppOutput
  mov xcx, [xsi].pEncryptBuffer
  mov [xbx], xcx                                  ; *ppOutput = pEncryptBuffer
  mov xbx, pdOutputSize
  mov [xbx], eax                                  ; *pdOutputSize = total size

  mov eax, OBJ_OK

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.Decrypt
; Purpose:    Decrypts ciphertext data using SChannel DecryptMessage with TLS record reassembly.
;             Incoming ciphertext is appended to the internal reassembly buffer, then
;             DecryptMessage is called. On success (SEC_E_OK), the plaintext pointer is returned
;             pointing directly into the reassembly buffer (caller must consume before next call).
;             On SEC_E_INCOMPLETE_MESSAGE, returns 0 bytes (need more data, not an error).
;             On SEC_I_RENEGOTIATE, transitions to TLS_STATE_HANDSHAKE.
;             On SEC_I_CONTEXT_EXPIRED, transitions to TLS_STATE_SHUTDOWN.
;             On any other error, transitions to TLS_STATE_ERROR.
;             SECBUFFER_EXTRA data is moved to the start of the reassembly buffer for the next
;             record (overlap-safe via MemMove).
; Arguments:  Arg1: -> Ciphertext data.
;             Arg2: Ciphertext size in bytes.
;             Arg3: -> POINTER to receive plaintext output (points into reassembly buffer).
;             Arg4: -> DWORD to receive plaintext output size.
; Return:     eax = OBJ_OK on success, TLS_DECRYPT_ERROR on fatal error.
; Notes:      The plaintext pointer returned in ppPlaintext points INTO the reassembly buffer.
;             The caller must consume the plaintext before the next Decrypt call.

Method TLS_SChannelContext.Decrypt, uses xbx xdi xsi, pCiphertext:POINTER, dSize:DWORD, ppPlaintext:POINTER, pdPlaintextSize:POINTER
  local Buffers[4]:SecBuffer
  local BufferDesc:SecBufferDesc
  local dStatus:DWORD

  SetObject xsi

  ; Data is already in the reassembly buffer (copied by OnReceivedTLS drain loop).
  ; pCiphertext/dSize point to pReassemblyBuffer/dReassemblyUsed (passed for interface compatibility).
  ; No copy needed - proceed directly to decryption.

  ; --- Set up SecBufferDesc with 4 SecBuffers ---
  mov BufferDesc.ulVersion, SECBUFFER_VERSION
  mov BufferDesc.cBuffers, 4
  lea xax, Buffers
  mov BufferDesc.pBuffers, xax

  ; Buffer[0]: SECBUFFER_DATA with reassembly content
  m2m Buffers[0 * sizeof SecBuffer].cbBuffer, [xsi].dReassemblyUsed, eax
  mov Buffers[0 * sizeof SecBuffer].BufferType, SECBUFFER_DATA
  m2m Buffers[0 * sizeof SecBuffer].pvBuffer, [xsi].pReassemblyBuffer, xax

  ; Buffer[1]: SECBUFFER_EMPTY
  mov Buffers[1 * sizeof SecBuffer].cbBuffer, 0
  mov Buffers[1 * sizeof SecBuffer].BufferType, SECBUFFER_EMPTY
  mov Buffers[1 * sizeof SecBuffer].pvBuffer, NULL

  ; Buffer[2]: SECBUFFER_EMPTY
  mov Buffers[2 * sizeof SecBuffer].cbBuffer, 0
  mov Buffers[2 * sizeof SecBuffer].BufferType, SECBUFFER_EMPTY
  mov Buffers[2 * sizeof SecBuffer].pvBuffer, NULL

  ; Buffer[3]: SECBUFFER_EMPTY
  mov Buffers[3 * sizeof SecBuffer].cbBuffer, 0
  mov Buffers[3 * sizeof SecBuffer].BufferType, SECBUFFER_EMPTY
  mov Buffers[3 * sizeof SecBuffer].pvBuffer, NULL

  ; --- Step 3: Call DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP) ---
  lea xbx, [xsi].hSecurityContext
  invoke DecryptMessage, xbx, addr BufferDesc, 0, NULL
  mov dStatus, eax

  ; --- Step 4: Handle results ---
  .if dStatus == SEC_E_OK
    ; --- SEC_E_OK: Extract plaintext from SECBUFFER_DATA ---
    ; Scan buffers for SECBUFFER_DATA
    mov xbx, ppPlaintext
    mov POINTER ptr [xbx], NULL                   ; Default: no plaintext found
    mov xbx, pdPlaintextSize
    mov DWORD ptr [xbx], 0

    lea xdi, Buffers
    xor ecx, ecx                                  ; Buffer index
  @@FindData:
    .if ecx >= 4
      jmp @@DataFound
    .endif
    .if [xdi].SecBuffer.BufferType == SECBUFFER_DATA
      ; Found plaintext data
      mov xbx, ppPlaintext
      mov xax, [xdi].SecBuffer.pvBuffer
      mov [xbx], xax                             ; *ppPlaintext = DATA buffer pvBuffer
      mov xbx, pdPlaintextSize
      mov eax, [xdi].SecBuffer.cbBuffer
      mov [xbx], eax                             ; *pdPlaintextSize = DATA buffer cbBuffer
      jmp @@DataFound
    .endif
    add xdi, sizeof SecBuffer
    inc ecx
    jmp @@FindData
  @@DataFound:

    ; Scan buffers for SECBUFFER_EXTRA
    lea xdi, Buffers
    xor ecx, ecx
  @@FindExtra:
    .if ecx >= 4
      ; No EXTRA buffer found - all data consumed
      mov [xsi].dReassemblyUsed, 0
      jmp @@Success
    .endif
    .if [xdi].SecBuffer.BufferType == SECBUFFER_EXTRA
      ; SECBUFFER_EXTRA found: defer the shift - plaintext pointer is still valid in buffer!
      ; Store EXTRA size and source pointer for caller to shift after copying plaintext.
      mov eax, [xdi].SecBuffer.cbBuffer
      mov [xsi].dReassemblyUsed, eax
      ; Do NOT shift here - pPlaintext still points into the buffer!
      ; Caller (OnReceivedTLS) will call MemShift after copying plaintext.
      m2m [xsi].pDeferredExtra, [xdi].SecBuffer.pvBuffer, xax
      jmp @@Success
    .endif
    add xdi, sizeof SecBuffer
    inc ecx
    jmp @@FindExtra

  @@Success:
    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_E_INCOMPLETE_MESSAGE
    ; --- SEC_E_INCOMPLETE_MESSAGE: Need more data ---
    mov xbx, ppPlaintext
    mov POINTER ptr [xbx], NULL
    mov xbx, pdPlaintextSize
    mov DWORD ptr [xbx], 0
    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_I_RENEGOTIATE
    ; --- SEC_I_RENEGOTIATE: Transition to handshake state ---
    mov [xsi].dState, TLS_STATE_HANDSHAKE
    mov xbx, ppPlaintext
    mov POINTER ptr [xbx], NULL
    mov xbx, pdPlaintextSize
    mov DWORD ptr [xbx], 0

    ; Handle SECBUFFER_EXTRA if present
    lea xdi, Buffers
    xor ecx, ecx
  @@FindExtraRenego:
    .if ecx >= 4
      mov [xsi].dReassemblyUsed, 0
      jmp @@RenegoExit
    .endif
    .if [xdi].SecBuffer.BufferType == SECBUFFER_EXTRA
      mov eax, [xdi].SecBuffer.cbBuffer
      mov [xsi].dReassemblyUsed, eax
      invoke MemShift, [xsi].pReassemblyBuffer, [xdi].SecBuffer.pvBuffer, [xsi].dReassemblyUsed
      jmp @@RenegoExit
    .endif
    add xdi, sizeof SecBuffer
    inc ecx
    jmp @@FindExtraRenego
  @@RenegoExit:
    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_I_CONTEXT_EXPIRED
    ; --- SEC_I_CONTEXT_EXPIRED: Peer initiated shutdown ---
    mov [xsi].dState, TLS_STATE_SHUTDOWN
    mov xbx, ppPlaintext
    mov POINTER ptr [xbx], NULL
    mov xbx, pdPlaintextSize
    mov DWORD ptr [xbx], 0
    mov eax, OBJ_OK
    jmp @@Exit

  .else
    ; --- Any other error: Fatal ---
    mov [xsi].dState, TLS_STATE_ERROR
    m2m [xsi].dLastError, dStatus, eax
;   DbgWarning "TLS: DecryptMessage failed"
    mov xbx, ppPlaintext
    mov POINTER ptr [xbx], NULL
    mov xbx, pdPlaintextSize
    mov DWORD ptr [xbx], 0
    mov eax, TLS_DECRYPT_ERROR
    jmp @@Exit
  .endif

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.SendToken
; Purpose:    Sends an SSPI output token (handshake message, alert or shutdown token) unencrypted
;             to the peer and releases the SSPI allocated memory.
; Arguments:  Arg1: -> SecBuffer (pvBuffer allocated by SSPI or NULL).
; Return:     Nothing. The SecBuffer is reset (pvBuffer = NULL, cbBuffer = 0).

Method TLS_SChannelContext.SendToken, uses xbx xsi, pSecBuf:POINTER
  SetObject xsi
  mov xbx, pSecBuf
  .if [xbx].SecBuffer.pvBuffer != NULL
    .if [xbx].SecBuffer.cbBuffer != 0 && [xsi].pConnection != NULL
      OCall [xsi].pConnection::NetComConnection.QueueSendRaw, \
            [xbx].SecBuffer.pvBuffer, [xbx].SecBuffer.cbBuffer
    .endif
    invoke FreeContextBuffer, [xbx].SecBuffer.pvBuffer
    mov [xbx].SecBuffer.pvBuffer, NULL
    mov [xbx].SecBuffer.cbBuffer, 0
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.FreeToken
; Purpose:    Releases an SSPI output token without sending it.
; Arguments:  Arg1: -> SecBuffer.
; Return:     Nothing.

Method TLS_SChannelContext.FreeToken, uses xbx, pSecBuf:POINTER
  mov xbx, pSecBuf
  .if [xbx].SecBuffer.pvBuffer != NULL
    invoke FreeContextBuffer, [xbx].SecBuffer.pvBuffer
    mov [xbx].SecBuffer.pvBuffer, NULL
    mov [xbx].SecBuffer.cbBuffer, 0
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.KeepExtra
; Purpose:    Moves unconsumed input (SECBUFFER_EXTRA) to the start of the reassembly buffer and
;             sets dReassemblyUsed accordingly. If there is no EXTRA buffer, all input was
;             consumed and dReassemblyUsed is set to 0.
; Arguments:  Arg1: -> SecBuffer that may have become SECBUFFER_EXTRA (InBuffers[1]).
;             Arg2: -> Input data passed to ISC/ASC.
;             Arg3: Input data size.
; Return:     Nothing.
; Note:       Must be called BEFORE AllocateBuffers may reallocate the reassembly buffer.

Method TLS_SChannelContext.KeepExtra, uses xbx xsi, pExtraBuf:POINTER, pData:POINTER, dDataSize:DWORD
  SetObject xsi
  mov xbx, pExtraBuf
  .if [xbx].SecBuffer.BufferType == SECBUFFER_EXTRA && [xbx].SecBuffer.cbBuffer != 0
    ; Extra data is at (pData + dDataSize - ExtraBuffer.cbBuffer)
    mov eax, [xbx].SecBuffer.cbBuffer
    mov [xsi].dReassemblyUsed, eax
    mov ecx, dDataSize
    sub ecx, eax
    mov xdx, pData
    add xdx, xcx                                        ;xdx -> start of extra data
    invoke MemShift, [xsi].pReassemblyBuffer, xdx, [xsi].dReassemblyUsed
  .else
    mov [xsi].dReassemblyUsed, 0                        ;All data consumed
  .endif
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.ValidatePeer
; Purpose:    Validates the peer certificate after a completed handshake. Fails closed:
;             - Client: a server certificate and a validator are mandatory (SChannel does not
;               validate anything itself because of ISC_REQ_MANUAL_CRED_VALIDATION). If
;               bVerifyServerName is set, a target name is mandatory, too.
;             - Server: only with bMutualAuth. Then a client certificate and a validator are
;               mandatory; the certificate is checked with TLS_CertValidator.ValidateClient.
; Arguments:  None.
; Return:     eax = OBJ_OK or TLS_CERTIFICATE_INVALID (reason in dLastError).

Method TLS_SChannelContext.ValidatePeer, uses xbx xsi
  local pCertContext:POINTER, dResult:DWORD

  SetObject xsi
  mov pCertContext, NULL
  mov dResult, TLS_CERTIFICATE_INVALID

  .if [xsi].bIsClient == FALSE
    ; --- Server side ---
    .if [xsi].bMutualAuth == FALSE
      mov dResult, OBJ_OK                               ;No client certificate requested
      jmp @@Exit
    .endif
  .endif

  ; A validator is mandatory
  .if [xsi].pCertValidator == NULL
    mov [xsi].dLastError, CERT_E_UNTRUSTEDROOT
    jmp @@Exit
  .endif

  ; Get the peer certificate (it MUST exist)
  lea xbx, [xsi].hSecurityContext
  invoke QueryContextAttributesA, xbx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, addr pCertContext
  .if eax != SEC_E_OK
    mov [xsi].dLastError, eax
    mov pCertContext, NULL
    jmp @@Exit
  .endif
  .if pCertContext == NULL
    mov [xsi].dLastError, SEC_E_CERT_UNKNOWN
    jmp @@Exit
  .endif

  .if [xsi].bIsClient != FALSE
    ; --- Client side: validate the server certificate ---
    .if [xsi].bVerifyServerName != FALSE
      .if [xsi].pTargetName == NULL
        ; Hostname check requested, but no hostname known => fail closed
        mov [xsi].dLastError, CERT_E_CN_NO_MATCH
        jmp @@Exit
      .endif
      OCall [xsi].pCertValidator::TLS_CertValidator.Validate, pCertContext, [xsi].pTargetName
    .else
      OCall [xsi].pCertValidator::TLS_CertValidator.Validate, pCertContext, NULL
    .endif
  .else
    ; --- Server side: validate the client certificate ---
    OCall [xsi].pCertValidator::TLS_CertValidator.ValidateClient, pCertContext
  .endif
  .if eax != 0
    mov [xsi].dLastError, eax
  .else
    mov dResult, OBJ_OK
  .endif

@@Exit:
  .if pCertContext != NULL
    invoke CertFreeCertificateContext, pCertContext
  .endif
  mov eax, dResult
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.ProcessHandshakeData
; Purpose:    Processes incoming handshake data. Branches based on bIsClient flag:
;             - Client (bIsClient=TRUE): Uses InitializeSecurityContext continuation calls.
;             - Server (bIsClient=FALSE): Uses AcceptSecurityContext.
;             Handles SEC_I_CONTINUE_NEEDED, SEC_E_OK, SEC_I_INCOMPLETE_CREDENTIALS,
;             SEC_E_INCOMPLETE_MESSAGE, SECBUFFER_EXTRA, and error conditions.
;             On completion: peer validation (fail closed), stream sizes, buffers, state DATA.
;             OnHandshakeComplete is only fired for the first handshake, not for
;             renegotiations or TLS 1.3 post-handshake messages.
; Arguments:  Arg1: -> Handshake data received from peer.
;             Arg2: Data size in bytes.
;             Arg3: -> NetComConnection (for sending reply tokens and callbacks).
; Return:     eax = OBJ_OK on success, error code on failure.

Method TLS_SChannelContext.ProcessHandshakeData, uses xbx xdi xsi, pData:POINTER, dDataSize:DWORD, pConnection:POINTER
  local InBuffers[2]:SecBuffer
  local InBufferDesc:SecBufferDesc
  local OutBuffer:SecBuffer
  local OutBufferDesc:SecBufferDesc
  local dwSSPIOutFlags:DWORD
  local dContextReq:DWORD
  local tsExpiry:TimeStamp
  local dStatus:DWORD
  local pCertContext:POINTER
  local SchannelCred:SCHANNEL_CRED
  local tsCredExpiry:TimeStamp
  local pSNIHostname:POINTER
  local dSNILen:DWORD
  local bClientCertTried:DWORD
  local dFailCode:DWORD

  SetObject xsi

  ; Store connection pointer
  m2m [xsi].pConnection, pConnection, xax
  mov bClientCertTried, FALSE

  ; Branch: Client vs Server
  .if [xsi].bIsClient == FALSE
    jmp @@ServerPath
  .endif

  ; ===========================================================================
  ; CLIENT PATH: InitializeSecurityContext continuation
  ; ===========================================================================
@@RetryISC:
  ; --- Build input SecBufferDesc ---
  mov InBufferDesc.ulVersion, SECBUFFER_VERSION
  mov InBufferDesc.cBuffers, 2
  lea xax, InBuffers
  mov InBufferDesc.pBuffers, xax

  ; InBuffer[0]: SECBUFFER_TOKEN with handshake data (already in reassembly buffer)
  m2m InBuffers[0 * sizeof SecBuffer].cbBuffer, dDataSize, eax
  mov InBuffers[0 * sizeof SecBuffer].BufferType, SECBUFFER_TOKEN
  m2m InBuffers[0 * sizeof SecBuffer].pvBuffer, pData, xax

  ; InBuffer[1]: SECBUFFER_EMPTY (for SECBUFFER_EXTRA detection)
  mov InBuffers[1 * sizeof SecBuffer].cbBuffer, 0
  mov InBuffers[1 * sizeof SecBuffer].BufferType, SECBUFFER_EMPTY
  mov InBuffers[1 * sizeof SecBuffer].pvBuffer, NULL

  ; --- Build output SecBufferDesc (SSPI allocates memory) ---
  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  ; --- Call InitializeSecurityContextA (continuation - pass existing context) ---
  ; ANSI variant: pTargetName is always stored as ANSI (also in WIDE builds).
  lea xbx, [xsi].hCredential
  lea xdi, [xsi].hSecurityContext
  invoke InitializeSecurityContextA, \
         xbx, \                               ; phCredential
         xdi, \                               ; phContext (existing context for continuation)
         [xsi].pTargetName, \                 ; pszTargetName (hostname for SNI)
         TLS_CLIENT_ISC_FLAGS or ISC_REQ_ALLOCATE_MEMORY, \ ; fContextReq
         0, \                                 ; Reserved1
         0, \                                 ; TargetDataRep
         addr InBufferDesc, \                 ; pInput
         0, \                                 ; Reserved2
         NULL, \                              ; phNewContext (NULL for continuation)
         addr OutBufferDesc, \                ; pOutput
         addr dwSSPIOutFlags, \               ; pfContextAttr
         addr tsExpiry                        ; ptsExpiry
  mov dStatus, eax

  .if dStatus == SEC_I_CONTINUE_NEEDED
    ; --- Send output token, keep unconsumed data, wait for more ---
    OCall xsi.SendToken, addr OutBuffer
    lea xbx, InBuffers
    add xbx, sizeof SecBuffer
    OCall xsi.KeepExtra, xbx, pData, dDataSize
    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_E_OK
    ; --- Handshake complete ---
    OCall xsi.SendToken, addr OutBuffer
    lea xbx, InBuffers
    add xbx, sizeof SecBuffer
    OCall xsi.KeepExtra, xbx, pData, dDataSize        ;BEFORE AllocateBuffers (no use-after-free)
    jmp @@HandshakeComplete

  .elseif dStatus == SEC_I_INCOMPLETE_CREDENTIALS
    ; --- Server requests a client certificate ---
    OCall xsi.FreeToken, addr OutBuffer

    ; Only one attempt - avoid an endless loop if the server rejects our certificate
    .if bClientCertTried != FALSE
      mov [xsi].dLastError, TLS_CLIENT_CERT_NOT_PROVIDED
      jmp @@HandshakeFailed
    .endif
    mov bClientCertTried, TRUE

    .if [xsi].pClientCertProvider == NULL
      mov [xsi].dLastError, TLS_CLIENT_CERT_REQUIRED
      jmp @@HandshakeFailed
    .endif

    OCall [xsi].pClientCertProvider::TLS_ClientCertProvider.GetClientCert
    .if xax == NULL
      mov [xsi].dLastError, TLS_CLIENT_CERT_NOT_PROVIDED
      jmp @@HandshakeFailed
    .endif
    mov pCertContext, xax

    ; Free existing credentials
    .if [xsi].bCredentialValid != FALSE
      lea xbx, [xsi].hCredential
      invoke FreeCredentialsHandle, xbx
      mov [xsi].bCredentialValid, FALSE
    .endif

    ; Recreate credentials with the client certificate
    invoke MemZero, addr SchannelCred, sizeof SCHANNEL_CRED
    mov SchannelCred.dwVersion, SCHANNEL_CRED_VERSION
    mov SchannelCred.cCreds, 1
    lea xax, pCertContext
    mov SchannelCred.paCred, xax
    mov SchannelCred.dwFlags, SCH_CRED_NO_DEFAULT_CREDS or SCH_USE_STRONG_CRYPTO
    mov SchannelCred.dwSessionLifespan, 1
    m2m SchannelCred.grBitEnabledProtocols, [xsi].dAllowedProtocols, eax
    m2m SchannelCred.palgSupportedAlgs, [xsi].pAllowedCipherSuites, xax
    m2m SchannelCred.cSupportedAlgs, [xsi].dCipherSuiteCount, eax

    lea xbx, [xsi].hCredential
    invoke AcquireCredentialsHandleA, \
           NULL, \
           $OfsCStrA("Microsoft Unified Security Protocol Provider"), \
           SECPKG_CRED_OUTBOUND, \
           NULL, \
           addr SchannelCred, \
           NULL, \
           NULL, \
           xbx, \
           addr tsCredExpiry
    mov dStatus, eax

    ; SChannel holds its own reference to the certificate
    invoke CertFreeCertificateContext, pCertContext

    .if dStatus != SEC_E_OK
      m2m [xsi].dLastError, dStatus, eax
      jmp @@HandshakeFailed
    .endif
    mov [xsi].bCredentialValid, TRUE

    ; Retry InitializeSecurityContext with the same input data
    jmp @@RetryISC

  .elseif dStatus == SEC_E_INCOMPLETE_MESSAGE
    ; --- Need more data from server ---
    ; dReassemblyUsed stays unchanged - caller will append more data on next call.
    OCall xsi.FreeToken, addr OutBuffer
    mov eax, OBJ_OK
    jmp @@Exit

  .else
    ; --- Any other status: Handshake failed ---
    ; Covers protocol version rejection and cipher suite mismatch (SEC_E_ALGORITHM_MISMATCH).
    ; With ISC_REQ_EXTENDED_ERROR the output token may contain an alert for the peer.
    OCall xsi.SendToken, addr OutBuffer
    m2m [xsi].dLastError, dStatus, eax
    jmp @@HandshakeFailed
  .endif


  ; ===========================================================================
  ; SERVER PATH: AcceptSecurityContext
  ; ===========================================================================
@@ServerPath:

  ; --- SNI Extraction and Credential Initialization (first call only) ---
  .if [xsi].bCredentialValid == FALSE
    ; SslGetServerIdentity needs the complete ClientHello record. Large ClientHellos (e.g. with
    ; post-quantum key shares) often span several TCP segments => wait for the whole record,
    ; otherwise the SNI is lost and the credentials are created for the wrong certificate.
    ; dReassemblyUsed stays unchanged, OnReceivedTLS appends more data and calls again.
    .if dDataSize < 5
      mov eax, OBJ_OK
      jmp @@Exit
    .endif
    mov xax, pData
    .if BYTE ptr [xax] == 16h                           ;TLS handshake record
      movzx ecx, BYTE ptr [xax + 3]                     ;Record length (big endian)
      shl ecx, 8
      mov cl, BYTE ptr [xax + 4]
      add ecx, 5                                        ;+ record header
      .if ecx <= TLS_MAX_RECORD_SIZE && ecx > dDataSize ;Oversized: let ASC reject it
        mov eax, OBJ_OK
        jmp @@Exit
      .endif
    .endif

    ; Extract SNI hostname from ClientHello using SslGetServerIdentity
    mov pSNIHostname, NULL
    mov dSNILen, 0
    invoke SslGetServerIdentity, pData, dDataSize, addr pSNIHostname, addr dSNILen, 0
    ; SEC_E_OK = SNI found, pSNIHostname points INTO pData buffer (no alloc needed)
    ; Any other status = no SNI, pSNIHostname stays NULL

    ; Initialize server credentials with SNI info for certificate selection
    OCall xsi.InitCredentials, SECPKG_CRED_INBOUND, pSNIHostname, dSNILen
    .if eax != OBJ_OK
      mov [xsi].dLastError, eax
      jmp @@HandshakeFailed
    .endif
  .endif

  ; --- Build input SecBufferDesc for AcceptSecurityContext ---
  mov InBufferDesc.ulVersion, SECBUFFER_VERSION
  mov InBufferDesc.cBuffers, 2
  lea xax, InBuffers
  mov InBufferDesc.pBuffers, xax

  m2m InBuffers[0 * sizeof SecBuffer].cbBuffer, dDataSize, eax
  mov InBuffers[0 * sizeof SecBuffer].BufferType, SECBUFFER_TOKEN
  m2m InBuffers[0 * sizeof SecBuffer].pvBuffer, pData, xax

  mov InBuffers[1 * sizeof SecBuffer].cbBuffer, 0
  mov InBuffers[1 * sizeof SecBuffer].BufferType, SECBUFFER_EMPTY
  mov InBuffers[1 * sizeof SecBuffer].pvBuffer, NULL

  ; --- Build output SecBufferDesc (SSPI allocates memory, ASC_REQ_ALLOCATE_MEMORY) ---
  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  ; --- Server context flags: request a client certificate only with mutual auth ---
  mov eax, TLS_SERVER_ASC_FLAGS
  .if [xsi].bMutualAuth != FALSE
    or eax, ASC_REQ_MUTUAL_AUTH
  .endif
  mov dContextReq, eax

  ; --- Call AcceptSecurityContext ---
  lea xbx, [xsi].hCredential
  lea xdi, [xsi].hSecurityContext
  .if [xsi].bContextValid == FALSE
    ; First call: phContext = NULL, phNewContext = &hSecurityContext
    invoke AcceptSecurityContext, \
           xbx, \                               ; phCredential
           NULL, \                              ; phContext (NULL for first call)
           addr InBufferDesc, \                 ; pInput
           dContextReq, \                       ; fContextReq
           0, \                                 ; TargetDataRep (not used with stream)
           xdi, \                               ; phNewContext
           addr OutBufferDesc, \                ; pOutput
           addr dwSSPIOutFlags, \               ; pfContextAttr
           addr tsExpiry                        ; ptsExpiry
  .else
    ; Continuation call: phContext = &hSecurityContext
    invoke AcceptSecurityContext, \
           xbx, \                               ; phCredential
           xdi, \                               ; phContext (existing context)
           addr InBufferDesc, \                 ; pInput
           dContextReq, \                       ; fContextReq
           0, \                                 ; TargetDataRep
           NULL, \                              ; phNewContext (NULL for continuation)
           addr OutBufferDesc, \                ; pOutput
           addr dwSSPIOutFlags, \               ; pfContextAttr
           addr tsExpiry                        ; ptsExpiry
  .endif
  mov dStatus, eax

  .if dStatus == SEC_I_CONTINUE_NEEDED
    mov [xsi].bContextValid, TRUE
    OCall xsi.SendToken, addr OutBuffer
    lea xbx, InBuffers
    add xbx, sizeof SecBuffer
    OCall xsi.KeepExtra, xbx, pData, dDataSize
    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_E_OK
    mov [xsi].bContextValid, TRUE
    OCall xsi.SendToken, addr OutBuffer
    lea xbx, InBuffers
    add xbx, sizeof SecBuffer
    OCall xsi.KeepExtra, xbx, pData, dDataSize        ;BEFORE AllocateBuffers (no use-after-free)
    jmp @@HandshakeComplete

  .elseif dStatus == SEC_E_INCOMPLETE_MESSAGE
    OCall xsi.FreeToken, addr OutBuffer
    mov eax, OBJ_OK
    jmp @@Exit

  .else
    ; Covers protocol version rejection and cipher suite mismatch (SEC_E_ALGORITHM_MISMATCH).
    OCall xsi.SendToken, addr OutBuffer               ;Alert for the peer, if any
    m2m [xsi].dLastError, dStatus, eax
    jmp @@HandshakeFailed
  .endif


  ; ===========================================================================
  ; Handshake complete (client and server)
  ; ===========================================================================
@@HandshakeComplete:
  ; (a) Validate the peer certificate BEFORE the session becomes usable (fail closed)
  OCall xsi.ValidatePeer
  .if eax != OBJ_OK
    mov dFailCode, TLS_CERTIFICATE_INVALID
    jmp @@Fail
  .endif

  ; (b) QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES) -> StreamSizes
  lea xbx, [xsi].hSecurityContext
  lea xdi, [xsi].StreamSizes
  invoke QueryContextAttributesA, xbx, SECPKG_ATTR_STREAM_SIZES, xdi
  .if eax != SEC_E_OK
    mov [xsi].dLastError, eax
    jmp @@HandshakeFailed
  .endif

  ; (c) Buffers based on StreamSizes (content of the reassembly buffer is preserved)
  OCall xsi.AllocateBuffers
  .if eax != OBJ_OK
    mov [xsi].dLastError, eax
    jmp @@HandshakeFailed
  .endif

  ; Publish max plaintext size to base class for polymorphic access
  m2m [xsi].dMaxMessageSize, [xsi].StreamSizes.cbMaximumMessage, eax

  ; (d) Session established
  mov [xsi].dState, TLS_STATE_DATA

  ; (e) Notify the protocol - only for the initial handshake
  .if [xsi].bHandshakeDone == FALSE
    mov [xsi].bHandshakeDone, TRUE
    mov xbx, pConnection
    mov xbx, [xbx].$Obj(NetComConnection).pProtocol
    OCall xbx::NetComProtocol.OnHandshakeComplete, pConnection
  .endif
  mov eax, OBJ_OK
  jmp @@Exit


  ; ===========================================================================
  ; Handshake failed (client and server)
  ; ===========================================================================
@@HandshakeFailed:
  mov dFailCode, TLS_HANDSHAKE_FAILED
@@Fail:
  ; The original SECURITY_STATUS / HRESULT is preserved in dLastError (see TranslateError).
  mov [xsi].dState, TLS_STATE_ERROR
  mov xbx, pConnection
  mov xbx, [xbx].$Obj(NetComConnection).pProtocol
  OCall xbx::NetComProtocol.OnHandshakeFailed, pConnection, [xsi].dLastError
  mov xbx, pConnection
  mov xbx, [xbx].$Obj(NetComConnection).pProtocol
  OCall xbx::NetComProtocol.OnError, pConnection, NULL, dFailCode
  ; Close connection
  OCall pConnection::NetComConnection.Disconnect, SD_BOTH
  mov eax, dFailCode

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.StartClientHandshake
; Purpose:    Initiates a TLS client handshake.
;             Sets state to TLS_STATE_HANDSHAKE, initializes client credentials (anonymous),
;             calls InitializeSecurityContext (first call, no input buffer) to generate the
;             initial handshake token, and sends it via NetComConnection.QueueSendRaw.
; Arguments:  Arg1: -> NetComConnection.
; Return:     eax = OBJ_OK on success, error code on failure.

Method TLS_SChannelContext.StartClientHandshake, uses xbx xdi xsi, pConnection:POINTER
  local OutBuffer:SecBuffer
  local OutBufferDesc:SecBufferDesc
  local dwSSPIOutFlags:DWORD
  local tsExpiry:TimeStamp

  SetObject xsi

  ; Set client mode flag
  mov [xsi].bIsClient, TRUE
  mov [xsi].bHandshakeDone, FALSE

  ; Store connection pointer for later use in ProcessHandshakeData
  m2m [xsi].pConnection, pConnection, xax

  ; Transition state: NONE -> HANDSHAKE
  mov [xsi].dState, TLS_STATE_HANDSHAKE

  ; Initialize client credentials (SECPKG_CRED_OUTBOUND, anonymous - no cert)
  OCall xsi.InitCredentials, SECPKG_CRED_OUTBOUND, NULL, 0
  .if eax != OBJ_OK
    mov [xsi].dState, TLS_STATE_ERROR
    jmp @@Exit
  .endif

  ; Allocate reassembly buffer early for handshake data accumulation.
  ; It must hold at least one complete TLS record (header + 16K + expansion).
  .if [xsi].pReassemblyBuffer == NULL
    MemAlloc TLS_MAX_RECORD_SIZE, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov [xsi].pReassemblyBuffer, xax
    mov [xsi].dReassemblyCapacity, TLS_MAX_RECORD_SIZE
    mov [xsi].dReassemblyUsed, 0
  .endif

  ; Prepare output SecBufferDesc for InitializeSecurityContext
  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  ; Call InitializeSecurityContextA (first call - pContext=NULL, pInput=NULL)
  lea xbx, [xsi].hCredential
  lea xdi, [xsi].hSecurityContext
  invoke InitializeSecurityContextA, \
         xbx, \                               ; phCredential
         NULL, \                              ; phContext (NULL for first call)
         [xsi].pTargetName, \                 ; pszTargetName (ANSI hostname for SNI, or NULL)
         TLS_CLIENT_ISC_FLAGS or ISC_REQ_ALLOCATE_MEMORY, \ ; fContextReq
         0, \                                 ; Reserved1
         0, \                                 ; TargetDataRep (not used with stream)
         NULL, \                              ; pInput (NULL for first call)
         0, \                                 ; Reserved2
         xdi, \                               ; phNewContext
         addr OutBufferDesc, \                ; pOutput
         addr dwSSPIOutFlags, \               ; pfContextAttr
         addr tsExpiry                        ; ptsExpiry

  .if eax == SEC_I_CONTINUE_NEEDED || eax == SEC_E_OK
    ; Context handle is now valid
    mov [xsi].bContextValid, TRUE
    OCall xsi.SendToken, addr OutBuffer               ;ClientHello
    mov eax, OBJ_OK
  .else
    ; InitializeSecurityContext failed on first call
    mov [xsi].dLastError, eax
    mov [xsi].dState, TLS_STATE_ERROR
    OCall xsi.FreeToken, addr OutBuffer
    mov eax, TLS_HANDSHAKE_FAILED
  .endif

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.StartServerHandshake
; Purpose:    Initiates a TLS server handshake.
;             Sets bIsClient=FALSE, transitions state to TLS_STATE_HANDSHAKE,
;             initializes server credentials (SECPKG_CRED_INBOUND) using the configured
;             TLS_ServerCertProvider. Unlike client, the server does NOT generate an initial
;             token — it waits for the client's ClientHello.
; Arguments:  Arg1: -> NetComConnection.
; Return:     eax = OBJ_OK on success, error code on failure.
; Notes:      The server certificate is obtained during InitCredentials via the
;             TLS_ServerCertProvider. A valid certificate with a private key is required.

Method TLS_SChannelContext.StartServerHandshake, uses xbx xsi, pConnection:POINTER
  SetObject xsi

  ; Set server mode flag
  mov [xsi].bIsClient, FALSE
  mov [xsi].bHandshakeDone, FALSE

  ; Store connection pointer for later use in ProcessHandshakeData
  m2m [xsi].pConnection, pConnection, xax

  ; Transition state: NONE → HANDSHAKE
  mov [xsi].dState, TLS_STATE_HANDSHAKE

  ; Initialize server credentials: DEFERRED to ProcessHandshakeData (SNI support).
  ; Credentials will be created after extracting SNI from the ClientHello,
  ; allowing GetServerCert to receive the hostname for multi-vhost selection.

  ; Allocate reassembly buffer early for handshake data accumulation.
  ; It must hold at least one complete TLS record (header + 16K + expansion).
  .if [xsi].pReassemblyBuffer == NULL
    MemAlloc TLS_MAX_RECORD_SIZE, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov [xsi].pReassemblyBuffer, xax
    mov [xsi].dReassemblyCapacity, TLS_MAX_RECORD_SIZE
    mov [xsi].dReassemblyUsed, 0
  .endif

  ; Server is now in HANDSHAKE state, waiting for client's ClientHello
  ; No initial token is sent — the server waits passively
  mov eax, OBJ_OK

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.Shutdown
; Purpose:    Initiates TLS shutdown sequence.
;             Applies the SCHANNEL_SHUTDOWN control token to the security context, then calls
;             InitializeSecurityContext (client) or AcceptSecurityContext (server) to generate
;             the shutdown token. The token is sent to the peer via QueueSendRaw, and the state
;             transitions to TLS_STATE_SHUTDOWN.
; Arguments:  Arg1: -> NetComConnection.
; Return:     eax = OBJ_OK on success, TLS_HANDSHAKE_FAILED on failure.

Method TLS_SChannelContext.Shutdown, uses xbx xdi xsi, pConnection:POINTER
  local ShutdownToken:DWORD
  local OutBuffer:SecBuffer
  local OutBufferDesc:SecBufferDesc
  local tsExpiry:TimeStamp
  local dOutAttrs:DWORD

  SetObject xsi

  ; Guard: Without a security context there is nothing to shut down
  .if [xsi].bContextValid == FALSE
    mov [xsi].dState, TLS_STATE_SHUTDOWN
    mov eax, OBJ_OK
    jmp @@Exit
  .endif

  ; Guard: If state is already TLS_STATE_SHUTDOWN (set by DecryptMessage on
  ; SEC_I_CONTEXT_EXPIRED when peer sent close_notify), skip ApplyControlToken.
  ; The security context already knows it's shutting down � we only need to
  ; generate our response token via ISC/ASC.
  .if [xsi].dState == TLS_STATE_SHUTDOWN
    jmp @@GenerateToken
  .endif

  ; Set the shutdown token type
  mov ShutdownToken, SCHANNEL_SHUTDOWN

  ; Build a SecBufferDesc containing the shutdown token
  ; This is the input token for ApplyControlToken
  mov OutBuffer.cbBuffer, sizeof DWORD
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  lea xax, ShutdownToken
  mov OutBuffer.pvBuffer, xax

  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax

  ; Apply the shutdown control token to the security context
  lea xbx, [xsi].hSecurityContext
  invoke ApplyControlToken, xbx, addr OutBufferDesc

  .if eax != 0
    ; ApplyControlToken failed - set error state
    mov [xsi].dLastError, eax
    mov [xsi].dState, TLS_STATE_ERROR
    mov eax, TLS_HANDSHAKE_FAILED
    jmp @@Exit
  .endif

@@GenerateToken:

  ; Now generate the shutdown token to send to the peer
  ; Re-use OutBuffer for the output
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax

  ; Call InitializeSecurityContext (client) or AcceptSecurityContext (server)
  ; to generate the actual shutdown token
  .if [xsi].bIsClient != FALSE
    ; Client: use InitializeSecurityContext
    lea xbx, [xsi].hSecurityContext
    lea xdi, [xsi].hCredential
    invoke InitializeSecurityContextA, \
           xdi, \                     ; phCredential
           xbx, \                     ; phContext (existing)
           NULL, \                    ; pszTargetName
           ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or ISC_REQ_CONFIDENTIALITY or ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_STREAM, \
           0, \                       ; Reserved1
           0, \                       ; TargetDataRep
           NULL, \                    ; pInput (none for shutdown)
           0, \                       ; Reserved2
           xbx, \                     ; phNewContext (same)
           addr OutBufferDesc, \      ; pOutput
           addr dOutAttrs, \          ; pfContextAttr
           addr tsExpiry              ; ptsExpiry
  .else
    ; Server: use AcceptSecurityContext
    lea xbx, [xsi].hSecurityContext
    lea xdi, [xsi].hCredential
    invoke AcceptSecurityContext, \
           xdi, \                     ; phCredential
           xbx, \                     ; phContext (existing)
           NULL, \                    ; pInput
           ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or ASC_REQ_CONFIDENTIALITY or ASC_REQ_ALLOCATE_MEMORY or ASC_REQ_STREAM, \
           0, \                       ; TargetDataRep
           xbx, \                     ; phNewContext (same)
           addr OutBufferDesc, \      ; pOutput
           addr dOutAttrs, \          ; pfContextAttr
           addr tsExpiry              ; ptsExpiry
  .endif

  ; No more application data from now on, then send the close_notify token (unencrypted,
  ; it is already protected by SChannel) and free it
  mov [xsi].dState, TLS_STATE_SHUTDOWN
  m2m [xsi].pConnection, pConnection, xax
  OCall xsi.SendToken, addr OutBuffer

  mov eax, OBJ_OK

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.InitCredentials
; Purpose:    Initializes SSPI credentials via AcquireCredentialsHandle.
;             In client mode (SECPKG_CRED_OUTBOUND): Creates anonymous credentials without a
;             certificate. In server mode (SECPKG_CRED_INBOUND): Obtains the server certificate
;             from the configured TLS_ServerCertProvider and uses it for credential creation.
; Arguments:  Arg1: dUsage - SECPKG_CRED_OUTBOUND (client) or SECPKG_CRED_INBOUND (server).
; Return:     eax = OBJ_OK on success, TLS_SERVER_CERT_REQUIRED / TLS_SERVER_CERT_NOT_PROVIDED /
;             TLS_CREDENTIAL_ERROR on failure.

Method TLS_SChannelContext.InitCredentials, uses xbx xsi, dUsage:DWORD, pSNIHostname:POINTER, dSNILen:DWORD
  local SchannelCred:SCHANNEL_CRED
  local pCertContext:POINTER
  local tsExpiry:TimeStamp
  local dACHStatus:DWORD

  SetObject xsi

  ; Zero-initialize SCHANNEL_CRED structure
  lea xbx, SchannelCred
  xor eax, eax
  mov ecx, sizeof SCHANNEL_CRED
@@ZeroLoop:
  mov BYTE ptr [xbx + xcx - 1], 0
  dec ecx
  jnz @@ZeroLoop

  ; Set version
  mov SchannelCred.dwVersion, SCHANNEL_CRED_VERSION

  ; Initialize certificate pointer
  mov pCertContext, NULL

  ; Branch: Server mode vs Client mode
  .if dUsage == SECPKG_CRED_INBOUND
    ; --- Server mode: Obtain certificate from TLS_ServerCertProvider ---

    ; Check that a ServerCertProvider is set
    .if [xsi].pServerCertProvider == NULL
      mov eax, TLS_SERVER_CERT_REQUIRED
      jmp @@Exit
    .endif

    ; Call GetServerCert on the provider (pass SNI hostname for multi-vhost selection)
    OCall [xsi].pServerCertProvider::TLS_ServerCertProvider.GetServerCert, pSNIHostname, dSNILen
    .if xax == NULL
      mov eax, TLS_SERVER_CERT_NOT_PROVIDED
      jmp @@Exit
    .endif

    ; Store the certificate context pointer
    mov pCertContext, xax

    ; Set up SCHANNEL_CRED for server with 1 certificate
    mov SchannelCred.cCreds, 1
    lea xax, pCertContext
    mov SchannelCred.paCred, xax

    ; Server flags: use strong crypto
    mov SchannelCred.dwFlags, SCH_USE_STRONG_CRYPTO

  .else
    ; --- Client mode: Anonymous credentials (no certificate) ---
    mov SchannelCred.cCreds, 0
    mov SchannelCred.paCred, NULL

    ; Client flags: no default creds + strong crypto + disable session cache
    mov SchannelCred.dwFlags, SCH_CRED_NO_DEFAULT_CREDS or SCH_USE_STRONG_CRYPTO
    mov SchannelCred.dwSessionLifespan, 1     ;Minimal lifespan - effectively disables session cache

  .endif

  ; Set protocol versions from TLS_Context configuration (Req 8.8)
  ; SChannel will reject connections from peers using protocol versions not in this bitmask.
  ; E.g., if only SP_PROT_TLS1_2 | SP_PROT_TLS1_3 is set, TLS 1.0/1.1 peers are rejected.
  m2m SchannelCred.grBitEnabledProtocols, [xsi].dAllowedProtocols, eax

  ; Set cipher suites from TLS_Context configuration (Req 8.9)
  ; SChannel will return SEC_E_ALGORITHM_MISMATCH if no common cipher suite exists.
  ; (may be NULL/0 = use SChannel defaults)
  m2m SchannelCred.palgSupportedAlgs, [xsi].pAllowedCipherSuites, xax
  m2m SchannelCred.cSupportedAlgs, [xsi].dCipherSuiteCount, eax

  ; Call AcquireCredentialsHandle
  lea xbx, [xsi].hCredential
  invoke AcquireCredentialsHandleA, \
         NULL, \                              ; pszPrincipal
         $OfsCStrA("Microsoft Unified Security Protocol Provider"), \ ; pszPackage (UNISP_NAME_A)
         dUsage, \                            ; fCredentialUse
         NULL, \                              ; pvLogonID
         addr SchannelCred, \                 ; pAuthData
         NULL, \                              ; pGetKeyFn
         NULL, \                              ; pvGetKeyArgument
         xbx, \                               ; phCredential
         addr tsExpiry                        ; ptsExpiry

  mov dACHStatus, eax

  ; SChannel holds its own reference to the server certificate => release ours
  .if pCertContext != NULL
    invoke CertFreeCertificateContext, pCertContext
  .endif

  ; Check result (SECURITY_STATUS, SEC_E_OK = 0)
  mov eax, dACHStatus
  .if eax == 0
    mov [xsi].bCredentialValid, TRUE
    mov eax, OBJ_OK
  .else
    mov [xsi].dLastError, eax
    mov [xsi].bCredentialValid, FALSE
;   DbgWarning "TLS: InitCredentials failed"
    mov eax, TLS_CREDENTIAL_ERROR
  .endif

@@Exit:
MethodEnd

; ==================================================================================================
;    TranslateError - Static error string data
; ==================================================================================================

.const
szTLS_ErrWrongPrincipal   db "Servername stimmt nicht mit Zertifikat ueberein", 0
szTLS_ErrUntrustedRoot    db "Zertifikat nicht vertrauenswuerdig", 0
szTLS_ErrCertExpired      db "Zertifikat abgelaufen", 0
szTLS_ErrAlgoMismatch     db "Keine gemeinsame Cipher-Suite gefunden", 0
szTLS_ErrInsufficientMem  db "Unzureichend Speicher fuer SSPI-Operation", 0
szTLS_ErrUnknown          db "Unbekannter SSPI-Fehler", 0
.code

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.TranslateError
; Purpose:    Translates a SECURITY_STATUS code into a human-readable German error string.
;             Maps well-known SChannel error codes to specific messages. For unknown codes,
;             returns a generic "Unbekannter SSPI-Fehler" string.
; Arguments:  Arg1: dStatus - The SECURITY_STATUS value to translate.
; Return:     xax = Pointer to a static null-terminated error string.
; Notes:      The returned pointer is valid indefinitely (points to .const data).
;             The caller does NOT free the returned string.

Method TLS_SChannelContext.TranslateError, uses xsi, dStatus:DWORD
  SetObject xsi

  mov eax, dStatus
  .if eax == SEC_E_WRONG_PRINCIPAL
    lea xax, szTLS_ErrWrongPrincipal
  .elseif eax == SEC_E_UNTRUSTED_ROOT
    lea xax, szTLS_ErrUntrustedRoot
  .elseif eax == SEC_E_CERT_EXPIRED
    lea xax, szTLS_ErrCertExpired
  .elseif eax == SEC_E_ALGORITHM_MISMATCH
    lea xax, szTLS_ErrAlgoMismatch
  .elseif eax == SEC_E_INSUFFICIENT_MEMORY
    lea xax, szTLS_ErrInsufficientMem
  .else
    lea xax, szTLS_ErrUnknown
  .endif
MethodEnd

endif
