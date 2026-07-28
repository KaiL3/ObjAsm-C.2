; ==================================================================================================
; Title:      TLS_SChannelContext.inc
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm SChannel/SSPI-based implementation of TLS_Context.
;             Manages SSPI credentials, security contexts, internal reassembly and encryption
;             buffers for TLS record processing.
; Links:      - https://learn.microsoft.com/en-us/windows/win32/secauthn/schannel
;             - https://learn.microsoft.com/en-us/windows/win32/api/sspi/
; Notes:      Requires TLS_Context.inc to be loaded before this file.
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
  ASC_REQ_MUTUAL_AUTH         equ   00020000h
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


; ==================================================================================================
;    Handshake Buffer Constants
; ==================================================================================================

TLS_HANDSHAKE_BUFFER_SIZE   equ   16384     ;Max TLS record size (sufficient for handshake messages)


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

  VirtualMethod   InitCredentials,    DWORD           ; dUsage (Client/Server)
  VirtualMethod   AllocateBuffers
  VirtualMethod   FreeBuffers
  VirtualMethod   TranslateError,     DWORD           ; dSecurityStatus -> xax = -> error string

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
; Purpose:    Allocates the internal reassembly buffer and encryption buffer based on the
;             current StreamSizes values (cbHeader + cbMaximumMessage + cbTrailer).
;             Both buffers are zero-initialized.
; Arguments:  None.
; Return:     eax = OBJ_OK on success, TLS_BUFFER_ALLOC_FAILED on failure.
; Notes:      StreamSizes must be filled (e.g. via QueryContextAttributes after handshake)
;             before calling this method.

Method TLS_SChannelContext.AllocateBuffers, uses xbx xsi
  local dRequiredSize:DWORD

  SetObject xsi

  ; Calculate required size: cbHeader + cbMaximumMessage + cbTrailer
  mov eax, [xsi].StreamSizes.cbHeader
  add eax, [xsi].StreamSizes.cbMaximumMessage
  add eax, [xsi].StreamSizes.cbTrailer
  mov dRequiredSize, eax

  ; Reallocate Reassembly buffer if needed (may already exist from handshake)
  .if [xsi].pReassemblyBuffer != NULL
    ; Check if existing buffer is large enough
    mov eax, dRequiredSize
    .if eax > [xsi].dReassemblyCapacity
      ; Need larger buffer - free old one and allocate new
      MemFree [xsi].pReassemblyBuffer
      mov [xsi].pReassemblyBuffer, NULL
    .endif
  .endif
  .if [xsi].pReassemblyBuffer == NULL
    MemAlloc dRequiredSize, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov [xsi].pReassemblyBuffer, xax
    m2m [xsi].dReassemblyCapacity, dRequiredSize, eax
  .endif
  mov [xsi].dReassemblyUsed, 0

  ; Allocate Encryption buffer (zero-initialized)
  MemAlloc dRequiredSize, MEM_INIT_ZERO
  .if xax == NULL
    ; Allocation failed - free already allocated reassembly buffer
    MemFree [xsi].pReassemblyBuffer
    mov [xsi].pReassemblyBuffer, NULL
    mov [xsi].dReassemblyCapacity, 0
    mov [xsi].dState, TLS_STATE_ERROR
    mov eax, TLS_BUFFER_ALLOC_FAILED
    jmp @@Exit
  .endif
  mov [xsi].pEncryptBuffer, xax
  m2m [xsi].dEncryptBufferSize, dRequiredSize, eax

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
; Method:     TLS_SChannelContext.ProcessHandshakeData
; Purpose:    Processes incoming handshake data. Branches based on bIsClient flag:
;             - Client (bIsClient=TRUE): Uses InitializeSecurityContext continuation calls.
;             - Server (bIsClient=FALSE): Uses AcceptSecurityContext.
;             Handles SEC_I_CONTINUE_NEEDED, SEC_E_OK, SEC_I_INCOMPLETE_CREDENTIALS,
;             SEC_E_INCOMPLETE_MESSAGE, SECBUFFER_EXTRA, and error conditions.
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
  local tsExpiry:TimeStamp
  local dStatus:DWORD
  local pCertContext:POINTER
  local SchannelCred:SCHANNEL_CRED
  local tsCredExpiry:TimeStamp

  SetObject xsi

  ; Store connection pointer
  m2m [xsi].pConnection, pConnection, xax

  ; Branch: Client vs Server
  .if [xsi].bIsClient == FALSE
    ; === SERVER PATH: AcceptSecurityContext ===
    jmp @@ServerPath
  .endif

  ; === CLIENT PATH: InitializeSecurityContext continuation ===

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

  ; --- Build output SecBufferDesc ---
  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax

  ; OutBuffer: Token type, SSPI allocates memory
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  ; --- Call InitializeSecurityContext (continuation - pass existing context) ---
  lea xbx, [xsi].hCredential
  lea xdi, [xsi].hSecurityContext
  invoke InitializeSecurityContext, \
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

  ; --- Handle return codes ---

  .if dStatus == SEC_I_CONTINUE_NEEDED
    ; --- SEC_I_CONTINUE_NEEDED: Send output token, wait for more data ---
    .if OutBuffer.cbBuffer > 0 && OutBuffer.pvBuffer != NULL
      OCall pConnection::NetComConnection.QueueSend, OutBuffer.pvBuffer, OutBuffer.cbBuffer
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; Handle SECBUFFER_EXTRA: preserve unconsumed data in reassembly buffer
    .if InBuffers[1 * sizeof SecBuffer].BufferType == SECBUFFER_EXTRA
      ; Extra data is at (pData + dDataSize - ExtraBuffer.cbBuffer)
      mov eax, InBuffers[1 * sizeof SecBuffer].cbBuffer
      mov xbx, pData
      mov ecx, dDataSize
      sub ecx, eax
      add xbx, xcx                            ; xbx = start of extra data
      ; Move extra data to the reassembly buffer start
      mov [xsi].dReassemblyUsed, eax
      invoke MemShift, [xsi].pReassemblyBuffer, xbx, [xsi].dReassemblyUsed
    .else
      ; All data consumed
      mov [xsi].dReassemblyUsed, 0
    .endif

    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_E_OK
    ; --- SEC_E_OK: Handshake complete ---

    ; Send final output token if any
    .if OutBuffer.cbBuffer > 0 && OutBuffer.pvBuffer != NULL
      OCall pConnection::NetComConnection.QueueSend, OutBuffer.pvBuffer, OutBuffer.cbBuffer
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; (a) QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES) → fill StreamSizes
    lea xbx, [xsi].hSecurityContext
    lea xdi, [xsi].StreamSizes
    invoke QueryContextAttributes, xbx, SECPKG_ATTR_STREAM_SIZES, xdi

    ; (b) AllocateBuffers based on StreamSizes
    OCall xsi.AllocateBuffers
    .if eax != OBJ_OK
      ; Buffer allocation failed - transition to error
      mov [xsi].dState, TLS_STATE_ERROR
      jmp @@HandshakeFailed
    .endif

    ; Publish max plaintext size to base class for polymorphic access
    m2m [xsi].dMaxMessageSize, [xsi].StreamSizes.cbMaximumMessage, eax

    ; (c) Set state to TLS_STATE_DATA, context is valid
    mov [xsi].dState, TLS_STATE_DATA
    mov [xsi].bContextValid, TRUE

    ; (d) Validate peer certificate
    mov pCertContext, NULL
    lea xbx, [xsi].hSecurityContext
    invoke QueryContextAttributes, xbx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, addr pCertContext

    .if eax == SEC_E_OK && pCertContext != NULL
      ; Delegate to CertValidator if one is set
      .if [xsi].pCertValidator != NULL
        ; Pass pTargetName for hostname verification if bVerifyServerName is TRUE
        .if [xsi].bVerifyServerName == TRUE
          OCall [xsi].pCertValidator::TLS_CertValidator.Validate, pCertContext, [xsi].pTargetName
        .else
          OCall [xsi].pCertValidator::TLS_CertValidator.Validate, pCertContext, NULL
        .endif
        .if eax != 0
          ; (e) Validation failed: close connection
          mov [xsi].dLastError, eax
          mov [xsi].dState, TLS_STATE_ERROR
          ; Call OnHandshakeFailed on the protocol
          mov xbx, pConnection
          mov xbx, [xbx].$Obj(NetComConnection).pProtocol
          OCall xbx::NetComProtocol.OnError, pConnection, NULL, TLS_CERTIFICATE_INVALID
          ; Close connection
          OCall pConnection::NetComConnection.Disconnect, SD_BOTH
          mov eax, TLS_CERTIFICATE_INVALID
          jmp @@Exit
        .endif
      .endif
    .endif

    ; Handle SECBUFFER_EXTRA for handshake completion
    .if InBuffers[1 * sizeof SecBuffer].BufferType == SECBUFFER_EXTRA
      mov eax, InBuffers[1 * sizeof SecBuffer].cbBuffer
      mov xbx, pData
      mov ecx, dDataSize
      sub ecx, eax
      add xbx, xcx
      mov [xsi].dReassemblyUsed, eax
      invoke MemShift, [xsi].pReassemblyBuffer, xbx, [xsi].dReassemblyUsed
    .else
      mov [xsi].dReassemblyUsed, 0
    .endif

    ; (f) Call OnHandshakeComplete on the protocol
    mov xbx, pConnection
    mov xbx, [xbx].$Obj(NetComConnection).pProtocol
    OCall xbx::NetComProtocol.OnHandshakeComplete, pConnection

    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_I_INCOMPLETE_CREDENTIALS
    ; --- SEC_I_INCOMPLETE_CREDENTIALS: Server requests client certificate ---

    ; Free output buffer if allocated
    .if OutBuffer.pvBuffer != NULL
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; Check if we have a ClientCertProvider
    .if [xsi].pClientCertProvider == NULL
      ; No provider set - fail with TLS_CLIENT_CERT_REQUIRED
      mov [xsi].dState, TLS_STATE_ERROR
      mov [xsi].dLastError, TLS_CLIENT_CERT_REQUIRED
      jmp @@HandshakeFailed
    .endif

    ; Get client certificate from provider
    OCall [xsi].pClientCertProvider::TLS_ClientCertProvider.GetClientCert
    .if xax == NULL
      ; Provider returned NULL - fail with TLS_CLIENT_CERT_NOT_PROVIDED
      mov [xsi].dState, TLS_STATE_ERROR
      mov [xsi].dLastError, TLS_CLIENT_CERT_NOT_PROVIDED
      jmp @@HandshakeFailed
    .endif

    ; Store cert context for credential recreation
    mov pCertContext, xax

    ; Free existing credentials
    .if [xsi].bCredentialValid != FALSE
      lea xbx, [xsi].hCredential
      invoke FreeCredentialsHandle, xbx
      mov [xsi].bCredentialValid, FALSE
    .endif

    ; Recreate credentials with the client certificate
    ; We need to rebuild SCHANNEL_CRED with the client cert
    ; Since InitCredentials doesn't accept a cert parameter for client mode,
    ; we do an inline AcquireCredentialsHandle here with the cert

    ; Zero-initialize SCHANNEL_CRED
    lea xbx, SchannelCred
    xor eax, eax
    mov ecx, sizeof SCHANNEL_CRED
  @@ZeroCredLoop:
    mov BYTE ptr [xbx + xcx - 1], 0
    dec ecx
    jnz @@ZeroCredLoop

    mov SchannelCred.dwVersion, SCHANNEL_CRED_VERSION
    mov SchannelCred.cCreds, 1
    lea xax, pCertContext
    mov SchannelCred.paCred, xax
    mov SchannelCred.dwFlags, SCH_USE_STRONG_CRYPTO
    m2m SchannelCred.grBitEnabledProtocols, [xsi].dAllowedProtocols, eax
    m2m SchannelCred.palgSupportedAlgs, [xsi].pAllowedCipherSuites, xax
    m2m SchannelCred.cSupportedAlgs, [xsi].dCipherSuiteCount, eax

    lea xbx, [xsi].hCredential
    invoke AcquireCredentialsHandle, \
           NULL, \
           $OfsCStr("Microsoft Unified Security Protocol Provider"), \
           SECPKG_CRED_OUTBOUND, \
           NULL, \
           addr SchannelCred, \
           NULL, \
           NULL, \
           xbx, \
           addr tsCredExpiry

    .if eax != 0
      ; Failed to recreate credentials with client cert
      mov [xsi].dLastError, eax
      mov [xsi].dState, TLS_STATE_ERROR
      jmp @@HandshakeFailed
    .endif
    mov [xsi].bCredentialValid, TRUE

    ; Retry InitializeSecurityContext with the same input data
    jmp @@RetryISC

  .elseif dStatus == SEC_E_INCOMPLETE_MESSAGE
    ; --- SEC_E_INCOMPLETE_MESSAGE: Need more data from server ---
    ; Data remains in the reassembly buffer (passed as pData, dDataSize is dReassemblyUsed).
    ; dReassemblyUsed stays unchanged � caller will append more data on next call.
    ; Free output buffer if any
    .if OutBuffer.pvBuffer != NULL
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif
    mov eax, OBJ_OK
    jmp @@Exit

  .else
    ; --- Any other status: Handshake failed ---
    ; NOTE: This handler covers both:
    ;   - Protocol version rejection (Req 8.8): SChannel returns a handshake failure when the
    ;     peer only supports protocol versions not in grBitEnabledProtocols (set via
    ;     InitCredentials from dAllowedProtocols). No explicit check needed here.
    ;   - Cipher-Suite mismatch (Req 8.9): SChannel returns SEC_E_ALGORITHM_MISMATCH
    ;     (80090331h) when no common cipher suite exists between client and server.
    ;     Both cases are caught here and propagated to OnHandshakeFailed via OnError.

    ; Free output buffer if allocated
    .if OutBuffer.pvBuffer != NULL
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; Check if ISC_RET_MUTUAL_AUTH is set in output flags (server wants mutual auth)
    .ifBitSet dwSSPIOutFlags, ISC_RET_MUTUAL_AUTH
      ; Server requests mutual auth - treat same as SEC_I_INCOMPLETE_CREDENTIALS
      ; This branch handles the case where the handshake continued but flagged mutual auth
      ; For now, fall through to error since the status indicates failure
    .endif

    ; Specific detection: SEC_E_ALGORITHM_MISMATCH (Req 8.9)
    ; When no common cipher suite exists, SChannel returns this status.
    ; dLastError preserves the original SECURITY_STATUS for diagnostics.
;   .if dStatus == SEC_E_ALGORITHM_MISMATCH
;     DbgWarning "TLS: No common cipher suite (SEC_E_ALGORITHM_MISMATCH)"
;   .endif

    m2m [xsi].dLastError, dStatus, eax
    mov [xsi].dState, TLS_STATE_ERROR

@@HandshakeFailed:
;   DbgWarning "TLS: Handshake failed"
    ; Notify protocol: OnError with TLS_HANDSHAKE_FAILED
    ; The original SECURITY_STATUS is preserved in dLastError for TranslateError diagnostics.
    mov xbx, pConnection
    mov xbx, [xbx].$Obj(NetComConnection).pProtocol
    OCall xbx::NetComProtocol.OnError, pConnection, NULL, TLS_HANDSHAKE_FAILED
    ; Close connection
    OCall pConnection::NetComConnection.Disconnect, SD_BOTH
    mov eax, TLS_HANDSHAKE_FAILED
  .endif

  jmp @@Exit

  ; ===========================================================================
  ; SERVER PATH: AcceptSecurityContext
  ; ===========================================================================
@@ServerPath:

@@RetryASC:
  ; --- Build input SecBufferDesc for AcceptSecurityContext ---
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

  ; --- Build output SecBufferDesc ---
  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax

  ; OutBuffer: Token type, SSPI allocates memory (ASC_REQ_ALLOCATE_MEMORY)
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  ; --- Determine server context flags ---
  ; Base flags + mutual auth if CertValidator is set (server requires client cert)
  mov eax, TLS_SERVER_ASC_FLAGS
  .if [xsi].pCertValidator != NULL
    or eax, ASC_REQ_MUTUAL_AUTH
  .endif
  mov dwSSPIOutFlags, eax                       ; Reuse local for input flags

  ; --- Call AcceptSecurityContext ---
  lea xbx, [xsi].hCredential
  ; Use phContext = NULL on first call, existing context on continuation
  .if [xsi].bContextValid == FALSE
    ; First call: phContext = NULL, phNewContext = &hSecurityContext
    lea xdi, [xsi].hSecurityContext
    invoke AcceptSecurityContext, \
           xbx, \                               ; phCredential
           NULL, \                              ; phContext (NULL for first call)
           addr InBufferDesc, \                 ; pInput
           dwSSPIOutFlags, \                    ; fContextReq
           0, \                                 ; TargetDataRep (not used with stream)
           xdi, \                               ; phNewContext
           addr OutBufferDesc, \                ; pOutput
           addr dwSSPIOutFlags, \               ; pfContextAttr (output flags reuse local)
           addr tsExpiry                        ; ptsExpiry
  .else
    ; Continuation call: phContext = &hSecurityContext
    lea xdi, [xsi].hSecurityContext
    invoke AcceptSecurityContext, \
           xbx, \                               ; phCredential
           xdi, \                               ; phContext (existing context)
           addr InBufferDesc, \                 ; pInput
           dwSSPIOutFlags, \                    ; fContextReq
           0, \                                 ; TargetDataRep
           NULL, \                              ; phNewContext (NULL for continuation)
           addr OutBufferDesc, \                ; pOutput
           addr dwSSPIOutFlags, \               ; pfContextAttr
           addr tsExpiry                        ; ptsExpiry
  .endif

  mov dStatus, eax

  ; --- Handle AcceptSecurityContext results ---

  .if dStatus == SEC_I_CONTINUE_NEEDED
    ; --- SEC_I_CONTINUE_NEEDED: Mark context valid, send output token, wait for more ---
    mov [xsi].bContextValid, TRUE

    .if OutBuffer.cbBuffer > 0 && OutBuffer.pvBuffer != NULL
      OCall pConnection::NetComConnection.QueueSend, OutBuffer.pvBuffer, OutBuffer.cbBuffer
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; Handle SECBUFFER_EXTRA
    .if InBuffers[1 * sizeof SecBuffer].BufferType == SECBUFFER_EXTRA
      mov eax, InBuffers[1 * sizeof SecBuffer].cbBuffer
      mov xbx, pData
      mov ecx, dDataSize
      sub ecx, eax
      add xbx, xcx                            ; xbx = start of extra data
      mov [xsi].dReassemblyUsed, eax
      invoke MemShift, [xsi].pReassemblyBuffer, xbx, [xsi].dReassemblyUsed
    .else
      mov [xsi].dReassemblyUsed, 0
    .endif

    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_E_OK
    ; --- SEC_E_OK: Server handshake complete ---
    mov [xsi].bContextValid, TRUE

    ; Send final output token if any
    .if OutBuffer.cbBuffer > 0 && OutBuffer.pvBuffer != NULL
      OCall pConnection::NetComConnection.QueueSend, OutBuffer.pvBuffer, OutBuffer.cbBuffer
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; (a) QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES) → fill StreamSizes
    lea xbx, [xsi].hSecurityContext
    lea xdi, [xsi].StreamSizes
    invoke QueryContextAttributes, xbx, SECPKG_ATTR_STREAM_SIZES, xdi

    ; (b) AllocateBuffers based on StreamSizes
    OCall xsi.AllocateBuffers
    .if eax != OBJ_OK
      ; Buffer allocation failed
      mov [xsi].dState, TLS_STATE_ERROR
      jmp @@ServerHandshakeFailed
    .endif

    ; Publish max plaintext size to base class for polymorphic access
    m2m [xsi].dMaxMessageSize, [xsi].StreamSizes.cbMaximumMessage, eax

    ; (c) Set state to TLS_STATE_DATA
    mov [xsi].dState, TLS_STATE_DATA

    ; (d) Validate client certificate if mutual auth was requested
    .if [xsi].pCertValidator != NULL
      mov pCertContext, NULL
      lea xbx, [xsi].hSecurityContext
      invoke QueryContextAttributes, xbx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, addr pCertContext

      .if eax == SEC_E_OK && pCertContext != NULL
        OCall [xsi].pCertValidator::TLS_CertValidator.Validate, pCertContext, NULL
        .if eax != 0
          ; Client certificate validation failed
          mov [xsi].dLastError, eax
          mov [xsi].dState, TLS_STATE_ERROR
          mov xbx, pConnection
          mov xbx, [xbx].$Obj(NetComConnection).pProtocol
          OCall xbx::NetComProtocol.OnError, pConnection, NULL, TLS_CERTIFICATE_INVALID
          OCall pConnection::NetComConnection.Disconnect, SD_BOTH
          mov eax, TLS_CERTIFICATE_INVALID
          jmp @@Exit
        .endif
      .endif
    .endif

    ; Handle SECBUFFER_EXTRA for handshake completion
    .if InBuffers[1 * sizeof SecBuffer].BufferType == SECBUFFER_EXTRA
      mov eax, InBuffers[1 * sizeof SecBuffer].cbBuffer
      mov xbx, pData
      mov ecx, dDataSize
      sub ecx, eax
      add xbx, xcx
      mov [xsi].dReassemblyUsed, eax
      invoke MemShift, [xsi].pReassemblyBuffer, xbx, [xsi].dReassemblyUsed
    .else
      mov [xsi].dReassemblyUsed, 0
    .endif

    ; (e) Call OnHandshakeComplete on the protocol
    mov xbx, pConnection
    mov xbx, [xbx].$Obj(NetComConnection).pProtocol
    OCall xbx::NetComProtocol.OnHandshakeComplete, pConnection

    mov eax, OBJ_OK
    jmp @@Exit

  .elseif dStatus == SEC_E_INCOMPLETE_MESSAGE
    ; --- SEC_E_INCOMPLETE_MESSAGE: Need more data from client ---
    ; Free output buffer if any
    .if OutBuffer.pvBuffer != NULL
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif
    mov eax, OBJ_OK
    jmp @@Exit

  .else
    ; --- Any other status: Server handshake failed ---
    ; NOTE: This handler covers both:
    ;   - Protocol version rejection (Req 8.8): SChannel returns a handshake failure when the
    ;     client only supports protocol versions not in grBitEnabledProtocols (set via
    ;     InitCredentials from dAllowedProtocols). No explicit check needed here.
    ;   - Cipher-Suite mismatch (Req 8.9): SChannel returns SEC_E_ALGORITHM_MISMATCH
    ;     (80090331h) when no common cipher suite exists between client and server.
    ;     Both cases are caught here and propagated to OnHandshakeFailed via OnError.

    ; Free output buffer if allocated
    .if OutBuffer.pvBuffer != NULL
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    ; Specific detection: SEC_E_ALGORITHM_MISMATCH (Req 8.9)
    ; When no common cipher suite exists, SChannel returns this status.
    ; dLastError preserves the original SECURITY_STATUS for diagnostics.
;   .if dStatus == SEC_E_ALGORITHM_MISMATCH
;     DbgWarning "TLS: No common cipher suite (SEC_E_ALGORITHM_MISMATCH)"
;   .endif

    m2m [xsi].dLastError, dStatus, eax
    mov [xsi].dState, TLS_STATE_ERROR

@@ServerHandshakeFailed:
;   DbgWarning "TLS: Server handshake failed"
    ; Notify protocol: OnError with TLS_HANDSHAKE_FAILED
    ; The original SECURITY_STATUS is preserved in dLastError for TranslateError diagnostics.
    mov xbx, pConnection
    mov xbx, [xbx].$Obj(NetComConnection).pProtocol
    OCall xbx::NetComProtocol.OnError, pConnection, NULL, TLS_HANDSHAKE_FAILED
    ; Close connection
    OCall pConnection::NetComConnection.Disconnect, SD_BOTH
    mov eax, TLS_HANDSHAKE_FAILED
  .endif

@@Exit:
MethodEnd

; --------------------------------------------------------------------------------------------------
; Method:     TLS_SChannelContext.StartClientHandshake
; Purpose:    Initiates a TLS client handshake.
;             Sets state to TLS_STATE_HANDSHAKE, initializes client credentials (anonymous),
;             calls InitializeSecurityContext (first call, no input buffer) to generate the
;             initial handshake token, and sends it via NetComConnection.QueueSend.
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

  ; Store connection pointer for later use in ProcessHandshakeData
  m2m [xsi].pConnection, pConnection, xax

  ; Transition state: NONE → HANDSHAKE
  mov [xsi].dState, TLS_STATE_HANDSHAKE

  ; Initialize client credentials (SECPKG_CRED_OUTBOUND, anonymous - no cert)
  OCall xsi.InitCredentials, SECPKG_CRED_OUTBOUND
  .if eax != OBJ_OK
    ; Credential initialization failed
    mov [xsi].dState, TLS_STATE_ERROR
    jmp @@Exit
  .endif

  ; Allocate reassembly buffer early for handshake data accumulation
  .if [xsi].pReassemblyBuffer == NULL
    MemAlloc TLS_HANDSHAKE_BUFFER_SIZE, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov [xsi].pReassemblyBuffer, xax
    mov [xsi].dReassemblyCapacity, TLS_HANDSHAKE_BUFFER_SIZE
    mov [xsi].dReassemblyUsed, 0
  .endif

  ; Prepare output SecBufferDesc for InitializeSecurityContext
  mov OutBufferDesc.ulVersion, SECBUFFER_VERSION
  mov OutBufferDesc.cBuffers, 1
  lea xax, OutBuffer
  mov OutBufferDesc.pBuffers, xax

  ; Output buffer: Token type, SSPI allocates memory (ISC_REQ_ALLOCATE_MEMORY)
  mov OutBuffer.cbBuffer, 0
  mov OutBuffer.BufferType, SECBUFFER_TOKEN
  mov OutBuffer.pvBuffer, NULL

  ; Call InitializeSecurityContext (first call - pContext=NULL, pInput=NULL)
  lea xbx, [xsi].hCredential
  lea xdi, [xsi].hSecurityContext
  invoke InitializeSecurityContext, \
         xbx, \                               ; phCredential
         NULL, \                              ; phContext (NULL for first call)
         [xsi].pTargetName, \                 ; pszTargetName (hostname for SNI, or NULL)
         TLS_CLIENT_ISC_FLAGS or ISC_REQ_ALLOCATE_MEMORY, \ ; fContextReq
         0, \                                 ; Reserved1
         0, \                                 ; TargetDataRep (not used with stream)
         NULL, \                              ; pInput (NULL for first call)
         0, \                                 ; Reserved2
         xdi, \                               ; phNewContext
         addr OutBufferDesc, \                ; pOutput
         addr dwSSPIOutFlags, \               ; pfContextAttr
         addr tsExpiry                        ; ptsExpiry

  ; Check result
  .if eax == SEC_I_CONTINUE_NEEDED || eax == SEC_E_OK
    ; Context handle is now valid
    mov [xsi].bContextValid, TRUE

    ; If output token was generated (cbBuffer > 0), send it
    .if OutBuffer.cbBuffer > 0 && OutBuffer.pvBuffer != NULL
      OCall pConnection::NetComConnection.QueueSend, OutBuffer.pvBuffer, OutBuffer.cbBuffer
      ; Free SSPI-allocated output buffer
      invoke FreeContextBuffer, OutBuffer.pvBuffer
    .endif

    mov eax, OBJ_OK
  .else
    ; InitializeSecurityContext failed on first call
    mov [xsi].dLastError, eax
    mov [xsi].dState, TLS_STATE_ERROR
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

  ; Store connection pointer for later use in ProcessHandshakeData
  m2m [xsi].pConnection, pConnection, xax

  ; Transition state: NONE → HANDSHAKE
  mov [xsi].dState, TLS_STATE_HANDSHAKE

  ; Initialize server credentials (SECPKG_CRED_INBOUND)
  ; This will obtain the server certificate from TLS_ServerCertProvider,
  ; verify private key, and call AcquireCredentialsHandle
  OCall xsi.InitCredentials, SECPKG_CRED_INBOUND
  .if eax != OBJ_OK
    ; Credential initialization failed (TLS_SERVER_CERT_REQUIRED,
    ; TLS_SERVER_CERT_NOT_PROVIDED, or TLS_CREDENTIAL_ERROR)
    mov [xsi].dLastError, eax
    mov [xsi].dState, TLS_STATE_ERROR

    ; Notify protocol of handshake failure
    mov xbx, pConnection
    mov xbx, [xbx].$Obj(NetComConnection).pProtocol
    OCall xbx::NetComProtocol.OnError, pConnection, NULL, TLS_HANDSHAKE_FAILED

    mov eax, TLS_HANDSHAKE_FAILED
    jmp @@Exit
  .endif

  ; Allocate reassembly buffer early for handshake data accumulation
  .if [xsi].pReassemblyBuffer == NULL
    MemAlloc TLS_HANDSHAKE_BUFFER_SIZE, MEM_INIT_ZERO
    .if xax == NULL
      mov [xsi].dState, TLS_STATE_ERROR
      mov eax, TLS_BUFFER_ALLOC_FAILED
      jmp @@Exit
    .endif
    mov [xsi].pReassemblyBuffer, xax
    mov [xsi].dReassemblyCapacity, TLS_HANDSHAKE_BUFFER_SIZE
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
;             the shutdown token. The token is sent to the peer via QueueSend, and the state
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
    invoke InitializeSecurityContext, \
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

  ; If output token was generated, send it to the peer
  .if OutBuffer.cbBuffer > 0 && OutBuffer.pvBuffer != NULL
    ; Set state to SHUTDOWN BEFORE QueueSend so the token bypasses encryption
    mov [xsi].dState, TLS_STATE_SHUTDOWN
    ; Send shutdown token via QueueSend (passes through as raw data like handshake tokens)
    OCall pConnection::NetComConnection.QueueSend, OutBuffer.pvBuffer, OutBuffer.cbBuffer
    ; Free the allocated output buffer (SSPI allocated it with ISC_REQ_ALLOCATE_MEMORY)
    invoke FreeContextBuffer, OutBuffer.pvBuffer
  .else
    ; No token generated, just set state
    mov [xsi].dState, TLS_STATE_SHUTDOWN
  .endif

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

Method TLS_SChannelContext.InitCredentials, uses xbx xsi, dUsage:DWORD
  local SchannelCred:SCHANNEL_CRED
  local pCertContext:POINTER
  local tsExpiry:TimeStamp

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

    ; Call GetServerCert on the provider
    OCall [xsi].pServerCertProvider::TLS_ServerCertProvider.GetServerCert
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
  invoke AcquireCredentialsHandle, \
         NULL, \                              ; pszPrincipal
         $OfsCStr("Microsoft Unified Security Protocol Provider"), \ ; pszPackage (UNISP_NAME)
         dUsage, \                            ; fCredentialUse
         NULL, \                              ; pvLogonID
         addr SchannelCred, \                 ; pAuthData
         NULL, \                              ; pGetKeyFn
         NULL, \                              ; pvGetKeyArgument
         xbx, \                               ; phCredential
         addr tsExpiry                        ; ptsExpiry

  ; Check result (SECURITY_STATUS in eax, SEC_E_OK = 0)
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
