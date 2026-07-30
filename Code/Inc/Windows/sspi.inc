ifndef __SSPI_INC__
__SSPI_INC__ equ 1

; --------------------------------------------------------------------------------------------------
;    Types
; --------------------------------------------------------------------------------------------------

SecHandle struct
  dwLower   POINTER   ?
  dwUpper   POINTER   ?
SecHandle ends

CredHandle  typedef SecHandle
CtxtHandle  typedef SecHandle
PCredHandle typedef ptr CredHandle
PCtxtHandle typedef ptr CtxtHandle

TimeStamp   typedef QWORD                               ;LARGE_INTEGER (100ns units)
PTimeStamp  typedef ptr TimeStamp

SECURITY_STATUS typedef SDWORD

; --------------------------------------------------------------------------------------------------
;    SecBuffer / SecBufferDesc
; --------------------------------------------------------------------------------------------------

SecBuffer struct
  cbBuffer      DWORD     ?
  BufferType    DWORD     ?
  pvBuffer      POINTER   ?
SecBuffer ends
PSecBuffer typedef ptr SecBuffer

SecBufferDesc struct
  ulVersion     DWORD     ?
  cBuffers      DWORD     ?
  pBuffers      PSecBuffer ?
SecBufferDesc ends
PSecBufferDesc typedef ptr SecBufferDesc

SECBUFFER_VERSION           equ   0

; SecBuffer types
SECBUFFER_EMPTY             equ   0
SECBUFFER_DATA              equ   1
SECBUFFER_TOKEN             equ   2
SECBUFFER_PKG_PARAMS        equ   3
SECBUFFER_MISSING           equ   4
SECBUFFER_EXTRA             equ   5
SECBUFFER_STREAM_TRAILER    equ   6
SECBUFFER_STREAM_HEADER     equ   7
SECBUFFER_ALERT             equ   17

; --------------------------------------------------------------------------------------------------
;    Context Attributes
; --------------------------------------------------------------------------------------------------

SecPkgContext_StreamSizes struct
  cbHeader          DWORD   ?
  cbTrailer         DWORD   ?
  cbMaximumMessage  DWORD   ?
  cBuffers          DWORD   ?
  cbBlockSize       DWORD   ?
SecPkgContext_StreamSizes ends

SECPKG_ATTR_STREAM_SIZES        equ   4
SECPKG_ATTR_REMOTE_CERT_CONTEXT equ   83

; --------------------------------------------------------------------------------------------------
;    Credential / Context Requirement Flags
; --------------------------------------------------------------------------------------------------

;InitializeSecurityContext request flags
ISC_REQ_DELEGATE                equ   00000001h
ISC_REQ_MUTUAL_AUTH             equ   00000002h
ISC_REQ_REPLAY_DETECT           equ   00000004h
ISC_REQ_SEQUENCE_DETECT         equ   00000008h
ISC_REQ_CONFIDENTIALITY         equ   00000010h
ISC_REQ_USE_SESSION_KEY         equ   00000020h
ISC_REQ_ALLOCATE_MEMORY         equ   00000100h
ISC_REQ_USE_SUPPLIED_CREDS      equ   00000080h
ISC_REQ_STREAM                  equ   00008000h
ISC_REQ_MANUAL_CRED_VALIDATION  equ   00080000h

;AcceptSecurityContext request flags
ASC_REQ_DELEGATE                equ   00000001h
ASC_REQ_MUTUAL_AUTH             equ   00000002h
ASC_REQ_REPLAY_DETECT           equ   00000004h
ASC_REQ_SEQUENCE_DETECT         equ   00000008h
ASC_REQ_CONFIDENTIALITY         equ   00000010h
ASC_REQ_ALLOCATE_MEMORY         equ   00000100h
ASC_REQ_STREAM                  equ   00010000h

;Target data representation
SECURITY_NATIVE_DREP            equ   00000010h
SECURITY_NETWORK_DREP           equ   00000000h

;Credential use direction
SECPKG_CRED_INBOUND             equ   1
SECPKG_CRED_OUTBOUND            equ   2
SECPKG_CRED_BOTH                equ   3

; --------------------------------------------------------------------------------------------------
;    Security Status Codes
; --------------------------------------------------------------------------------------------------

SEC_E_OK                        equ   00000000h
SEC_I_CONTINUE_NEEDED           equ   00090312h
SEC_I_COMPLETE_NEEDED           equ   00090313h
SEC_I_COMPLETE_AND_CONTINUE     equ   00090314h
SEC_I_CONTEXT_EXPIRED           equ   00090317h
SEC_I_RENEGOTIATE               equ   00090321h

SEC_E_INSUFFICIENT_MEMORY       equ   80090300h
SEC_E_INVALID_HANDLE            equ   80090301h
SEC_E_UNSUPPORTED_FUNCTION      equ   80090302h
SEC_E_TARGET_UNKNOWN             equ   80090303h
SEC_E_INTERNAL_ERROR            equ   80090304h
SEC_E_SECPKG_NOT_FOUND          equ   80090305h
SEC_E_NOT_OWNER                 equ   80090306h
SEC_E_WRONG_PRINCIPAL           equ   80090322h
SEC_E_INCOMPLETE_MESSAGE        equ   80090318h
SEC_E_BUFFER_TOO_SMALL          equ   80090321h
SEC_E_CERT_EXPIRED              equ   80090328h
SEC_E_CERT_UNKNOWN              equ   80090327h
SEC_E_UNTRUSTED_ROOT            equ   80090325h
SEC_E_ALGORITHM_MISMATCH        equ   80090331h

; --------------------------------------------------------------------------------------------------
;    Function Prototypes (Secur32.dll)
; --------------------------------------------------------------------------------------------------

@DefProto DllImport, AcquireCredentialsHandleW, WIN_STD_CALL_CONV,, \
  <:POINTER, :POINTER, :DWORD, :POINTER, :POINTER, :POINTER, :POINTER, :PCredHandle, :PTimeStamp>, 36
AcquireCredentialsHandle equ AcquireCredentialsHandleW

@DefProto DllImport, FreeCredentialsHandle, WIN_STD_CALL_CONV,, \
  <:PCredHandle>, 4

@DefProto DllImport, InitializeSecurityContextW, WIN_STD_CALL_CONV,, \
  <:PCredHandle, :PCtxtHandle, :POINTER, :DWORD, :DWORD, :DWORD, :PSecBufferDesc, :DWORD, :PCtxtHandle, :PSecBufferDesc, :POINTER, :PTimeStamp>, 48
InitializeSecurityContext equ InitializeSecurityContextW

@DefProto DllImport, AcceptSecurityContext, WIN_STD_CALL_CONV,, \
  <:PCredHandle, :PCtxtHandle, :PSecBufferDesc, :DWORD, :DWORD, :PCtxtHandle, :PSecBufferDesc, :POINTER, :PTimeStamp>, 36

@DefProto DllImport, DeleteSecurityContext, WIN_STD_CALL_CONV,, \
  <:PCtxtHandle>, 4

@DefProto DllImport, QueryContextAttributesW, WIN_STD_CALL_CONV,, \
  <:PCtxtHandle, :DWORD, :POINTER>, 12
QueryContextAttributes equ QueryContextAttributesW

@DefProto DllImport, EncryptMessage, WIN_STD_CALL_CONV,, \
  <:PCtxtHandle, :DWORD, :PSecBufferDesc, :DWORD>, 16

@DefProto DllImport, DecryptMessage, WIN_STD_CALL_CONV,, \
  <:PCtxtHandle, :PSecBufferDesc, :DWORD, :POINTER>, 16

@DefProto DllImport, ApplyControlToken, WIN_STD_CALL_CONV,, \
  <:PCtxtHandle, :PSecBufferDesc>, 8

@DefProto DllImport, FreeContextBuffer, WIN_STD_CALL_CONV,, \
  <:POINTER>, 4

endif ;__SSPI_INC__
