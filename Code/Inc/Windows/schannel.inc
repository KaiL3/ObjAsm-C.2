ifndef __SCHANNEL_INC__
__SCHANNEL_INC__ equ 1
  include specstrings.inc
  include winapifamily.inc

; --------------------------------------------------------------------------------------------------
;    SChannel Protocol Version Flags
; --------------------------------------------------------------------------------------------------

SP_PROT_SSL2_CLIENT             equ   00000008h
SP_PROT_SSL2_SERVER             equ   00000004h
SP_PROT_SSL3_CLIENT             equ   00000020h
SP_PROT_SSL3_SERVER             equ   00000010h
SP_PROT_TLS1_0_CLIENT           equ   00000080h
SP_PROT_TLS1_0_SERVER           equ   00000040h
SP_PROT_TLS1_1_CLIENT           equ   00000200h
SP_PROT_TLS1_1_SERVER           equ   00000100h
SP_PROT_TLS1_2_CLIENT           equ   00000800h
SP_PROT_TLS1_2_SERVER           equ   00000400h
SP_PROT_TLS1_3_CLIENT           equ   00002000h
SP_PROT_TLS1_3_SERVER           equ   00001000h

SP_PROT_TLS1_CLIENT             equ   SP_PROT_TLS1_0_CLIENT
SP_PROT_TLS1_SERVER             equ   SP_PROT_TLS1_0_SERVER

SP_PROT_TLS1_X_CLIENT           equ   SP_PROT_TLS1_0_CLIENT or SP_PROT_TLS1_1_CLIENT or \
                                       SP_PROT_TLS1_2_CLIENT or SP_PROT_TLS1_3_CLIENT
SP_PROT_TLS1_X_SERVER           equ   SP_PROT_TLS1_0_SERVER or SP_PROT_TLS1_1_SERVER or \
                                       SP_PROT_TLS1_2_SERVER or SP_PROT_TLS1_3_SERVER

; --------------------------------------------------------------------------------------------------
;    SCHANNEL_CRED Structure
; --------------------------------------------------------------------------------------------------

SCHANNEL_CRED_VERSION           equ   4

SCHANNEL_CRED struct
  dwVersion               DWORD     ?     ;Must be SCHANNEL_CRED_VERSION
  cCreds                  DWORD     ?     ;Number of credentials (certificates)
  paCred                  POINTER   ?     ;-> Array of PCCERT_CONTEXT
  hRootStore              HANDLE    ?     ;Optional root certificate store
  cMappers                DWORD     ?     ;Number of credential mappers
  aphMappers              POINTER   ?     ;-> Array of mapper pointers
  cSupportedAlgs          DWORD     ?     ;Number of supported algorithms
  palgSupportedAlgs       POINTER   ?     ;-> Array of ALG_IDs
  grbitEnabledProtocols   DWORD     ?     ;SP_PROT_* flags
  dwMinimumCipherStrength DWORD     ?     ;Minimum cipher strength
  dwMaximumCipherStrength DWORD     ?     ;Maximum cipher strength
  dwSessionLifespan       DWORD     ?     ;Session cache lifetime (ms)
  dwFlags                 DWORD     ?     ;SCH_CRED_* flags
  dwCredFormat            DWORD     ?     ;Credential format
SCHANNEL_CRED ends
PSCHANNEL_CRED typedef ptr SCHANNEL_CRED

; --------------------------------------------------------------------------------------------------
;    SCHANNEL_CRED Flags
; --------------------------------------------------------------------------------------------------

SCH_CRED_NO_SYSTEM_MAPPER               equ   00000002h
SCH_CRED_NO_SERVERNAME_CHECK             equ   00000004h
SCH_CRED_MANUAL_CRED_VALIDATION          equ   00000008h
SCH_CRED_NO_DEFAULT_CREDS               equ   00000010h
SCH_CRED_AUTO_CRED_VALIDATION           equ   00000020h
SCH_CRED_USE_DEFAULT_CREDS              equ   00000040h
SCH_CRED_REVOCATION_CHECK_END_CERT      equ   00000100h
SCH_CRED_REVOCATION_CHECK_CHAIN         equ   00000200h
SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT equ 00000400h
SCH_CRED_IGNORE_NO_REVOCATION_CHECK     equ   00000800h
SCH_CRED_IGNORE_REVOCATION_OFFLINE      equ   00001000h
SCH_SEND_ROOT_CERT                      equ   00040000h
SCH_CRED_SNI_CREDENTIAL                 equ   00080000h
SCH_CRED_SNI_ENABLE_OCSP                equ   00100000h
SCH_SEND_AUX_RECORD                     equ   00200000h
SCH_USE_STRONG_CRYPTO                   equ   00400000h

; --------------------------------------------------------------------------------------------------
;    SChannel Shutdown Control Token
; --------------------------------------------------------------------------------------------------

SCHANNEL_SHUTDOWN                equ   1
SCHANNEL_ALERT                   equ   2

; --------------------------------------------------------------------------------------------------
;    Certificate Error Codes (used with SChannel validation)
; --------------------------------------------------------------------------------------------------

CERT_E_EXPIRED                   equ   800B0101h
CERT_E_VALIDITYPERIODNESTING     equ   800B0102h
CERT_E_UNTRUSTEDROOT             equ   800B0109h
CERT_E_UNTRUSTEDTESTROOT         equ   800B010Dh
CERT_E_CN_NO_MATCH               equ   800B010Fh
CERT_E_WRONG_USAGE               equ   800B0110h
CERT_E_CHAINING                  equ   800B010Ah
CERT_E_REVOKED                   equ   800B010Ch
CERT_E_REVOCATION_FAILURE        equ   800B010Eh

SslGetServerIdentity proto WIN_STD_CALL_CONV :ptr BYTE, DWORD, :ptr BYTE, :ptr DWORD, DWORD

endif ;__SCHANNEL_INC__
