; ==================================================================================================
; Title:      NetComTLSServer_Shared.inc
; Author:     Kai Liebenau
; Version:    See NetComTLSServer.asm
; Purpose:    NetCom TLS Server Application.
; ==================================================================================================


;General information
APP_TITLE                     textequ   <NetCom TLS Test Server>
ABOUT_TEXT                    textequ   <NetComTLSTestServer>
COPYRIGHT                     textequ   <G. Friedrich   June 2026>
VER_FILEVERSION               equ       1,0,0,0
VER_FILEVERSION_STR           textequ   <1.0>
VER_PRODUCTVERSION            equ       1,0,0,0
VER_PRODUCTVERSION_STR        textequ   <1.0>

;Build information - updated automatically -
BUILD_NUMBER                  equ       121
BUILD_DATE_STR                textequ   <26.11.2026>
BUILD_BITNESS                 equ       64
BUILD_MODE                    equ       DBG

IDM_SEND                      equ       1000
IDM_EXIT                      equ       1001
IDM_SETTINGS                  equ       1002

IDM_PAUSE                     equ       1200
IDM_RESUME                    equ       1201
IDM_DISCONNECT                equ       1202
IDM_ABORT                     equ       1203
IDM_RESET_STATS               equ       1204
IDM_HELP                      equ       1100
IDM_ABOUT                     equ       1101

BUILD_BIN_FORMAT              equ       EXE
BUILD_BIN_SUFFIX_STR          textequ   <>
