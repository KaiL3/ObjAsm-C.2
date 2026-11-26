; ==================================================================================================
; Title:      NetComTLSClient_Shared.inc
; Author:     Kai Liebenau
; Version:    See NetComTLSClient.asm
; Purpose:    NetCom TLS Client Application.
; ==================================================================================================


;General information
APP_TITLE                     textequ   <NetCom TLS Test Client>
ABOUT_TEXT                    textequ   <NetComTLSTestClient>
COPYRIGHT                     textequ   <Kai Liebenau   June 2026>
VER_FILEVERSION               equ       1,0,0,0
VER_FILEVERSION_STR           textequ   <1.0>
VER_PRODUCTVERSION            equ       1,0,0,0
VER_PRODUCTVERSION_STR        textequ   <1.0>

;Build information - updated automatically -
BUILD_NUMBER                  equ       153
BUILD_DATE_STR                textequ   <26.11.2026>
BUILD_BITNESS                 equ       64
BUILD_MODE                    equ       DBG

IDM_SEND                      equ       1000
IDM_EXIT                      equ       1001
IDM_SETTINGS                  equ       1002
IDM_RESET_STATS               equ       1003
IDM_HELP                      equ       1100
IDM_ABOUT                     equ       1101

;Send.dlg
IDD_DLG_SEND                  equ       1000

IDC_GRP_SERVER                equ       2000
IDC_BTN_CONNECT               equ       2001
IDC_BTN_DISCONNECT            equ       2002
IDC_STC_ADDR                  equ       2003
IDC_CBO_ADDR                  equ       2004
IDC_STC_PORT                  equ       2005
IDC_EDT_PORT                  equ       2006
IDC_UDN_PORT                  equ       2007
IDC_STC_CONNECTIONS           equ       2008
IDC_EDT_CONNECTIONS           equ       2009
IDC_UDN_CONNECTIONS           equ       2010

IDC_GRP_DATA                  equ       3000
IDC_BTN_SEND                  equ       3001
IDC_EDT_DATA                  equ       3002
IDC_STC_REPETITIONS           equ       3003
IDC_EDT_REPETITIONS           equ       3004
IDC_UDN_REPETITIONS           equ       3005

IDC_GRP_TEST                  equ       3010
IDC_CHK_NODELIM               equ       3011
IDC_CHK_TRICKLE               equ       3012
IDC_BTN_PAUSE                 equ       3013
IDC_BTN_RESUME                equ       3014
IDC_BTN_ABORT                 equ       3015

BUILD_BIN_FORMAT              equ       EXE
BUILD_BIN_SUFFIX_STR          textequ   <>
