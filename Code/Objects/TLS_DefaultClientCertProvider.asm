; ==================================================================================================
; Title:      TLS_DefaultClientCertProvider.asm
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm compilation file for TLS_DefaultClientCertProvider object.
; Notes:      Version C.2.0
;             - Initial release.
; ==================================================================================================


% include Objects.cop

;Add here all files that build the inheritance path and referenced objects
LoadObjects Primer
LoadObjects TLS_Context
LoadObjects TLS_ClientCertProvider

;Add here the file that defines the object(s) to be included in the library
MakeObjects TLS_DefaultClientCertProvider

end
