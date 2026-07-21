; ==================================================================================================
; Title:      TLS_CertValidator.asm
; Author:     Kai Liebenau
; Version:    C.2.0
; Purpose:    ObjAsm compilation file for TLS_CertValidator object.
; Notes:      Version C.1.0
;             - Initial release.
; ==================================================================================================


% include Objects.cop

;Add here all files that build the inheritance path and referenced objects
LoadObjects Primer

;Add here the file that defines the object(s) to be included in the library
MakeObjects TLS_CertValidator

end
