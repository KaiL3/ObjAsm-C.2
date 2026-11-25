# Extending the libraries

Two libraries: **Objects** (`Code/Objects`, classes) and **ObjMem** (`Code/ObjMem`, plain
procedures). Look at a similar existing item first and copy its structure.

## A. New or changed object in `Code/Objects`

### Files
1. `Code/Objects/<Name>.inc` - definition **and** implementation in one file:

   ```asm
   ; ==================================================================================================
   ; Title:      <Name>.inc
   ; Author:     <author>
   ; Version:    C.1.0
   ; Purpose:    ObjAsm implementation of <Name> object.
   ; Notes:      Version C.1.0, <Month Year>
   ;               - Initial release.
   ; ==================================================================================================

   ; --------------------------------------------------------------------------------------------------
   ; Object:     <Name>
   ; Purpose:    ...
   ; Notes:      ...

   Object <Name>, <Name>ID, <Ancestor>
     ...
   ObjectEnd

   ; ==================================================================================================

   if IMPLEMENT

   ; ...Method headers + implementations, alphabetical order is the house style...

   endif
   ```

   Large objects may be split into several `<Name>_*.inc` files included from the main one
   (see `TLS_*`, `NetCom*`, `Chart*`).

2. `Code/Objects/<Name>.asm` - library stub:

   ```asm
   % include Objects.cop

   ;Add here all files that build the inheritance path and referenced objects
   LoadObjects Primer, <Ancestor...>

   ;Add here the file that defines the object(s) to be included in the library
   MakeObjects <Name>

   end
   ```

3. `Code/Objects/ObjIDs.inc` - add `<Name>ID equ <unique number>` in a new or matching block
   (IDs are grouped in ranges by topic; pick the next free number after the last block, never reuse).
4. `Code/Objects/ObjErrs.inc` - add error codes if the object reports its own errors.
5. `Code/Objects/Build/ObjectsX.lst` - add `<Name>` **after all its ancestors** (the list is built
   in order). Use `Objects32.lst`/`Objects64.lst` for bitness-specific objects.

### Building the object libraries
- All variants: `Code/Objects/Build/MakeObjects3264AW.cmd`; single variant:
  `MakeObjects64W.cmd`, `MakeObjects32A.cmd`, ... -> `Code/Objects/Lib/<32|64><A|W>/<Name>.lib`.
- Single object: `MakeObject64W.cmd` / `MakeMyObject.cmd` (edit the variables at the top).
- The stub is assembled with `cwd = Lib/<variant>`, which is how `% include Objects.cop` resolves.
- Quicker check while developing: use `MakeObjects <Name>` in a test project
  (`Projects/X/...`) and build that project - it compiles the source directly.

### Rules for library objects
- Must work for **all four variants** (32/64 x ANSI/WIDE) unless listed in a bitness list. Test at
  least the 64W build plus one 32-bit build when touching register- or pointer-size code.
- Inherit from `Primer` (or a descendant) so error handling/owner chain work; `Init` takes
  `pOwner` first; `Done` frees everything the object allocated.
- Document the object (Purpose/Notes, invariants if any) and every method header.
- Bump the `Version:` in the file header and add a Notes line describing the change.

## B. New procedure in `Code/ObjMem`

ObjMem is a "one procedure per object file" library so the linker only pulls in what is used.

| Location | Content |
|---|---|
| `Common/<Proc>_<suffix>.inc` | Shared implementation template. Suffix letters: `T` = text-type dependent (built as A and W), `X` = bitness neutral (same source for 32/64), `P` = parameterised by the stub (`ProcName`, types); `_32`/`_64` = bitness-specific; `UEFI` = UEFI variant |
| `32/<Proc>[A|W].asm`, `64/<Proc>[A|W].asm` | Tiny stubs: include `OA_Setup<bits>.inc`, set `TARGET_STR_TYPE`, include `ObjMemWin.cop` (or `ObjMemUefi.cop`), set `ProcName`, include the Common template. Fully hand-written bitness-specific versions also live here |
| `ObjMem.inc` | Prototypes, plus `textequ` mapping `Proc` -> `ProcA`/`ProcW` by `TARGET_STR_TYPE` |
| `ObjMem.api` | RadASM API list (keep in sync if you care about IDE completion) |

Stub example (`64/Base64EncodeW.asm`):

```asm
% include @Environ(OBJASM_PATH)\\Code\\OA_Setup64.inc
TARGET_STR_TYPE = STR_TYPE_WIDE
% include &ObjMemPath&ObjMemWin.cop

ProcName textequ <Base64EncodeW>

% include &ObjMemPath&Common\\Base64Encode_TX.inc

end
```

Steps: write the Common template (with a full Procedure header), add stubs to `32/` and `64/`
(A and W if text-dependent), add prototypes/mapping to `ObjMem.inc`, then build:

- `Code/ObjMem/MakeObjMem64.cmd` / `MakeObjMem32.cmd` / `MakeObjMem3264.cmd` -> `BuildObjMem.cmd`
  assembles every `.asm` in `32/` or `64/` into `ObjMem<bits>.lib`.
- **Install**: applications include `Code/Inc/ObjAsm/ObjMem.inc` and link
  `Code/Lib/<bits>/ObjAsm/ObjMem<bits>.lib`, *not* the files in `Code/ObjMem`. `BuildObjMem.cmd`
  copies both automatically after a successful build (`InstallObjMemInc.cmd`,
  `InstallObjMemLib<bits>.cmd`). If you only edited `ObjMem.inc`, run `InstallObjMemInc.cmd`
  yourself - otherwise projects keep seeing the old prototypes.

## C. Windows / third-party include files (`Code/Inc`)

When adding API declarations (e.g. `Windows/schannel.inc`, `sspi.inc`, `wincrypt.inc`):
- Provide both `...A` and `...W` variants of string structures/functions and map the neutral name by
  string type, the way existing headers do it; this is a frequent source of A/W bugs.
- Use MASM types (`DWORD`, `POINTER`, `HANDLE`, `XWORD`) with correct alignment; check structure
  sizes against the SDK for both bitnesses.
- Add the matching import library with `% includelib &LibPath&Windows\<lib>.lib` in the consumer.
