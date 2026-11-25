# Projects and the build chain

## Project folder layout (convention from `Projects/X/*`)

| File | Role |
|---|---|
| `<Name>.asm` | Main file. **Exactly one `.asm` per folder** - its name becomes `ProjectName`. Contains `SysSetup`, includes, `MakeObjects`, `start proc` |
| `<Name>_Globals.inc` | Global strings/constants (`CStr szAppTitle, ...`) - includes `_Shared.inc` |
| `<Name>_Main.inc` | Application object(s) and their methods |
| `<Name>_Shared.inc` | Constants shared with resources (APP_TITLE, version, menu IDs). Build number/date lines are **rewritten by every build** |
| `<Name>_Shared.rc` | **Generated** from `_Shared.inc` by the build (Inc2RC). Do not edit by hand |
| `<Name>.rc` | Resources (includes `_Shared.rc`), `Res/` icons etc. |
| `Make.cmd` | Copy of `Build/Make.cmd`; just calls `%OBJASM_PATH%\Build\OA_BUILD.cmd` |
| `BUILD_PRE.cmd` / `BUILD_POS.cmd` | Optional project hooks called before/after the build |
| `*.rap` | RadASM project file (IDE; `Build/RA_*.cmd`) |

Because each build bumps `BUILD_NUMBER`/`BUILD_DATE_STR` and relinks the `.exe`, a build leaves
diffs in `_Shared.inc`, `_Shared.rc` and the binary. Mention this to the user rather than silently
committing or reverting them.

## SysSetup: targets come from the source

`Build/OA_TARGET.cmd` parses the `SysSetup` line of the main `.asm` (text after `;` is ignored, so
`;, DEBUG(WND)` is a handy toggle):

```asm
SysSetup OOP, WIN64, WIDE_STRING, DEBUG(WND, ResGuard)
```

| Keyword | Effect |
|---|---|
| `OOP` | Enables the object support (needed for Object/MakeObjects) |
| `WIN32` / `WIN64` | GUI EXE |
| `CON32` / `CON64` | Console EXE |
| `NUI32` / `NUI64` | EXE without UI (services, tools) |
| `DLL32` / `DLL64`, `LIB32` / `LIB64` | DLL / static library |
| `UEFI32` / `UEFI64` | UEFI application (`OA_UEFI.cmd` converts to .efi; needs `EFI_TOOLKIT_PATH`) |
| `ANSI_STRING` / `WIDE_STRING` | Default string type (`CHR`, `CStr`, A/W API mapping) |
| `SUFFIX` | Appends bitness to the output name |
| `DEBUG(dev, opts)` | Debug build (`TARGET_MODE=DBG`); device `WND` (DebugCenter), `CON`, `LOG`; `ResGuard` resource tracking |
| `CPU(...)` | Optional SIMD/CPU feature target (see `Model.inc` `CPU` macro) |

Switching 32 <-> 64 or ANSI <-> WIDE is a one-word change *if* the code follows the neutral style.

## Includes and libraries

```asm
% include &IncPath&Windows\CommCtrl.inc       ;'%' expands the &Path& text macros
% includelib &LibPath&Windows\shell32.lib
% include &COMPath&COM.inc
MakeObjects Primer, Stream, WinPrimer, Window  ;Assemble object sources (ObjPath default)
LoadObjects Primer, Stream                     ;Or link prebuilt libs from Code/Objects/Lib/<bits><A|W>
```

- List objects **in inheritance order** (ancestors first), plus everything they reference.
  Missing ancestors cause "unknown ancestor"/undefined symbol errors at the `Object` line.
- `MakeObjects` = compile from source (safest while the library is changing);
  `LoadObjects` = faster, but requires up-to-date libs for the exact bitness and string type.
- ObjMem procedures (`StrLength`, `MemAlloc` helpers, `dword2dec`, Base64 ...) are prototyped in
  `Code/ObjMem/ObjMem.inc` and linked from `ObjMem32/64.lib` automatically by `SysSetup`.

## Build pipeline

`Make.cmd [NOPAUSE]` -> `OA_BUILD.cmd`:

1. `OA_TARGET` - read SysSetup
2. `OA_SET` - locate VS (vswhere or `OBJASM_VS_PATH`), Windows SDK, UASM, linker, lib, rc
3. `BUILD_PRE.cmd` (optional)
4. `OA_PRE` - delete old outputs, bump build info in `_Shared.inc`, regenerate `_Shared.rc`
5. `OA_MIDL` (type libraries), `OA_RES` (resources)
6. `OA_ASM` - `UASMxx @Build\Options\OPT_ASM_<RLS|DBG>_<32|64>.txt <Name>.asm`
7. `OA_LINK` - options `OPT_LNK_<CON|WIN|...>_<RLS|DBG>_<bits>.txt`
8. `OA_UEFI` (UEFI only), `BUILD_POS.cmd` (optional), `OA_POS` - cleanup

Diagnostics:
- Output goes to `Make.log`. **After a successful release build `OA_POS` deletes `Make.log`** (and
  `.obj/.pdb/.err`), so "no log + fresh exe" means success. On failure the log stays and ends with
  an `ERROR` banner.
- Assembler errors also produce `<Name>.err`. Read the **first** error; later ones are usually
  cascades. UASM reports macro-expansion lines - map back to the source line given in the trace.
- Running from Bash: `cmd //c ".\Make.cmd NOPAUSE"` inside the project folder (override `OBJASM_PATH` if it points to another checkout). Without `NOPAUSE` the
  error path waits for a key press and the command hangs.
- Rebuilding all samples: `Projects/MakeAll.cmd`, `Projects/X/MakeAll.cmd`.

## Typical build errors

| Symptom | Likely cause |
|---|---|
| Undefined symbol of an object/method | Object not in `MakeObjects` list, wrong order, or misspelled `Obj.Mtd` in `OCall` |
| Error at `ObjectEnd` / "unknown ancestor" | Ancestor not included before the definition |
| Type mismatch / A-W wrong function | Hard-coded `A`/`W` API, `CHRA` vs `CHR`, wrong `$OfsCStr` variant for the string type |
| Works in 64, fails in 32 (or reverse) | Used `rax`/`eax` instead of `xax`, `QWORD` instead of `XWORD`, `r8-r15` in shared code, missing `ArgReg` fallback |
| Linker: unresolved external `_Xxx@n` / `Xxx` | Missing `includelib`, ObjMem lib not rebuilt after adding a procedure, or prebuilt object lib stale -> use `MakeObjects` |
| Crash on call of a method | Abstract method not overridden, instance not `New`-ed (DMT pointer missing), or `Init` not called |
| Assembler finds nothing / "No project file found" | More than one or no `.asm` in the folder, or not run from the project folder |
| VS/SDK not found | `OBJASM_PATH`/`OBJASM_VS_PATH` wrong; run `Build/OA_INST.cmd` |
