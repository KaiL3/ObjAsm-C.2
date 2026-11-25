# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ObjAsm C.2: an object-oriented macro framework on top of MASM-syntax assemblers (UASM by default)
for Windows and UEFI, 32/64-bit, ANSI/WIDE. Almost everything is a macro, so assembler errors are
usually reported inside a macro expansion far away from the real cause. The source of truth is the
code: `Code/Macros/*.inc` (well documented macro headers) and the existing objects in `Code/Objects`.

Detailed knowledge lives in the project skills - load them instead of guessing:
- `.claude/skills/objasm` - language, object model, build chain, library development, house style.
- `.claude/skills/objasm-tls` - TLS/SChannel layer of NetCom (architecture, invariants, review log
  in `references/known-issues.md`).

## Repository layout

- `Build/` - build chain (`Make.cmd` -> `OA_BUILD.cmd` -> `OA_TARGET/SET/PRE/MIDL/RES/ASM/LINK/POS.cmd`),
  assembler/linker response files in `Build/Options`, UASM in `Build/Tools/Assembler`.
  `OA_INST.cmd` installs prerequisites and sets the environment variables.
- `Code/Macros/` - core macros (`Model.inc` = `SysSetup`, `Objects.inc` = OOP, `Debug.inc` ...).
- `Code/Objects/` - object library: one `<Name>.inc` (definition + implementation under `if IMPLEMENT`)
  and one `<Name>.asm` lib stub per object; `ObjIDs.inc`, `ObjErrs.inc`; build order in
  `Build/ObjectsX.lst` (ancestors first); prebuilt libs in `Lib/{32A,32W,64A,64W}`.
- `Code/ObjMem/` - procedure library (one procedure per .obj): templates in `Common/`, per-variant
  stubs in `32/` and `64/`, prototypes in `ObjMem.inc`. Applications use the *installed* copies in
  `Code/Inc/ObjAsm/ObjMem.inc` and `Code/Lib/<bits>/ObjAsm/ObjMem<bits>.lib`.
- `Code/Inc/` - Windows/COM/UEFI/third-party API includes (A and W variants must both exist).
- `Projects/X/` - bitness-neutral applications; the best source of patterns. `Projects/X/NetCom`
  contains the NetCom/TLS test programs (Core Test, Stress Test, Small Reverse Proxy Server).
- `Help/` - reference manuals (PDF), install docs.

## Build

Every source starts with `% include @Environ(OBJASM_PATH)\Code\Macros\Model.inc`; the target
(GUI/console/DLL/LIB/UEFI, 32/64, ANSI/WIDE, DEBUG) is taken from the `SysSetup` line of the main
`.asm`. A project folder holds exactly one `.asm` plus a copy of `Build/Make.cmd`.

**`OBJASM_PATH` on this machine points to a different checkout** (`D:\_Develop\ASM\ObjAsm-C.2`).
Override it per command when building this repository, and always pass `NOPAUSE`:

```bash
cd "<project folder>" && OBJASM_PATH='D:\_Develop\ASM\ObjAsm\KaiL3-C.2' cmd //c ".\\Make.cmd NOPAUSE"
```

Projects with a `<Name>_Shared.inc` call `find` in `BuildInfo.cmd`; from Git Bash that resolves to
the Unix `find` and fails. Use a wrapper `.cmd` that puts `%SystemRoot%\System32` first in `PATH`
(see the `objasm` skill). Result: a successful release build deletes `Make.log`; on failure read
`Make.log` and `<Name>.err` and fix the **first** error. Each build bumps the build number in
`_Shared.inc`, regenerates `_Shared.rc` and relinks the exe - these diffs are build artefacts.

Libraries:
- Objects, all variants: `Code/Objects/Build/MakeObjects3264AW.cmd`; one variant:
  `MakeObjects64W.cmd` etc.; one object: `MakeObject64W.cmd`.
- ObjMem: `Code/ObjMem/MakeObjMem3264.cmd` (or `...32` / `...64`); builds and installs lib + include.
- TLS/NetCom syntax check in all four variants (writes only to the given dir):
  `bash .claude/skills/objasm-tls/scripts/assemble_tls.sh <scratch dir>`

There is no unit-test framework. Verification = clean build of the affected library variants plus
running the relevant program in `Projects/X` (for NetCom/TLS: Core Test client/server, Stress Test).

## Code rules

- Sources are CRLF and single-byte (ASCII/CP1252, some headers contain box-drawing bytes). Never
  re-encode to UTF-8; prefer targeted edits over rewriting files.
- Code and comments are in English.
- Write bitness-neutral (`xax`, `xsi`, `XWORD`, `POINTER`) and string-type-neutral (`CHR`, `$OfsCStr`,
  un-suffixed API/ObjMem names) code; library objects must assemble in 32A/32W/64A/64W.
- Object life cycle: `New` -> `Init` (calls `ACall xsi.Init, pOwner` first) -> `Done` (own cleanup,
  then `ACall xsi.Done`) -> `Destroy`.
- Match house style: Hungarian prefixes, standard header comment above every Method/procedure,
  bump `Version:` and add a Notes line in the file header when changing a library object.
- Library objects do not include the Windows headers they need; the application `.asm` must.
