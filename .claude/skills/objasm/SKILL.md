---
name: objasm
description: Guide for developing with and on the ObjAsm framework (object-oriented MASM/UASM assembler for Windows/UEFI, 32/64-bit, ANSI/WIDE). Use this skill whenever you read, write, debug, build, or review ObjAsm code - any .asm/.inc/.cop file using SysSetup, Object/ObjectEnd, Method/MethodEnd, OCall/ACall/ICall, New/Destroy, MakeObjects/LoadObjects, xax/xsi registers, $OfsCStr, Dbg* macros - and whenever the user asks to create an ObjAsm application, add or change a library object in Code/Objects, add an ObjMem procedure, fix assembler/linker errors, or run Make.cmd / OA_BUILD. Use it even if the user just says "assembler", "asm project", "object library" or names an ObjAsm object such as Collection, WinApp, ConsoleApp, NetCom or TLS_*.
---

# ObjAsm development

ObjAsm is a macro layer over MASM-syntax assemblers (UASM by default) that adds objects, inheritance,
virtual/interface/dynamic methods, event dispatch and a large runtime library. Nearly everything is a
macro, so errors are often macro-expansion errors far from the real cause. The source of truth is the
code itself: `Code/Macros/*.inc` (macro headers are well documented) and existing objects in
`Code/Objects`. When unsure about a macro, grep its definition and read the header comment rather
than guessing - the behaviour differs from plain MASM in many small ways.

## Repository map

| Path | Content |
|---|---|
| `Build/` | Build chain: `Make.cmd` -> `OA_BUILD.cmd` -> `OA_TARGET/SET/PRE/MIDL/RES/ASM/LINK/POS.cmd`; `Options/` = assembler/linker response files; `Tools/Assembler/UASM32/64.exe` |
| `Code/Macros/` | Core macros: `Model.inc` (SysSetup, naming rules), `Objects.inc` (OOP), `System.inc`, `Memory.inc`, `Strings.inc`, `Debug.inc`, data-structure macros |
| `Code/Objects/` | Object library: one `Name.inc` (definition + implementation) and `Name.asm` (lib build stub) per object; `ObjIDs.inc`, `ObjErrs.inc`; `Build/` lib scripts and `.lst` lists; `Lib/{32A,32W,64A,64W}` prebuilt libs |
| `Code/ObjMem/` | Procedure library: `Common/*.inc` templates, `32/`+`64/` per-variant stubs, `ObjMem.inc` prototypes, `ObjMem32/64.lib` |
| `Code/Inc/` | API includes: `Windows/`, `COM/`, `UEFI/`, `ObjAsm/`, third-party (Lua, PCRE, CUDA, libpng ...) |
| `Code/OA_Setup32/64.inc` | Communal path symbols (`IncPath`, `LibPath`, `ObjPath`, `MacPath`, `COMPath`, `ObjMemPath`) |
| `Projects/X/` | Bitness-neutral sample/real projects (best place to copy patterns from); `Projects/32`, `64` |
| `Help/` | `ObjAsm_Reference_Volume-I..III.pdf`, install docs, `MS_ABI_x64.txt` |

`OBJASM_PATH` (env var) must point to the repo root; every source starts with
`% include @Environ(OBJASM_PATH)\Code\Macros\Model.inc`.

## Golden rules (read before editing)

1. **Encoding & line endings.** Sources are CRLF and single-byte (ASCII / ISO-8859-1 / CP1252; some
   headers contain box-drawing bytes). Never re-encode files to UTF-8 and never introduce non-ASCII
   characters in new code. Prefer targeted Edit operations over rewriting whole existing files.
2. **Write bitness-neutral code.** Use `xax, xbx, xcx, xdx, xsi, xdi, xbp, xsp` instead of
   `eax/rax`, `XWORD`/`POINTER` for pointer-sized data, `sizeof(POINTER)`. Use 32-bit registers
   (`eax`, `ecx`) only for DWORD data. Guard truly bitness-specific code with
   `if TARGET_BITNESS eq 32 ... else ... endif`.
3. **Write string-type-neutral code.** Use `CHR` and `sizeof(CHR)`, `CStr`/`$OfsCStr("...")`, and
   the un-suffixed API/ObjMem names (`StrLength`, `StrNew`, `CreateWindowEx`) which resolve to A/W via
   `TARGET_STR_TYPE`. Use explicit `A`/`W` forms (`CHRA`, `$OfsCStrA`, `StrNewW`) only when the data
   format is fixed (e.g. protocol bytes, UTF-8 payloads). Wrong A/W mixing is a common bug class.
4. **Follow the object life cycle.** `New` -> `Init` (first thing: `ACall xsi.Init, pOwner`) ->
   use -> `Done` (release own resources first, `ACall xsi.Done` last) -> `Destroy`/memory release.
   `Done` must stay the first virtual method (it is in `Primer`).
5. **Match house style** (see `references/conventions.md`): Hungarian prefixes (`dCount`, `pItems`,
   `hWnd`, `xArg`), standard header comment above every Method/procedure/macro (text starts at
   column 15), comments aligned at the right with `;`, 2-space indentation inside procedures.
6. **Verify by building.** After changes, build the affected project or object library (see
   below) and read `Make.log` / `*.err`. Do not claim success without a clean build.

## Typical tasks -> where to look

- **Understand / use the object model** (Object, methods, events, calls, ArgReg, Embed, Override,
  errors): read `references/object-model.md`.
- **Create or build an application project, set targets, debug output, fix build errors**: read
  `references/build-and-projects.md`.
- **Add/modify a library object in `Code/Objects` or a procedure in `Code/ObjMem`**: read
  `references/library-development.md`.
- **Naming, headers, macro cheat-sheet**: `references/conventions.md`.
- **TLS / SChannel / NetCom encryption** (`TLS_*` objects, `OnReceivedTLS` ...): use the separate
  `objasm-tls` skill (`.claude/skills/objasm-tls`), which has the architecture and the review log.

## Minimal application skeleton (64-bit console, OOP)

```asm
% include @Environ(OBJASM_PATH)\Code\Macros\Model.inc
SysSetup OOP, CON64, WIDE_STRING;, DEBUG(WND)

% include &IncPath&Windows\tlhelp32.inc             ;Needed by ConsoleApp (Process32First...)

MakeObjects Primer, Stream, ConsoleApp              ;Ancestors first, in inheritance order

Object Application, 0, ConsoleApp                   ;0 = no runtime type ID needed
  RedefineMethod    Run
ObjectEnd

.code
Method Application.Run, uses xsi
  SetObject xsi
  OCall xsi.PrintLn, $OfsCStr("Hello ObjAsm")
MethodEnd

start proc
  SysInit
  OCall $ObjTmpl(Application)::Application.Init, NULL   ;NULL = no owner
  OCall $ObjTmpl(Application)::Application.Run
  OCall $ObjTmpl(Application)::Application.Done
  SysDone
  invoke ExitProcess, 0
start endp

end
```

Put it in its own folder as `<Name>.asm` (exactly one `.asm` there), copy `Build/Make.cmd` next to
it and run it. Library objects do **not** include the Windows/COM headers they need - the
application must (`Symbol not defined` / `INVOKE requires prototype` inside `Code/Objects/X.inc`
means a missing `% include &IncPath&Windows\...` in your `.asm`). Find the right includes by
grepping an existing project that uses the same object (`grep -rl "MakeObjects.*ConsoleApp" Projects`). Check an existing project in `Projects/X` with the same app type (`WinApp`/`SdiApp`/`MdiApp`
GUI, `ConsoleApp` CLI ...) before inventing structure.

## Building from this environment

The build scripts are `cmd` batch files using delayed expansion and ANSI colour escapes. Run them
through cmd with `NOPAUSE` so a failure does not block on `pause`:

```bash
cd "<project folder>" && OBJASM_PATH='<repo root, backslashes>' cmd //c ".\\Make.cmd NOPAUSE"
```

**Check `OBJASM_PATH` first** (`echo $OBJASM_PATH`): it may point to a *different* ObjAsm checkout
than the one being edited, in which case the build silently uses the other tree's macros and
objects. Override it per command as above when testing changes in this repository. Use `.\\Make.cmd`
(cmd does not search the current dir when invoked this way). A WIDE console program writes UTF-16
when its output is piped, so captured text shows spaced letters - that is expected.

Projects with a `<Name>_Shared.inc` run `Build/Tools/BuildInfo.cmd`, which calls `find /V /N`.
Started from Git Bash, the inherited PATH resolves `find` to the Unix tool and the build stops at
"BuildInfo is processing ..." with an ERROR banner. Put System32 first: use a small wrapper `.cmd`
(written with the Write tool, never via `printf` - escaped `\n` in paths has bitten before):

```bat
@echo off
setlocal
set "OBJASM_PATH=D:\_Develop\ASM\ObjAsm\KaiL3-C.2"
set "PATH=%SystemRoot%\System32;%SystemRoot%;%PATH%"
call "%CD%\Make.cmd" NOPAUSE
```

and run it from the project folder: `cd "<project>" && cmd //c "<wrapper path in Windows form>"`.
`LNK1104 cannot open <Name>.exe` means the program is still running. Note that `OA_PRE` deletes
`.obj/.pdb/.res` of the project even when the build fails later.

Then read `Make.log` (and any `<Name>.err` the assembler leaves). A successful release build deletes `Make.log` - a fresh `.exe` and no log means success. UASM errors cite the line inside
the *macro expansion*; look at the first error, find the source line it refers to, and check the
macro arguments there. Requirements: `OBJASM_PATH` set, Visual Studio (link.exe/lib.exe) and the
Windows SDK detectable by `Build/OA_SET.cmd`.

## Debugging at runtime

Enable with `DEBUG(WND)` (DebugCenter window, `Projects/X/DebugCenter`) or `DEBUG(CON)` / `DEBUG(LOG)` in
`SysSetup`; add `ResGuard` to track leaks (`ResGuard_Start/Show/Stop`). Then use `DbgText`,
`DbgStr`, `DbgHex`, `DbgDec`, `DbgFloat`, `DbgMem`, `DbgObject`, `DbgApiError`, `DbgComError`,
`DbgLine`, `DbgWarning`. They compile to nothing when DEBUG is off, so they can stay in code.
