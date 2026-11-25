# Conventions and macro cheat-sheet

Full rules: header of `Code/Macros/Model.inc` ("Notes about ObjAsm").

## Naming

- Constants, structures, native types: `UPPER_CASE` (`MAX_SIZE`, `OBJECT_LOCK`).
- Variables, fields, arguments: CamelCase with type prefix.

| Prefix | Type | Prefix | Type |
|---|---|---|---|
| `x` | XWORD (pointer-sized int) | `p` / `pp` | POINTER / pointer to pointer |
| `b` | BYTE / BOOL | `h` | HANDLE |
| `w` / `d` / `q` / `o` | WORD / DWORD / QWORD / OWORD | `sz` | zero-terminated string constant |
| `sb sw sd sq` | signed variants | `c` | CHR / character buffer (`cBuffer[MAX_PATH]:CHR`) |
| `r4 r8 r10` | REAL4/8/10 | `v` / `m` | vector / matrix |
| `$Name` | macro function returning text/number | `??Name` | cross-macro hidden symbol - don't touch |
| `$$Name` | macro-local scratch symbol | `TPL_` / `POB_` | object template / object pointer type |

Objects: `PascalCase` names, type ID `<Name>ID`; events `On<Something>`.

## Header comments (descriptions start at column 15)

```asm
; --------------------------------------------------------------------------------------------------
; Method:     Collection.Insert
; Purpose:    Inserts item at the end of the collection.
; Arguments:  Arg1: -> Item.
; Return:     xax -> Inserted item or NULL on failure.
; Note:       ...
```

Use `Procedure:` / `Macro:` / `Method:` / `Object:` accordingly. `->` means "pointer to".
File headers carry Title/Author/Version/Purpose/Notes with a version history.

## Code layout

- 2-space indentation inside procs/methods, labels/directives at column 0.
- End-of-line comments start with `;` aligned to a common column (~col 57) - follow surrounding code.
- High-level control flow is preferred: `.if/.elseif/.else/.endif`, `.while/.endw`,
  `.repeat/.until`, `.break`, `.continue`. Local labels `@@:` / `@F` / `@B` for short jumps.

## Frequently used macros

| Area | Macros (definition file) |
|---|---|
| Setup | `SysSetup`, `SysInit`, `SysDone`, `CPU` (`Model.inc`) |
| Moves | `m2m dst, src, reg` (mem->mem via reg), `m2z mem` (zero), `c2m`, `s2s`, `mrm` (`System.inc`) |
| Calls | `$invoke(...)` (returns xax inline), `$call`, `PushAll/PopAll` |
| Size helpers | `$32(x)`, `$64(x)`, `$SubReg`, `$ArgReg`, `ArgReg`, `LocReg` |
| Strings | `CStr name, "..."` (const), `DStr` (data), `TStr`, `$OfsCStr("...")`, explicit `CStrA/CStrW`, `$OfsCStrA/W` (`Strings.inc`, `AStrings.inc`, `WStrings.inc`) |
| Memory | `MemAlloc size[, flags]` (xax -> block), `MemReAlloc`, `MemFree p`, `StackAlloc`, `FillMemZero` (`Memory.inc`) |
| Bits | `BitSet/BitClear/BitToggle`, `.ifBitSet` (`Memory.inc`) |
| Math | `uMin/uMax/sMin/sMax`, `$RGB`, `$Log2`, `fMath.inc`, `qMath.inc`, `SIMD_Math.inc` |
| Lists | `SDLL`, `LDLL`, `LSLL`, `CDLL` macros (linked lists) |
| Exceptions | `Exception32.inc` / `Exception64.inc` |
| Debug | `DbgText`, `DbgStr`, `DbgHex`, `DbgDec`, `DbgFloat`, `DbgMem`, `DbgObject`, `DbgVMT`, `DbgApiError`, `DbgComError`, `DbgLine`, `DbgWarning`, `DbgClearAll`, `ResGuard_*` (`Debug.inc`) |

Symbols set by the build/SysSetup that code may test: `TARGET_BITNESS` (32/64),
`TARGET_STR_TYPE` (`STR_TYPE_ANSI`/`STR_TYPE_WIDE`), `TARGET_STR_AFFIX` (A/W), `TARGET_MODE`,
`TARGET_PLATFORM`, `DEBUGGING`.

If a macro is not listed here, `grep -n "^<Name> macro" Code/Macros/*.inc` and read its header.
