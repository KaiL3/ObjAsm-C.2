# ObjAsm object model

Source of truth: `Code/Macros/Objects.inc` (each macro has a header comment). Base object of the
library: `Code/Objects/Primer.inc`.

## Contents
1. Defining an object
2. Method kinds
3. Implementing methods (pSelf, SetObject, ArgReg)
4. Calling methods
5. Instances: New / Init / Done / Destroy / Embed
6. Events (Windows messages, COM dispatch)
7. Overriding at runtime, dynamic methods
8. Error handling
9. Thread safety
10. Internals worth knowing

## 1. Defining an object

```asm
Object MyParser, MyParserID, Primer            ;Name, type ID (0 if unused), ancestor
  RedefineMethod    Done
  RedefineMethod    Init,           POINTER, PSTRING      ;-> Owner, -> Text
  VirtualMethod     Parse                                 ;Returns eax = OBJ_OK or error
  VirtualAbstract   OnToken,        PSTRING, DWORD        ;Must be overridden by descendants
  StaticMethod      Reset
  Private
    StaticMethod    SkipBlanks
  PrivateEnd

  DefineVariable    pText,          PSTRING,  NULL
  DefineVariable    dPos,           DWORD,    0
  Embed             Tokens,         Collection            ;Embedded instance (no pointer)
ObjectEnd
```

- Argument lists in method declarations are **types only**; `pSelf` is implicit and never listed.
- The trailing `;` comment on each declaration documents the arguments - keep that habit.
- `DefineVariable Name, Type, Init` defines instance data in the template; `RedefineVariable`
  changes an inherited variable's initial value.
- The ancestor must already be known (included via `MakeObjects`/`LoadObjects` before).
- Type IDs live in `Code/Objects/ObjIDs.inc` for library objects; application objects either use 0
  or define their own ID constant in an app include.
- Namespaces: `ObjNamespace` and the `Nsp:Obj` syntax exist but are rarely used; default prefix is
  `OA_`.

## 2. Method kinds

| Declaration | Dispatch | Use for |
|---|---|---|
| `VirtualMethod` / `VirtualAbstract` | VMT (per object type) | Normal overridable methods |
| `RedefineMethod` | replaces an inherited entry | Overriding an ancestor method (any kind) |
| `StaticMethod` | direct call | Non-overridable helpers, fastest |
| `InterfaceMethod` / `InterfaceAbstract` | IMT (COM vtable order) | COM interfaces; order = vtable order |
| `DynamicMethod` / `DynamicAbstract` | address stored in the *instance* | Per-instance behaviour (callbacks, subclassing) |
| `InlineMethod` | expanded as macro | Tiny accessors |
| `ObsoleteMethod` | traps when called | Keeping slots after removing a method |
| `VirtualEvent` / `StaticEvent` / `DynamicEvent` / `InterfaceEvent` | method + event table | Message handlers (see 6) |

Calling an abstract method that was never overridden crashes (GPF) - by design.

## 3. Implementing methods

Implementation goes below the definition, inside `if IMPLEMENT ... endif` for library objects (the
switch is set automatically by MakeObjects/the lib stub). Pattern from `Collection.inc`:

```asm
; --------------------------------------------------------------------------------------------------
; Method:     MyParser.Init
; Purpose:    Initialize the object.
; Arguments:  Arg1: -> Owner object.
;             Arg2: -> Text to parse.
; Return:     Nothing.

Method MyParser.Init, uses xsi, pOwner:POINTER, pText:PSTRING
  ArgReg pOwner:rdx                                     ;64-bit: use rdx directly

  SetObject xsi                                         ;xsi = pSelf, typed as MyParser
  ACall xsi.Init, $ArgReg(pOwner)                       ;Ancestor first
  m2m [xsi].pText, pText, xdx
  m2z [xsi].dPos
  OCall [xsi].Tokens::Collection.Init, xsi, 16, 16, COL_MAX_CAPACITY
MethodEnd
```

- `Method Obj.Mtd, uses <regs>, Arg:Type, ...` / `MethodEnd`. `uses` lists callee-saved regs you
  modify (`xbx xsi xdi`, plus `r12-r15` when used in 64-bit only code).
- `pSelf` is available as the first (hidden) argument. `SetObject xsi` loads it and *assumes* the
  register to the object type so `[xsi].Field` works. `ReleaseObject` drops the assumption (needed
  before reusing the register for something else in the same method).
- In 64-bit the first args arrive in `rcx` (pSelf), `rdx`, `r8`, `r9`. `ArgReg name:reg` makes
  `$ArgReg(name)` mean the register in 64-bit and the stack argument in 32-bit - use it to avoid
  spilling, but remember those registers are clobbered by any call you make.
- `SetObject xcx` (no `uses`) is fine for leaf methods that make no calls.
- `ExitMethod` leaves early; idiomatic alternative is `jmp @@EOM` (label `@@EOM` is provided by
  MethodEnd).
- Return values: `eax`/`xax` like plain procedures. Library convention: `eax = OBJ_OK` or an error
  code for methods that can fail; `xax -> object/buffer` for getters.

## 4. Calling methods

Expression format: `Instance::ObjectName.MethodName` (`Instance` can be a register, `[reg]`,
`[reg].Field`, a local instance name, or `$ObjTmpl(Obj)`).

| Macro | Meaning |
|---|---|
| `OCall inst::Obj.Mtd, args` | Normal call (virtual/static/dynamic/interface resolved from the declaration) |
| `OCall xsi.Mtd, args` | Short form when `xsi` was typed via `SetObject` |
| `ACall xsi.Mtd, args` | Call the *ancestor's* implementation (inside an override) |
| `DCall inst::Obj.Mtd` | Direct call of this object's implementation, bypassing dispatch |
| `TCall inst::Obj.Mtd` | Call via the address in the object template |
| `ICall pItf::IInterface.Mtd, args` | COM interface call (`Code/Inc/COM`) |
| `$OCall(...)` / `$invoke(...)` | Function-form returning `xax`, usable inside expressions: `.if $invoke(PtInRect, addr R, Pnt) != FALSE` |

Arguments follow `invoke` rules: `addr local`, `offset global`, `$OfsCStr("text")`, registers,
memory. Do not pass `xax`/`xcx`/`xdx` as arguments in 64-bit when earlier arguments are computed
into them - the macros load registers in a fixed order.

## 5. Instances

```asm
local Parser:$Obj(MyParser)                   ;Instance on the stack
local pParser:$ObjPtr(MyParser)               ;Typed pointer

New Parser::MyParser                          ;Copies the template into the local instance
OCall Parser::MyParser.Init, xsi, pText
...
OCall Parser::MyParser.Done                   ;Stack/embedded instances: Done only

New MyParser                                  ;Heap instance, xax -> instance
mov pParser, xax
OCall pParser::MyParser.Init, xsi, pText
...
Destroy pParser                               ;NULL-safe: calls Done, then frees memory
```

- `$Obj(X)` = instance type, `$ObjPtr(X)` = pointer type, `$ObjTmpl(X)` = the global template
  (used as the singleton application object: `OCall $ObjTmpl(Application)::Application.Init`).
- `Kill` is `Destroy` without the NULL check. Clear the pointer yourself (`m2z pParser`) if it may be reused.
- `Embed` instances are part of the owner's memory: never `Destroy` them, only call `Done` from the
  owner's `Done`.
- Ownership: pass the owning object as `pOwner` to `Init`; errors propagate to the owner.
- Collections (`Collection`, `DataCollection`, ...) dispose their items with `Dispose*`/`Done` -
  read the object's "GLOBAL INVARIANTS" header before relying on ownership.

## 6. Events

```asm
Object Application, ApplicationID, SdiApp
  VirtualEvent      OnCommand,  WM_COMMAND
  VirtualEvent      OnClose,    WM_CLOSE, WM_QUERYENDSESSION
ObjectEnd

Method Application.OnCommand, uses xsi, wParam:WPARAM, lParam:LPARAM
  SetObject xsi
  ...
  xor eax, eax                                          ;Zero = handled
MethodEnd
```

Window objects (`WinPrimer`, `Window`, `Dialog*`, `WinApp`, `SdiApp`, `MdiApp`) dispatch messages
through the event translation table; handlers receive `wParam, lParam`. Unhandled messages fall
through to the default window procedure as implemented by the ancestor. `IDispEvent` maps COM
`IDispatch::Invoke` DISPIDs to methods.

## 7. Override and dynamic methods

```asm
Override [xsi].GdiObjects::XWCollection.DestroyItem, GdiObjects.DestroyItem
```

Replaces the method address for one instance (dynamic methods) or the table (virtual/interface).
Do not pass a procedure address in `r11` - it is used internally.

## 8. Error handling

Every `Primer` descendant has `dErrorCode` (`OBJ_OK` when fine) and `pErrorCaller`.
- `OCall xsi.ErrorReport, NULL, ERROR_CODE` sets the code and propagates it up the owner chain;
  pass `NULL` (or `xsi`) as caller when you are the originator. Returns `eax = error code`.
- `ErrorSet` sets without propagation, `ErrorClear` resets the chain.
- Library error codes: `Code/Objects/ObjErrs.inc`; application codes belong in a separate app file.
- For Win32 failures use `DbgApiError` in debug builds and report a meaningful code.

## 9. Thread safety

Objects with `DefineVariable ObjLock, OBJECT_LOCK, {}` use `LockObjectAccess inst` /
`UnlockObjectAccess inst` (instance in a non-volatile register). Respect each object's documented
rules (e.g. Collection must not be modified during `ForEach`).

## 10. Internals worth knowing

- Dual Method Table: IMT at positive offsets (COM-compatible vtable), VMT at negative offsets,
  pointer to the event table in between. First instance field is the DMT pointer.
- Object metadata (templates, IDs, events) is chained from `p1stOMD`; `DbgObject`, `DbgVMT`,
  `DbgIMT` dump it at runtime.
- Including an object definition twice is guarded, but inheritance order still matters.
