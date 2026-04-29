# Ghidra Import Scripts

Generates Ghidra import scripts that apply CommonLib type definitions, vtable
layouts, function signatures, and address-library-derived symbols to Skyrim SE,
Skyrim AE, and Fallout 4 AE binaries.

## Supported game versions

| Game           | Version label | Address library     | CommonLib repo       |
|----------------|---------------|---------------------|----------------------|
| Skyrim SE      | `se`          | `1-5-97-0`          | `powerof3/CommonLibSSE` |
| Skyrim AE      | `ae`          | `1-6-1170-0`        | `powerof3/CommonLibSSE` |
| Fallout 4 AE   | `ae`          | `1-11-191-0`        | `libxse/commonlibf4` |


---

## Project layout

```
.
├── extern/
│   ├── CommonLibSSE/                powerof3/CommonLibSSE
│   ├── CommonLibF4/                 libxse/commonlibf4 (+ commonlib-shared)
│   └── AddressLibraryDatabase/      meh321 — provides skyrimae.rename
├── addresslibrary/
│   ├── sse/version-1-5-97-0.bin     SE
│   ├── sse/versionlib-1-6-1170-0.bin AE
│   └── f4/version-1-11-191-0.bin    F4 AE (primary)
├── extras/
│   ├── SkyrimSE.pdb                 fallback symbol names for Skyrim SE
│   └── IDAImportNames_1.11.191.0.py fallback symbol names for F4 AE
├── exes/
│   ├── skyrim/se/SkyrimSE.exe
│   ├── skyrim/ae/SkyrimSE.exe
│   └── f4/ae/Fallout4.exe
├── ghidra/                          Ghidra install (12.x)
├── ghidraprojects/                  Headless Ghidra projects (auto-created)
├── ghidrascripts/                   Generated import scripts (output)
└── scripts/
    ├── run_headless.py              Unified headless runner
    ├── core/
    │   ├── clang_types.py           clang AST + record-layout parser
    │   ├── ghidra_import_gen.py     Game-agnostic Ghidra script emitter
    │   ├── pdb_symbols.py           PDB public-symbol extraction
    │   └── template_types.py        C++ template alias generator
    ├── commonlibsse/
    │   ├── parse_commonlib_types.py Generates SE + AE scripts
    │   ├── reloc_parser.py          RELOCATION_ID(SE,AE) regex scanner
    │   └── address_library.py       SE + AE binary loader
    └── commonlibf4/
        ├── parse_commonlib_types.py Generates F4 AE script
        ├── reloc_parser.py          libxse single-ID regex scanner
        ├── address_library.py       AE address library loader
        └── ida_names.py             Parses extras/IDAImportNames_*.py
```

---

## Prerequisites

- Python 3.10+ (64-bit). Install deps: `pip install pdbparse pyghidra`
- LLVM/Clang on `PATH` (used for `-ast-dump` and `-fdump-record-layouts`)
- Ghidra 12.x extracted into `./ghidra/`
- Submodules initialized:

```
git submodule update --init --recursive
```

---

## Generating the import scripts

Run each pipeline from the repo root. They read directly from `extern/<repo>/`
and write into `ghidrascripts/`.

```bash
python scripts/commonlibsse/parse_commonlib_types.py   # SE + AE
python scripts/commonlibf4/parse_commonlib_types.py    # F4 AE
```

Outputs:
- `ghidrascripts/CommonLibImport_SE.py`
- `ghidrascripts/CommonLibImport_AE.py`
- `ghidrascripts/CommonLibImport_F4_AE.py`

Re-run whenever a `extern/CommonLib*` submodule is updated, when address
library `.bin` files change, or when generator code under `scripts/core/` is
modified.

---

## Running headless against the binaries

Place each binary under `exes/<game>/<version>/`. The runner auto-discovers all
present targets.

```bash
python scripts/run_headless.py                # all games × versions
python scripts/run_headless.py skyrim         # all skyrim versions
python scripts/run_headless.py skyrim ae      # specific
python scripts/run_headless.py f4 ae
```

For each target the runner:
1. Opens or creates `ghidraprojects/<game>_<version>/`
2. Imports the `.exe` if not already present
3. Runs the matching `CommonLibImport_*.py`
4. Saves the program
5. Prints a verification summary (named functions, type spot-checks,
   game-specific labels/functions)

Exit code is non-zero if any target's spot-checks or sanity thresholds fail.

---

## Pipeline overview

```
extern/CommonLib*/include/    ─── reloc_parser.py         ──► symbols (game-version offsets)
addresslibrary/<game>/*.bin   ─── address_library.py      ──┘

extern/CommonLib*/include/    ─── clang -ast-dump         ──► enums, classes, methods, vtables
                              ─── clang -fdump-record-layouts ─► struct field offsets + sizes

extras/SkyrimSE.pdb           ─── pdb_symbols.py          ──► Skyrim fallback symbols
extras/IDAImportNames_*.py    ─── ida_names.py            ──► F4 fallback symbols

parse_commonlib_types.py      ─── orchestrates each game ─┐
ghidra_import_gen.py          ─── emits the .py script ───┴─► ghidrascripts/CommonLibImport_*.py
```

**Symbol sources** (priority order):

1. `RELOCATION_ID(SE, AE)` (Skyrim) or `REL::ID Name{id}` (F4 libxse) macros
2. `Offsets_RTTI.h`, `Offsets_NiRTTI.h`, `Offsets_VTABLE.h` labels
3. `RE::Offset::` namespace IDs (Skyrim)
4. CommonLibSSE `src/*.cpp` cross-references (Skyrim only)
5. Fallback: AE rename DB (`skyrimae.rename`) — Skyrim AE only
6. Fallback: PDB public symbols (`SkyrimSE.pdb`) — Skyrim
7. Fallback: IDA `NAME(addr, …)` script (`IDAImportNames_1.11.191.0.py`) — F4 AE

Fallback symbols whose address lands on a known CommonLib vtable slot are
re-tagged with the slot's CommonLib name (and filed under `/CommonLibSSE/`
or `/CommonLibF4/` in the Data Type Manager) instead of the original
PDB/rename/IDA name.

---

## Generated script behaviour

Each `CommonLibImport_*.py` is a self-contained Jython script that:

- Creates all enums, structs, primary + secondary vtable structs under
  `/CommonLib<Game>/`
- Populates struct fields with computed offsets and types (including
  flattened base-class fields and per-class secondary `__vftable_<base>`
  pointers for multi-inheritance)
- Names virtual functions by walking vtable addresses in the binary
- Applies function signatures by building a `FunctionDefinitionDataType`
  directly from the pipeline's structured type descriptors (falling back
  to `CParserUtils.parseSignature()` with `void *` substitution for the
  rare cases the structured path can't resolve)
- Labels every known address-library symbol
- Adds a `Source: <origin>` plate comment to each named function so you
  can tell which fallback table claimed a name

The scripts are idempotent — safe to re-run; they overwrite types/labels.

---

## Known limitations

The pipeline guarantees correctness as a hard rule: every emitted struct field
or signature parameter points at the **exact** type declared in the source.
Anything we can't pin to an exact type is left as bare `ptr` (Ghidra renders
this as `void *`) instead of being upgraded to a guessed type. Counts below
are from the most recent run.

| | F4 AE | Skyrim AE | Skyrim SE |
| --- | --- | --- | --- |
| Total struct fields | 24,216 | 34,243 | 34,231 |
| Bare-`ptr` fields | 58 (0.24%) | 84 (0.25%) | 84 (0.25%) |
| Signatures with unresolved template params | 0 | 0 | 0 |
| Struct fields referencing unresolved template params | 0 | 0 | 0 |
| Vtable structs built | 1,292 | 2,023 | 2,024 |

The remaining ~0.25% bare-`ptr` fields fall into a small number of categories
that genuinely *are* opaque pointers in the source:

- **Function-pointer typedef fields.** Members declared as a pointer to a
  named function-type alias (e.g. Havok `ShapeFuncs::getSupportingVertexFunc`,
  `BSAudioCallbacks::idCallback`, the various `_readFn` / `_writeFn`
  callbacks) are 8-byte function pointers but the pipeline doesn't currently
  emit a Ghidra `FunctionDefinitionDataType` for the typedef, so the field is
  typed as plain `ptr`. The byte layout is exact; only the parameter
  annotation is missing. Skyrim contains ~24 such fields in `ShapeFuncs` /
  `ShapeFuncs2` and a handful elsewhere.
- **Type-erased STL containers.** `std::_Tree_node<..., void*>` and similar
  STL nodes use `void*` as their second template argument, which makes
  `_Left` / `_Right` / `_Parent` truly `void*` at the source level. The
  bare `ptr` type is correct here.
- **STL stream classes.** `basic_ostream`, `basic_ostringstream`, `ios_base`
  and a handful of related types have `has_vtable=True` but their virtual
  destructors / methods are declared in MSVC headers we don't pull in. Their
  derived `__vftable` pointers stay bare. F4: 6 fields, Skyrim: 7 fields.
- **Skipped uninstantiated-template signatures.** Template member functions
  whose RELOCATION_ID lives on the unspecialised template (e.g.
  `BSPointerHandleManagerInterface<T>::CreateHandle(T*)`) have a parameter
  type that's literally the template parameter `T`. Rather than apply a
  signature with `T*` (which would resolve to `void*` in Ghidra and so
  silently mis-type the argument), the orchestrators skip the signature
  entirely and only apply the function's name. ~2-3 such symbols per game.
- **Fallback-symbol coverage.** F4 fallback names come from the IDA script
  `extras/IDAImportNames_1.11.191.0.py` (3,639 hand-named addresses), so
  most F4 names still come from the CommonLibF4 ID database; the IDA script
  fills in helpers and globals that have no `REL::ID` mapping. Skyrim
  fallback names come from `extras/SkyrimSE.pdb`'s public-symbol table.
- **Special-character template names.** A handful of x86 emit-helper templates
  use byte literals as non-type template arguments (`BRANCH5<'\xe8'>`,
  `BRANCH6<'\x15'>`); the resulting struct names contain backslash escapes.
  They work in Ghidra but render unusually in the Data Type Manager.

Outside that, every struct field's offset, size, and (where typed) referenced
type matches what clang emits for the layout. Vtable structs include exact
slot indices from clang's `-fdump-vtable-layouts` (preferred) or the AST
fallback, and per-(class, subobject offset) secondary vtable structs are
generated for multi-inheritance so each `__vftable_<base>` field at a
non-zero offset points at the most-derived class's secondary struct rather
than the base's primary.

---
