#  Ghidra Import Scripts

Toolchain that reverse-engineers Skyrim SE/AE by importing CommonLibSSE type definitions,
vtable layouts, and function signatures into Ghidra.

---

## Table of Contents

1. [Project Layout](#project-layout)
2. [Plugin Build](#plugin-build)
3. [Ghidra Pipeline Overview](#ghidra-pipeline-overview)
4. [Prerequisites](#prerequisites)
5. [Setup](#setup)
6. [Running the Generator](#running-the-generator)
7. [Running the Ghidra Scripts](#running-the-ghidra-scripts)
8. [Pipeline Files Reference](#pipeline-files-reference)
9. [extra\_types.json Reference](#extra_typesjson-reference)
10. [template\_types.py Reference](#template_typespy-reference)
11. [Known Limitations](#known-limitations)

---

## Project Layout

```
GhidraImportScripts/
├── plugin/                     SKSE plugin build project
│   ├── src/                    C++ source files
│   ├── cmake/                  CMake helpers (version templates, triplets)
│   ├── CMakeLists.txt
│   ├── CMakePresets.json
│   └── vcpkg.json
├── extern/
│   ├── CommonLibSSE/           CommonLibSSE submodule (powerof3/dev branch)
│   └── AddressLibraryDatabase/ AE rename database submodule
├── addresslibrary/
│   ├── version-1-5-97-0.bin    SE address library (ID → offset)
│   └── versionlib-1-6-1170-0.bin  AE address library
├── pdbs/
│   ├── GhidraImport_SE_D.pdb   SE debug PDB — written here by the plugin build
│   ├── GhidraImport_AE_D.pdb   AE debug PDB — written here by the plugin build
│   └── SkyrimSE.pdb            Optional: vanilla SE PDB for extra symbol names
├── ghidrascripts/
│   ├── CommonLibImport_SE.py   Generated: import SE types + vtables + symbols
│   └── CommonLibImport_AE.py   Generated: import AE types + vtables + symbols
├── parse_commonlib_types.py    Generator for CommonLibImport_SE/AE.py
├── template_types.py           Optional: C++ template instantiation handling
├── extra_types.json            Manual type definitions (typedefs, enums, opaques)
└── requirements.txt            Python dependencies
```

---

## Plugin Build

### Requirements

| Tool | Notes |
|------|-------|
| [CMake](https://cmake.org/) | Add to `PATH` |
| [PowerShell](https://github.com/PowerShell/PowerShell/releases/latest) | |
| [Vcpkg](https://github.com/microsoft/vcpkg) | Set `VCPKG_ROOT` environment variable |
| [Visual Studio 2022](https://visualstudio.microsoft.com/) | Desktop development with C++ workload |
| [CommonLibSSE](https://github.com/powerof3/CommonLibSSE/tree/dev) | `powerof3/dev` branch; set `CommonLibSSEPath` env var |

### Register Visual Studio as a CMake Generator

Open an **x64 Native Tools Command Prompt** and run `cmake` once to register the
generator, then close it.

### Clone and initialise

```bash
git clone https://github.com/doodlum/GhidraImportScripts.git
cd GhidraImportScripts
git submodule update --init --recursive
```

### Build SE

```bash
cd plugin
cmake --preset vs2026-windows-vcpkg-se
cmake --build build --config Release
```

### Build AE

```bash
cd plugin
cmake --preset vs2026-windows-vcpkg-ae
cmake --build buildae --config Release
```

The debug builds copy the PDB to `pdbs/GhidraImport_SE_D.pdb` (or AE) at the
repo root, where `parse_commonlib_types.py` expects to find them.

---

## Ghidra Pipeline Overview

The pipeline produces two Ghidra scripts from the CommonLibSSE source tree and
address databases. Run the Python generator on the host machine, then run the
resulting scripts inside Ghidra on a Skyrim SE or AE binary.

```
CommonLibSSE headers ─┬─ parse_commonlib_types.py ──► CommonLibImport_SE.py
Address libraries   ──┤                           ──► CommonLibImport_AE.py
PDB files           ──┘
extra_types.json ─────────────────────────────────► (embedded in both scripts)
template_types.py ────────────────────────────────► (optional, auto-used)
```

**Symbol sources** (in priority order for SE):

1. CommonLibSSE headers — libclang AST (fully-qualified names, signatures)
2. CommonLibSSE `src/*.cpp` — libclang unity parse (functions not in headers)
3. `skyrimae.rename` — AE address database fallback names
4. `SkyrimSE.pdb` — vanilla SE PDB public symbols (fallback, no signatures)

**Execution order inside Ghidra** (per binary):

Run **`CommonLibImport_SE.py`** (SE) or **`CommonLibImport_AE.py`** (AE).

This single script:
- Creates all `RE::` structs, classes, and enums in the Ghidra Data Type Manager
  under `/CommonLibSSE/RE/`.
- Populates vtable structs with typed function pointer fields.
- Applies all function signatures via `CParserUtils.parseSignature()`.
- Labels all known symbols at their computed addresses.

---

## Prerequisites

### Python (host machine, for running the generator)

- Python **3.10+**, **64-bit** (required for the 64-bit libclang DLL)
- Install dependencies:

```bash
pip install -r requirements.txt
# requirements.txt contains: libclang, comtypes
```

`libclang` provides the `clang.cindex` bindings used to parse CommonLibSSE
headers. `comtypes` is used to load the DIA SDK COM interface for PDB type
extraction.

### CommonLibSSE submodule

The generator reads directly from `extern/CommonLibSSE/`. Ensure the submodule
is checked out:

```bash
git submodule update --init extern/CommonLibSSE
```

### Address library files

Place the address library binaries in `addresslibrary/`:

| File | Source |
|------|--------|
| `version-1-5-97-0.bin` | [Address Library for SKSE Plugins (SE)](https://www.nexusmods.com/skyrimspecialedition/mods/32444) |
| `versionlib-1-6-1170-0.bin` | [Address Library for SKSE Plugins (AE)](https://www.nexusmods.com/skyrimspecialedition/mods/32444) |

### PDB files

Place debug PDB files in `pdbs/`. These are used to cross-reference struct sizes
and vtable layouts:

| File | Purpose |
|------|---------|
| `GhidraImport_SE_D.pdb` | SE debug build PDB — struct sizes + vtable data |
| `GhidraImport_AE_D.pdb` | AE debug build PDB — struct sizes + vtable data |
| `SkyrimSE.pdb` | *(optional)* Vanilla SE PDB — fallback symbol names |

The DIA SDK (installed with Visual Studio) is used to read PDB type info. If
`msdia140.dll` is present on the system (it usually is after installing VS), it
is found automatically via the registry. A manual TPI stream parser provides a
fallback if COM is unavailable.

### Ghidra

- [Ghidra](https://ghidra-sre.org/) 10.x or later
- The generated scripts use the Ghidra Python (Jython 2.7) scripting environment

---

## Setup

All paths are relative to the repository root. The generator finds all inputs
automatically — no environment variables are required.

```
GhidraImportScripts/
├── extern/CommonLibSSE/   ← must be populated (git submodule)
├── addresslibrary/        ← version-1-5-97-0.bin + versionlib-1-6-1170-0.bin
└── pdbs/                  ← GhidraImport_SE_D.pdb + GhidraImport_AE_D.pdb
                             (built by plugin debug build; + optionally SkyrimSE.pdb)
```

---

## Running the Generator

Run the generator from the repository root. It writes output into `ghidrascripts/`.

```bash
python parse_commonlib_types.py
```

Outputs:
- `ghidrascripts/CommonLibImport_SE.py` — SE types, enums, vtables, symbols
- `ghidrascripts/CommonLibImport_AE.py` — AE types, enums, vtables, symbols

Typical run time: ~60–90 seconds (two full header parse passes + src/ unity parse).

Console output per version:
```
SE entries: 142458, AE entries: 167347
=== Collecting symbols via libclang ===
Parsing CommonLibSSE headers...
Collecting types...
Found 885 enums, 2801 structs/classes
Computed vtable slots for 507 structs from libclang
Loading PDB type info from GhidraImport_SE_D.pdb...
Found 2542 RE:: types in PDB
PDB cross-reference: 2517 matched, 909 size-ok, 1308 supplemented, 2 mismatched
Built 1360 vtable structs
...
Added N symbols from AE rename database
Added N symbols from SE PDB
Output: ghidrascripts/CommonLibImport_SE.py (891 enums, 2853 structs)
```

### Regeneration

Regenerate whenever:
- CommonLibSSE submodule is updated (`git submodule update`)
- `extra_types.json` is edited
- `template_types.py` or the generator is modified

---

## Running the Ghidra Scripts

### Import the binary

1. Open Ghidra and create a project.
2. Import `SkyrimSE.exe` (SE) or the AE executable. Use the default PE import
   options with auto-analysis enabled; let auto-analysis finish before running
   the scripts.

### Run CommonLibImport_SE.py or CommonLibImport_AE.py

In the Ghidra Script Manager (`Window → Script Manager`):

1. Add `ghidrascripts/` to the script directories.
2. Run **`CommonLibImport_SE.py`** for SE binaries or **`CommonLibImport_AE.py`**
   for AE binaries.

This script:
- Creates all `RE::` structs, classes, and enums in the Data Type Manager.
- Populates vtable structs with typed function pointer fields.
- Applies vtable function signatures to the virtual function implementations.
- Applies all symbol labels and function signatures at computed addresses.
- Prints a summary: `Labels: N, Functions: N, Signatures applied: N, Signatures failed: N`

Both scripts are safe to re-run; they overwrite existing types and labels.

---

## Pipeline Files Reference

### `parse_commonlib_types.py`

Single generator for both SE and AE scripts. Parses CommonLibSSE headers with
libclang to produce struct/enum/vtable data and function symbols.

| Input | Purpose |
|-------|---------|
| `extern/CommonLibSSE/include/RE/Skyrim.h` | RE:: namespace types + relocation IDs |
| `extern/CommonLibSSE/src/*.cpp` | Additional function bodies (unity parse) |
| `pdbs/GhidraImport_SE_D.pdb` | Authoritative struct sizes and vtable layout |
| `addresslibrary/` | SE and AE offset databases |
| `extern/AddressLibraryDatabase/skyrimae.rename` | AE fallback symbol names |
| `pdbs/SkyrimSE.pdb` | SE fallback symbol names (optional) |
| `extra_types.json` | Manually defined types not extractable from headers |
| `template_types.py` | Template instantiation alias generation (auto-imported) |

Output variables in generated scripts:
- `ENUMS` — list of `(name, size, category, values)` tuples
- `STRUCTS` — list of `(name, size, category, fields, bases, has_vtable)` tuples
- `VTABLES` — list of `(name, class_full_name, size, category, slots)` tuples
- `SYMBOLS` — list of `{n, t, sig, s?, a?, src}` dicts
- `C_TYPE_PRELUDE` — C declarations prepended to every `CParserUtils.parseSignature()` call
- `TEMPLATE_TYPE_MAP` — maps `NiPointer<BSTriShape>` → `NiPointer_BSTriShape` etc.

### `extra_types.json`

Manually maintained type definitions for types that cannot be auto-extracted from
the headers. Loaded by the generator and embedded in both generated scripts.
See [extra\_types.json Reference](#extra_typesjson-reference) below.

### `template_types.py`

Optional module that scans for C++ template instantiation names and generates
sanitized C identifier aliases. Automatically imported by the generator when
present. See [template\_types.py Reference](#template_typespy-reference) below.

---

## extra_types.json Reference

File location: `extra_types.json` (repository root)

This file defines types that are either template instantiations, primitive
typedef aliases, or forward-declared-only types that libclang cannot extract with
full detail from the CommonLibSSE headers. The generator loads this file and:

1. Injects the types into the Ghidra Data Type Manager.
2. Emits C declarations into `C_TYPE_PRELUDE` so `CParserUtils.parseSignature()`
   can parse function signatures that reference these types.

### Schema

```json
{
  "_comment": "...",

  "typedefs": {
    "TypeName": {
      "base": "u32",
      "comment": "optional human-readable explanation"
    }
  },

  "enums": {
    "EnumName": {
      "size": 4,
      "comment": "...",
      "values": {
        "kSomeValue": 0,
        "kOtherValue": 1
      }
    }
  },

  "opaques": {
    "StructName": "human-readable description"
  }
}
```

### `typedefs` — integer typedef aliases

| Field | Values | Description |
|-------|--------|-------------|
| `base` | `u8` `i8` `u16` `i16` `u32` `i32` `u64` `i64` | Underlying integer type |
| `comment` | string | Optional description |

Emitted as `typedef unsigned int FormID;` etc. in `C_TYPE_PRELUDE`.

### `enums` — enum definitions

| Field | Values | Description |
|-------|--------|-------------|
| `size` | `1` `2` `4` `8` | Byte size of the enum |
| `values` | `{ "kName": N }` | Enumerator name → integer value pairs |
| `comment` | string | Optional description |

Enums with no `values` (empty `{}`) are emitted as `typedef unsigned int Name;`
since CParserUtils cannot parse empty enum bodies.

### `opaques` — forward-declared / opaque structs

Any type that is forward-declared only, has an unknown layout, or is only
referenced by pointer. Created as a zero-size opaque struct in the Ghidra Data
Type Manager. Emitted as:
```c
struct Name;
typedef struct Name Name;
```

### Adding new types

Add types here when a Ghidra script run produces a `SIG FAIL` for a function
whose signature contains an unknown type name. Identify the type in CommonLibSSE
headers to determine whether it belongs in `typedefs`, `enums`, or `opaques`,
then regenerate both scripts.

---

## template_types.py Reference

File location: `template_types.py` (repository root)

Handles C++ template instantiation type names such as `NiPointer<BSTriShape>` and
`BSTArray<NiPointer<CombatInventoryItem>>`. These names contain angle brackets
and cannot appear in C function prototype strings that Ghidra's
`CParserUtils.parseSignature()` processes.

### What it does

1. **Scans** struct field descriptors and raw PDB signature strings for
   `Word<...>` template instantiation names, handling arbitrary nesting.
2. **Generates** a sanitized C identifier alias for each:
   - `NiPointer<BSTriShape>` → `NiPointer_BSTriShape`
   - `BSTEventSource<ActorKill::Event>` → `BSTEventSource_ActorKill_Event`
   - `BSTSmallArray<TESForm *, 6>` → `BSTSmallArray_TESForm_ptr_6`
3. **Extends** `C_TYPE_PRELUDE` with forward declarations for the alias names.
4. **Embeds** a `TEMPLATE_TYPE_MAP` dict and `_patch_templates(proto)` function
   in each generated script. Before every `parseSignature()` call the proto
   string is patched so template names are replaced by their aliases.

### Integration

`template_types.py` is imported automatically (via `try/except ImportError`) by
the generator. If the file is absent the pipeline continues without template
support — all template-typed parameters fall back to `void *`.

### Public API

```python
from template_types import (
    sanitize_template_name,   # 'NiPointer<BSTriShape>' -> 'NiPointer_BSTriShape'
    extract_template_names,   # find all Word<...> in a string
    collect_template_names,   # scan struct descriptors + sig strings
    build_template_result,    # TemplateResult from a set of names
    patch_proto_templates,    # substitute names in a proto string (generation-time)
    process_template_types,   # main entry point
)
```

`process_template_types(structs, extra_types, sig_strings)` returns a
`TemplateResult` containing:

| Attribute | Type | Description |
|-----------|------|-------------|
| `template_map` | `dict[str, str]` | `original → sanitized` |
| `c_prelude_fragment` | `str` | C typedef/forward-decl block |
| `map_source` | `str` | Python source: `TEMPLATE_TYPE_MAP = {...}` |
| `patch_fn_source` | `str` | Python source: `def _patch_templates(proto): ...` |

---

## Known Limitations

### Function signatures — template parameter degradation

When a `REL::Relocation<func_t>` variable declaration contains complex template
types (e.g. `BSScrapArray<ActorHandle>*`), libclang's error recovery degrades the
type to `int`. The function is found at the correct address; only the parameter
type spelling is wrong. Affected parameters show as `int *` instead of the real
type.

### Function signatures — Offset:: namespace

Functions using `RE::Offset::` IDs use a two-stage AST/token-scan fallback. Exotic
initialisers (macros expanding to Offset references, nested template expressions)
are silently skipped.

### Five uncaptured functions

The following are not captured by any extraction path:

- `BSPointerHandleManager::GetHandleEntries` — array bound `0x100000` in the
  template type argument shadows the real `RELOCATION_ID`.
- `RTTI::from`, `RTTI::to`, `NiObjectNET::rtti`, `NiRTTI::to` — offsets inside
  template functions depend on the concrete template type parameter; no integer
  RELOCATION_ID is present.

### Missing `binary_io` dependency

`binary_io/file_stream.hpp` is not in the `extern/` tree. libclang emits one parse
error per pass and recovers; types that depend on that header are skipped or receive
degraded `int` types. The error is suppressed in console output.

### Struct size discrepancies

Two classes have genuine size disagreements between libclang and the PDB:

| Class | libclang | PDB |
|-------|----------|-----|
| `RE::AttackAnimationArrayMap` | 16 | 64 |
| `RE::bhkTelekinesisListener` | 8 | 16 |

libclang's layout is used for these. If the PDB is absent, all struct sizes fall
back to libclang's `sizeof` estimate.

### Vtable slot computation

Slot indices are computed by counting virtual method declarations in base-class
order. Diamond inheritance with shared virtual bases may produce incorrect slot
numbers.

### Template instantiation layout

Template field types preserve the full instantiation name
(e.g. `NiPointer<BSTriShape>`) from libclang's `Type.spelling`. The corresponding
Ghidra struct is an opaque placeholder — field layout inside the instantiation is
not resolved. Only types that are explicitly specialised in the CommonLibSSE
headers get full field data.

### CParserUtils type resolution

Ghidra's `CParserUtils.parseSignature()` resolves type names against the
`C_TYPE_PRELUDE` declarations prepended to each proto. Types not covered by
`C_TYPE_PRELUDE` or by the Data Type Manager are replaced with `void *` by the
`sanitize_unknown_types()` fallback. Add missing types to `extra_types.json` to
improve coverage.

---

## License

[MIT](LICENSE)
