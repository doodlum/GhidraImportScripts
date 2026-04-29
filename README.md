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

Fallout 4 OG (1.10.163) is **not** supported. The `extras/Fallout4.pdb` is from
1.10.984 ("NG"); its symbols are rebased onto 1.11.191 (AE) via `RVA → 984 ID →
191 RVA` lookup.

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
│       version-1-10-984-0.bin       F4 NG (used to rebase the PDB)
├── extras/
│   ├── SkyrimSE.pdb                 fallback symbol names for Skyrim SE
│   └── Fallout4.pdb                 fallback symbol names for F4 (NG 1.10.984)
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
        └── address_library.py       AE primary; NG inverted for PDB rebase
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

extras/<game>.pdb             ─── pdb_symbols.py          ──► fallback symbols
                                                              (Fallout4.pdb is rebased
                                                               1.10.984 NG → 1.11.191 AE)

parse_commonlib_types.py      ─── orchestrates each game ─┐
ghidra_import_gen.py          ─── emits the .py script ───┴─► ghidrascripts/CommonLibImport_*.py
```

**Symbol sources** (priority order):

1. `RELOCATION_ID(SE, AE)` (Skyrim) or `REL::ID Name{ng_id}` (F4 libxse) macros
2. `Offsets_RTTI.h`, `Offsets_NiRTTI.h`, `Offsets_VTABLE.h` labels
3. `RE::Offset::` namespace IDs (Skyrim)
4. CommonLibSSE `src/*.cpp` cross-references (Skyrim only)
5. Fallback: AE rename DB (`skyrimae.rename`) — Skyrim AE only
6. Fallback: PDB public symbols (`SkyrimSE.pdb`, `Fallout4.pdb`-rebased)

Vtable slots known from the AST upgrade matching fallback symbols' source from
PDB/rename to the CommonLib name, so they appear under
`/CommonLibSSE/` or `/CommonLibF4/` in the Data Type Manager.

---

## Generated script behaviour

Each `CommonLibImport_*.py` is a self-contained Jython script that:

- Creates all enums, structs, and vtable structs under `/CommonLib<Game>/`
- Populates struct fields with computed offsets and types
- Names virtual functions by walking vtable addresses in the binary
- Applies function signatures via `CParserUtils.parseSignature()` (with a
  `void *` fallback for unresolved type names)
- Labels every known address-library symbol
- Adds a `Source: <origin>` plate comment to each named function

The scripts are idempotent — safe to re-run; they overwrite types/labels.

---

## Known limitations

- **Template layouts.** A third clang pass (`-fdump-record-layouts` over a
  synthetic `struct sN { T<...> _; }` for each unfilled template) forces
  instantiation of templates the orchestrator header never used. ~95% of
  empty placeholders get real layouts; the only stragglers are
  malformed names from clang's lambda-numbering (e.g. `Allocator<24, RE::8>`).
- **Vtable slots.** A 4th clang pass synthesises `auto u<N> = &Class::Method;`
  (one per polymorphic class) and runs `-S -emit-llvm -Xclang
  -fdump-vtable-layouts`, which yields exact slot indices for every primary
  vtable. The address-of-virtual-member trick avoids destructor instantiation,
  so it sidesteps the `BSTSmartPointer<incomplete-type>` and ambiguous
  `operator delete` errors that block `delete t` / `t->~T()`.
  A two-stage compile (`-fsyntax-only` to filter overload-ambiguous
  declarations, then real codegen) recovers usable data even when the
  candidate set has bad picks. The clang slot map replaces AST-computed
  `vfuncs` for ~95% of polymorphic classes, fixing destructor-position
  miscounts that previously truncated vtable structs (e.g. F4 `Actor_vtbl`:
  299 → 307 components).
  Secondary vtable IDs from multi-inheritance — `std::array<REL::ID, N>`
  arrays in `IDs_VTABLE.h` / `Offsets_VTABLE.h` with N > 1 — are emitted as
  `VTABLE_<Class>_2`, `VTABLE_<Class>_3`, ... so all of a class's vtables get
  labeled. The unnamed-walk pass labels their slot functions as
  `Class::Func1_v2`, `Class::Func2_v2`, etc.

  Per-class typed secondary vtable structs are also generated from the dump's
  `VFTable for B in C` blocks: each `[this adjustment: -N non-virtual]`
  annotation gives the subobject offset, and a struct named
  `<Class>_vtbl_<offset>` is emitted with the slot names from clang. A
  post-flatten pass rewrites every `__vftable_<base>` field at non-zero
  offset in C's flattened layout to point at C's secondary struct instead of
  B's primary, so multi-inheritance vfptr fields type-correctly per
  most-derived class.
- **Type resolution in signatures.** Almost all `void *` fallbacks have been
  removed via:
  - `using X = Y;` alias extraction from the AST and descriptor rewriting
    (with each struct's `full_name` as `class_scope` so class-local typedefs
    like `Foo::EventSource_t` resolve);
  - `const`/`volatile`/`restrict` stripping (including `T *const`);
  - primitive map entries for `_Bool`, `std::byte`, `wchar_t`, `char16_t`,
    `char32_t`, `char8_t`, `__int128`, `long double`;
  - SIMD vector detection: clang's `__attribute__((__vector_size__(N *
    sizeof(T))))` is mapped to `arr:u8:<bytes>`;
  - function-pointer-shape detection (`Ret (*)(args)`, `Ret (Class::*)(args)`,
    `Ret (**)(args)`, `Ret (&)(args)`) collapsed to plain `ptr`;
  - chained pointer typing: `T **` and `T ***` now wrap as
    `ptr:ptr:struct:T` instead of collapsing to bare `ptr`, so members like
    `BGSKeyword** keywords` resolve all the way through the deref chain;
  - 0-byte opaque struct entries for any name referenced as `struct:NAME`
    but not present in `structs`/`enums`, including nested types inside
    template instantiations (`Outer<args>::Inner`) — pointers to them get
    typed in Ghidra instead of `void *`.

  F4 result: unresolved field types dropped from **13.7% → 0.30%** (after
  pointer-chaining, template-method propagation, sibling-namespace AST scope,
  and `std::` AST inclusion); Skyrim AE/SE: **0.36%**. Structured
  symbol-signature resolution at **100%** for all primary symbols. The
  remaining 0.30–0.36% is mostly member function-pointer typedefs
  (intentionally collapsed to plain `ptr`) and a handful of stdlib stream
  internals (`basic_ostream`, `basic_ostringstream`) whose virtual-method
  declarations live in MSVC headers outside the project's include scope.
- **AST scope.** `_parse_ast_dump`'s in-scope test originally fired only on
  the configured root namespace (`RE`) and on file paths under the main
  include directory. Sibling top-level namespaces (`REL`, `REX`, `F4SE`,
  `SKSE`, `Scaleform`) and `std` were silently skipped, so all the IUnknown /
  D3D11 / Scaleform / std-stream classes inherited via CommonLib's interface
  shims kept their `vmethods` empty — and their derived classes ended up
  with bare `__vftable` pointers.  The fix:
  1. `extra_scope_paths` parameter on `collect_types`, plumbed in by both
     orchestrators, lets the parser accept any AST decl whose source location
     is under a configured commonlib subdirectory (covers REL/REX/F4SE/SKSE).
  2. NamespaceDecl now sets `in_re=True` on three additional triggers: the
     namespace's own source location matches a scope path, the namespace
     name equals the configured root, or the namespace is `std` (so user
     classes deriving from `std::runtime_error`, `std::exception`,
     `std::function` chains pick up the inherited virtual slots).
  3. `nested` and `inline` modifier tokens that clang appends after the
     namespace name in `namespace A::B {}` declarations are now stripped
     before the trailing token is read as the namespace name — previously
     classes inside such blocks were silently filed under a bogus
     `RE::nested::...` namespace and lost all their AST methods.
  4. Numeric / boolean / string literals appearing as template arguments
     (`<16>`, `<false>`, `<"foo">`) are no longer wrongly rewritten to
     `RE::16`, `RE::false`, etc. by the qualifier — `_qualify_type`'s leaf
     branch defers to `_ensure_qualified` so non-type tokens pass through.

  Combined effect: ~5,200 bad-named template instantiations vanished, vtable
  struct count went from 1,075 → **1,292** (F4) and 1,825 → **2,024**
  (Skyrim), template-method propagation jumped to **26,671** instantiations
  (was 1,771).
- **Template-instantiation methods.** Layout-only template instantiations
  (e.g. `RE::BSTEventSink<RE::FooEvent>`) used to inherit only the layout
  from the record-layout dump and lost the template definition's `vmethods`
  and `methods` dictionaries. A propagation pass copies `vmethods`/`methods`
  from the template definition `T` onto every `T<args>` instantiation that
  arrived through any path (layout dump, layout propagation, alias map,
  forced-layout synthesis), so vtable structs get generated for instantiations
  too. Vfuncs that came from the clang vtable dump are tagged
  `_vfuncs_from_dump` and protected from re-computation, so the second AST
  pass can populate the new instantiations without clobbering exact slot
  indices.
- **Anonymous types stripped.** Clang's record-layout dump emits names like
  `(lambda at PATH:LINE:COL)` and `(anonymous at PATH:LINE:COL)` for unnamed
  closures and structs. Those names embed absolute file paths from the build
  machine and aren't useful as Ghidra type names. A post-pass drops every
  struct whose name (or a fragment thereof — including transitive wrappers
  like `std::optional<lambda>::_Value`) contains one of those tokens, and
  rewrites any descriptor referencing them to raw `bytes:<size>` padding so
  byte footprints are preserved without leaking machine-specific names.
- **Fallout 4 PDB coverage.** The shipped `Fallout4.pdb` only contains ~11.7k
  real public symbols (the rest are auto-named `FUN_*` placeholders, filtered
  out). The vast majority of named F4 functions therefore come from the
  CommonLibF4 ID database, not the PDB.

---

## License

[MIT](LICENSE)
