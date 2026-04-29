#!/usr/bin/env python3
"""
Parse libxse/commonlibf4 headers and generate the Ghidra import script
for Fallout 4 AE (1.11.191).

Pipeline:
  Types:        core/clang_types.py  (clang AST dump + record layouts)
  Relocations:  reloc_parser.py      (IDs.h map + ID::Class::Method references)
  Address lib:  address_library.py   (1-11-191 AE; 1-10-984 NG used to rebase PDB)
  Script gen:   core/ghidra_import_gen.py

Generates:
  ghidrascripts/CommonLibImport_F4_AE.py
"""

import os
import sys
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
CORE_DIR    = os.path.join(os.path.dirname(SCRIPT_DIR), 'core')

sys.path.insert(0, CORE_DIR)
sys.path.insert(0, SCRIPT_DIR)

COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'include')
FALLOUT_H         = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Fallout.h')
RE_INCLUDE        = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR        = os.path.join(PROJECT_DIR, 'ghidrascripts')
ADDRLIB_DIR       = os.path.join(PROJECT_DIR, 'addresslibrary', 'f4')


def _enrich_symbols(symbols_list, structs):
    structs_by_suffix = {}
    for key, val in structs.items():
        parts = key.split('::')
        for i in range(len(parts)):
            suffix = '::'.join(parts[i:])
            if suffix not in structs_by_suffix:
                structs_by_suffix[suffix] = val
    enriched = 0
    for sym in symbols_list:
        if sym['t'] != 'func' or sym.get('sd'):
            continue
        name = sym['n']
        if '::' not in name:
            continue
        idx = name.rfind('::')
        class_name  = name[:idx]
        method_name = name[idx + 2:]
        st = structs.get(class_name) or structs_by_suffix.get(class_name)
        if not st:
            continue
        info = st.get('methods', {}).get(method_name)
        if info:
            ret, params, is_static = info
            sym['sd'] = [ret, params, 1 if is_static else 0]
            enriched += 1
    if enriched:
        print(f'Enriched {enriched} symbols with AST method signatures')


def main():
    import json as _json

    from address_library import F4AddressLibrary
    from ghidra_import_gen import (
        build_vtable_structs as _build_vtable_structs,
        inject_vtable_fields as _inject_vtable_fields,
        flatten_structs       as _flatten_structs,
        apply_secondary_vtable_typing as _apply_secondary_vtable_typing,
        generate_script,
    )

    # --- Address library ---
    addr_lib = F4AddressLibrary()
    addr_lib.load_all(ADDRLIB_DIR)
    print(f'AE address library: {len(addr_lib.ae_db):,} entries')
    print(f'NG address library: {len(addr_lib.ng_db):,} entries (PDB rebase)')

    # --- Relocation scan ---
    print('\n=== Collecting symbols via relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, static_methods = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    # Mark statics
    for fs in func_syms:
        if fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    # Build unified symbol list with 'a' = AE offset
    symbols = []
    for fs in func_syms:
        full_name = '{}::{}'.format(fs['class_'], fs['name']) if fs['class_'] else fs['name']
        sym = {'n': full_name, 't': 'func', 'sig': '', 'src': 'CommonLibF4'}
        if fs.get('ae_off'): sym['a'] = fs['ae_off']
        symbols.append(sym)

    for lbl in label_syms:
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibF4'}
        if lbl.get('ae_off'): sym['a'] = lbl['ae_off']
        symbols.append(sym)

    # Normalise __ -> ::
    for s in symbols:
        if '__' in s['n']:
            s['n'] = re.sub(r':{3,}', '::', s['n'].replace('__', '::'))

    ae_syms = [s for s in symbols if s.get('a')]
    print(f'\nTotal symbols: {len(symbols)}  (AE coverage: {len(ae_syms)})')

    # --- Type parsing ---
    print('\n=== Parsing types (clang AST) ===')
    from clang_types import collect_types, _setup_include_paths

    if not os.path.isfile(FALLOUT_H):
        print('ERROR: Could not find Fallout.h at', FALLOUT_H)
        sys.exit(1)

    stub_dir   = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
    parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
    # commonlib-shared provides REL/ and REX/ headers
    shared_include = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'lib', 'commonlib-shared', 'include')
    if os.path.isdir(shared_include):
        parse_args = ['-I' + shared_include] + parse_args

    # Capture types from REL/, REX/, F4SE/ as well as RE/ — they're sibling
    # namespaces under CommonLibF4 whose AST methods would otherwise be skipped.
    extra_scopes = [
        COMMONLIB_INCLUDE,                                   # F4SE/ + RE/
        os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4',
                     'lib', 'commonlib-shared', 'include'),  # REL/ + REX/
    ]
    enums, structs, template_source = collect_types(
        FALLOUT_H, RE_INCLUDE, parse_args,
        verbose=True, category_prefix='/CommonLibF4',
        extra_scope_paths=extra_scopes)
    print(f'Found {len(enums)} enums, {len(structs)} structs/classes')

    _enrich_symbols(symbols, structs)

    vtable_structs = _build_vtable_structs(structs)
    _inject_vtable_fields(structs, vtable_structs)
    _flatten_structs(structs)
    _apply_secondary_vtable_typing(structs)

    # --- Fallout4.pdb fallback symbols (rebased NG -> AE) ---
    print('\n=== Loading Fallout4.pdb fallback symbols (1.10.984 NG -> 1.11.191 AE) ===')
    from pdb_symbols import load_pdb_names as _load_pdb
    f4_pdb_path = os.path.join(PROJECT_DIR, 'extras', 'Fallout4.pdb')
    pdb_names = _load_pdb(f4_pdb_path)
    print(f'PDB: {len(pdb_names):,} public symbols')

    primary_rvas = {s['a'] for s in symbols if s.get('a')}
    pdb_fallback = []
    rebased = 0
    unmapped = 0
    for rva_ng, name in pdb_names.items():
        ae_rva = addr_lib.rva_ng_to_ae(rva_ng)
        if ae_rva is None:
            unmapped += 1
            continue
        rebased += 1
        sym = {'n': name, 't': 'func', 'sig': '', 'a': ae_rva, 'src': 'Fallout4.pdb'}
        pdb_fallback.append(sym)
    print(f'PDB fallback symbols: {rebased:,} rebased onto AE '
          f'({unmapped:,} unmapped, '
          f'{sum(1 for s in pdb_fallback if s["a"] not in primary_rvas):,} not in primary)')

    fallback_json = _json.dumps(pdb_fallback, separators=(',', ':'))

    # --- Generate AE script ---
    print('\nGenerating Ghidra script...')
    output_path = os.path.join(OUTPUT_DIR, 'CommonLibImport_F4_AE.py')
    n_enums, n_structs = generate_script(
        enums, structs, vtable_structs, output_path,
        version='f4_ae',
        symbols_json=_json.dumps(symbols, separators=(',', ':')),
        fallback_symbols_json=fallback_json,
        template_source=template_source,
        project_name='CommonLibF4',
    )
    print(f'  CommonLibImport_F4_AE.py: {n_enums} enums, {n_structs} structs')


if __name__ == '__main__':
    main()
