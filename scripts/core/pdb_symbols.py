"""PDB public symbol extraction.

Provides:
  load_pdb_names  - extracts public function symbols from a PDB file via pdbparse
  undecorate      - demangles MSVC-mangled symbol names via dbghelp
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
from typing import Dict


# ---------------------------------------------------------------------------
# MSVC symbol demangling
# ---------------------------------------------------------------------------

def undecorate(name: str) -> str:
    """Demangle an MSVC-mangled symbol name using dbghelp.UnDecorateSymbolName."""
    try:
        buf = ctypes.create_string_buffer(512)
        if ctypes.windll.dbghelp.UnDecorateSymbolName(name.encode(), buf, 512, 0x1000):
            return buf.value.decode('ascii', errors='replace')
    except Exception:
        pass
    return name


def _clean_name(name: str) -> str | None:
    if name.startswith('?'):
        name = undecorate(name)
    if re.match(r'^FUN_[0-9A-Fa-f]+$', name):
        return None
    name = re.sub(r'_14[0-9A-Fa-f]{6,8}$', '', name)
    name = re.sub(r':{3,}', '::', name.replace('__', '::'))
    return name or None


# ---------------------------------------------------------------------------
# PDB public symbols
# ---------------------------------------------------------------------------

def load_pdb_names(file_path: str) -> Dict[int, str]:
    """Parse a PDB file and return dict of rva -> name for all public function symbols.

    Handles two layouts:
      - gsym.funcs dict (Skyrim-style): keyed by name, values have symtype/segment/offset
      - gsym.globals list (F4-style): flat list of S_PUB32 records
    """
    if not os.path.exists(file_path):
        return {}

    import pdbparse

    pdb = pdbparse.parse(file_path)
    dbi = pdb.STREAM_DBI
    gsym = pdb.streams[dbi.DBIHeader.symrecStream]

    sec_data = pdb.streams[dbi.DBIDbgHeader.snSectionHdr].data
    sections = [struct.unpack_from('<I', sec_data, i * 40 + 12)[0]
                for i in range(len(sec_data) // 40)]

    result = {}

    if gsym.funcs:
        # Skyrim-style: dict keyed by name
        for name, rec in gsym.funcs.items():
            if not (rec.symtype & 0x2) or not (1 <= rec.segment <= len(sections)):
                continue
            name = _clean_name(name)
            if name is None:
                continue
            result[sections[rec.segment - 1] + rec.offset] = name
    else:
        # F4-style: flat list of S_PUB32 records; include all code-segment mangled names
        for rec in gsym.globals:
            if not (1 <= rec.segment <= len(sections)):
                continue
            # Only segment 1 (.text) for executable code
            if rec.segment != 1:
                continue
            name = _clean_name(rec.name)
            if name is None:
                continue
            rva = sections[rec.segment - 1] + rec.offset
            result[rva] = name

    return result
