"""Parse `IDAImportNames_<version>.py` (Bethesda-IDA reverse-engineering script
that names addresses in Fallout4.exe).

The file is a flat sequence of ``NAME(0xABS_ADDR, 'name_HEX_SUFFIX')`` calls.
We extract them into ``{rva: name}`` for use as a fallback symbol source —
each name's trailing ``_<addr>`` suffix is stripped so functions don't end up
double-tagged in Ghidra.

Output is keyed by RVA (relative to the EXE image base) so it plugs directly
into the orchestrator's fallback-symbol pipeline.

Public API:
    load_ida_import_names(path, image_base=0x140000000) -> dict[int, str]
"""

from __future__ import annotations

import re
from typing import Dict


_NAME_LINE_RE = re.compile(
    r"^\s*NAME\(\s*0x([0-9A-Fa-f]+)\s*,\s*['\"]([^'\"]+)['\"]\s*\)\s*$"
)
# The IDA script appends ``_<HEX_ADDR>`` to every name to make them unique.
# Strip this suffix so we get the raw symbol name.
_ADDR_SUFFIX_RE = re.compile(r'_[0-9A-Fa-f]{6,12}$')
# Filter out IDA-generated placeholder names that carry no information.
_PLACEHOLDER_RE = re.compile(
    r'^(?:FUN|sub|loc|byte|word|dword|qword|unk|off|stru|asc|jpt|nullsub|j_)_[0-9A-Fa-f]+$'
)


def _clean_ida_name(raw: str) -> str | None:
    """Strip the trailing ``_<HEX_ADDR>`` suffix and reject placeholder names.

    Returns the cleaned name, or ``None`` if the entry is just an
    address-derived placeholder with no real symbol info.
    """
    name = raw.strip()
    if not name:
        return None
    if _PLACEHOLDER_RE.match(name):
        return None
    name = _ADDR_SUFFIX_RE.sub('', name)
    return name or None


def load_ida_import_names(path: str, image_base: int = 0x140000000) -> Dict[int, str]:
    """Read an IDA NAME() script and return ``{rva: name}``.

    ``image_base`` defaults to the standard Fallout 4 EXE base (0x140000000).
    Absolute addresses outside ``[image_base, image_base + 0x80000000)`` are
    skipped — they're either thunks/imports referenced by VA in another module
    or junk we don't want to apply.
    """
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        return {}

    out: Dict[int, str] = {}
    duplicate_addr = 0
    placeholder_skipped = 0
    out_of_range = 0

    for line in text.splitlines():
        m = _NAME_LINE_RE.match(line)
        if not m:
            continue
        try:
            abs_addr = int(m.group(1), 16)
        except ValueError:
            continue
        if abs_addr < image_base or abs_addr >= image_base + 0x80000000:
            out_of_range += 1
            continue
        rva = abs_addr - image_base

        clean = _clean_ida_name(m.group(2))
        if clean is None:
            placeholder_skipped += 1
            continue

        if rva in out:
            duplicate_addr += 1
            # Keep the longer / more descriptive name on duplicates.
            if len(clean) <= len(out[rva]):
                continue
        out[rva] = clean

    return out
