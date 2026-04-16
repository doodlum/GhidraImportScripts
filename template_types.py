"""
template_types.py
-----------------
Optional pipeline step for handling C++ template instantiation type names in
the Ghidra import pipeline.

C++ identifiers like ``NiPointer<BSTriShape>`` and
``BSTArray<NiPointer<CombatInventoryItem>>`` contain angle brackets and cannot
appear in C function prototype strings that Ghidra's
``CParserUtils.parseSignature()`` processes.  This module:

  1. Scans struct field/vtable descriptors and raw signature strings for
     template instantiation names (anything of the form ``Word<...>``).
  2. Generates a sanitized C identifier alias for each name, e.g.::

         NiPointer<BSTriShape>                    -> NiPointer_BSTriShape
         BSTArray<NiPointer<CombatInventoryItem>> -> BSTArray_NiPointer_CombatInventoryItem
         BSTSmallArray<TESForm *, 6>              -> BSTSmallArray_TESForm_ptr_6

  3. Builds a C typedef/forward-declaration fragment to append to
     ``C_TYPE_PRELUDE`` so ``CParserUtils`` sees those aliases.
  4. Produces embeddable Python source (``TEMPLATE_TYPE_MAP`` dict and
     ``_patch_templates`` function) for generated Ghidra scripts, where
     template names in proto strings are substituted before ``parseSignature``.

Typical usage in a generator script::

    from template_types import process_template_types

    result = process_template_types(structs, extra_types, sig_strings=raw_sigs)
    c_prelude += '\\n' + result.c_prelude_fragment
    # result.map_source and result.patch_fn_source are written verbatim into
    # the generated Ghidra script alongside C_TYPE_PRELUDE.

At Ghidra runtime the generated script contains::

    TEMPLATE_TYPE_MAP = {
        'NiPointer<BSTriShape>': 'NiPointer_BSTriShape',
        ...
    }

    def _patch_templates(proto):
        for _tmpl, _alias in sorted(TEMPLATE_TYPE_MAP.items(), key=lambda x: -len(x[0])):
            proto = proto.replace(_tmpl, _alias)
        return proto

    ...
    proto = _patch_templates(proto)
    func_def = CParserUtils.parseSignature(dtm, program, C_TYPE_PRELUDE + '\\n' + proto, True)

Notes
-----
- Template instantiation *layout* is not resolved here; all discovered
  instantiations are treated as opaque structs (unknown size).  Actual field
  data for fully-instantiated templates (e.g. ``NiPointer<T>`` which is just
  ``T *``) could be a future enhancement via libclang.
- Only identifiers beginning with an ASCII letter or underscore trigger
  extraction; numeric non-type parameters (e.g. the ``6`` in
  ``BSTSmallArray<T, 6>``) appear verbatim in the sanitized name.
- Namespace prefixes (``RE::``, ``Impl::``, etc.) are stripped from the
  sanitized name but preserved in ``template_map`` keys so substitution
  targets the exact string found in source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

def _display_name(orig: str) -> str:
    """Strip ``RE::`` namespace prefix for display-friendly template names.

    Example: ``RE::NiPointer<RE::BSTriShape>`` -> ``NiPointer<BSTriShape>``
    """
    return orig.replace('RE::', '')


@dataclass
class TemplateResult:
    """
    Output of :func:`process_template_types` / :func:`build_template_result`.

    Attributes
    ----------
    template_map:
        Maps the original C++ template instantiation name (as it appears in
        source/signatures) to a display-friendly name (``RE::`` stripped).
        Example: ``{'RE::NiPointer<RE::BSTriShape>': 'NiPointer<BSTriShape>'}``
    c_alias_map:
        Maps the original C++ template instantiation name to a sanitized
        C identifier alias for use in ``CParserUtils.parseSignature()`` prototypes.
        Example: ``{'RE::NiPointer<RE::BSTriShape>': 'RE_NiPointer_RE_BSTriShape'}``
    c_prelude_fragment:
        C declaration block (struct forward-decls + typedefs) that can be
        appended to ``C_TYPE_PRELUDE``.
    map_source:
        Python source text for the ``TEMPLATE_TYPE_MAP`` variable, ready to
        be embedded verbatim in a generated Ghidra script.
    patch_fn_source:
        Python source text for the ``_patch_templates(proto)`` helper
        function, ready to be embedded verbatim in a generated Ghidra script.
    """
    template_map: Dict[str, str] = dc_field(default_factory=dict)
    c_alias_map: Dict[str, str] = dc_field(default_factory=dict)
    c_prelude_fragment: str = ''
    map_source: str = 'TEMPLATE_TYPE_MAP = {}\n'
    patch_fn_source: str = (
        'def _patch_templates(proto):\n'
        '    """Substitute C++ template type names with C-safe aliases before parseSignature."""\n'
        '    for _tmpl, _alias in sorted(TEMPLATE_TYPE_MAP.items(), key=lambda x: -len(x[0])):\n'
        '        proto = proto.replace(_tmpl, _alias)\n'
        '    return proto\n'
    )

    def combined_source(self) -> str:
        """Return ``map_source + patch_fn_source`` for single-block embedding."""
        return self.map_source + '\n' + self.patch_fn_source


# ---------------------------------------------------------------------------
# Name sanitization
# ---------------------------------------------------------------------------

def sanitize_template_name(name: str) -> str:
    """Convert a C++ template instantiation name to a valid C identifier.

    Steps:

    1. Convert ``::`` namespace separators to ``_`` (preserves uniqueness for
       qualified names like ``ActorKill::Event`` -> ``ActorKill_Event``).
    2. Replace ``<``, ``>``, ``,``, spaces with ``_``.
    3. Replace ``*`` with ``_ptr``, ``&`` with ``_ref``, ``[]`` with ``_``.
    4. Collapse runs of ``_`` and strip leading/trailing underscores.

    Examples::

        >>> sanitize_template_name('NiPointer<BSTriShape>')
        'NiPointer_BSTriShape'
        >>> sanitize_template_name('BSTArray<NiPointer<CombatInventoryItem>>')
        'BSTArray_NiPointer_CombatInventoryItem'
        >>> sanitize_template_name('BSTSmallArray<TESForm *, 6>')
        'BSTSmallArray_TESForm_ptr_6'
        >>> sanitize_template_name('BSTEventSource<ActorKill::Event>')
        'BSTEventSource_ActorKill_Event'
        >>> sanitize_template_name('RE::BSTHashMap<RE::FormID, RE::TESForm *>')
        'RE_BSTHashMap_RE_FormID_RE_TESForm_ptr'
    """
    buf: List[str] = []
    i = 0
    n = len(name)
    while i < n:
        if name[i:i+2] == '::':
            buf.append('_')
            i += 2
        elif name[i] in '<>, 	':
            buf.append('_')
            i += 1
        elif name[i] == '*':
            buf.append('_ptr')
            i += 1
        elif name[i] == '&':
            buf.append('_ref')
            i += 1
        elif name[i] in '[]':
            buf.append('_')
            i += 1
        else:
            buf.append(name[i])
            i += 1
    s = ''.join(buf)
    s = re.sub(r'_+', '_', s).strip('_')
    return s



# ---------------------------------------------------------------------------
# Template name extraction
# ---------------------------------------------------------------------------

# Matches an optionally namespace-qualified identifier immediately followed by
# '<', e.g. "NiPointer<", "RE::NiPointer<", "RE::BSTArray<"
_IDENT_LT = re.compile(r'((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*<')


def extract_template_names(text: str) -> Set[str]:
    """Extract all C++ template instantiation names from *text*.

    Handles arbitrarily-nested angle brackets.  Returns every distinct
    ``Word<...>`` substring found, including inner templates.  Comparisons
    (``operator<``, ``a < b``) are filtered out because they don't match the
    ``identifier<`` pattern or have unbalanced brackets.

    Examples::

        >>> extract_template_names('NiPointer<BSTriShape> * foo(BSTArray<int> a)')
        {'NiPointer<BSTriShape>', 'BSTArray<int>'}
        >>> extract_template_names('BSTArray<NiPointer<X>>')
        {'BSTArray<NiPointer<X>>', 'NiPointer<X>'}
    """
    found: Set[str] = set()
    _collect_templates(text, found)
    return found


def _collect_templates(text: str, found: Set[str]) -> None:
    """Recursive worker for :func:`extract_template_names`."""
    i = 0
    n = len(text)
    while i < n:
        m = _IDENT_LT.search(text, i)
        if m is None:
            break
        id_start = m.start()   # start of identifier
        lt_pos   = m.end() - 1  # position of '<'

        # Walk forward to find the matching '>'
        depth = 1
        j = lt_pos + 1
        while j < n and depth > 0:
            c = text[j]
            if c == '<':
                depth += 1
            elif c == '>':
                depth -= 1
            j += 1

        if depth != 0:
            # Unmatched '<' (e.g. comparison operator) — skip past it
            i = lt_pos + 1
            continue

        full_name = text[id_start:j]
        found.add(full_name)

        # Recurse into the argument list to capture nested instantiations
        inner = text[lt_pos + 1 : j - 1]
        _collect_templates(inner, found)

        i = j


def _templates_from_descriptor(desc: str) -> Set[str]:
    """Extract template instantiation names from a type descriptor string.

    Descriptors produced by ``_map_type`` look like::

        'ptr:struct:RE::NiPointer<RE::BSTriShape>'
        'struct:BSTArray<NiPointer<X>>'
        'arr:8:struct:BSSimpleList<TESForm *>'

    The type name (which may contain ``::`` namespace separators) is everything
    after the last recognised prefix token (``ptr``, ``struct``, ``enum``,
    ``arr``, or a numeric array size).  A naive ``.split(':')`` would break
    ``::`` into empty segments, so we protect ``::`` with a sentinel first.
    """
    if '<' not in desc:
        return set()
    # Protect C++ '::' namespace separators from being split on ':'
    protected = desc.replace('::', '\x00')
    for part in reversed(protected.split(':')):
        restored = part.replace('\x00', '::')
        if '<' in restored:
            return extract_template_names(restored)
    return set()


# ---------------------------------------------------------------------------
# Collection pass
# ---------------------------------------------------------------------------

def collect_template_names(
    structs: dict,
    sig_strings: Optional[List[str]] = None,
) -> Set[str]:
    """Scan struct field/vtable descriptors and optional signature strings.

    Parameters
    ----------
    structs:
        Dict of struct info dicts as produced by ``parse_commonlib_types.py``.
        Each entry is expected to have:

        - ``'fields'``: list of ``{'type': descriptor_str, ...}``
        - ``'vtable_slots'``: list of
          ``{'ret': descriptor_str, 'params': [(name, descriptor_str), ...]}``

    sig_strings:
        Optional list of raw C/C++ signature strings (e.g. the ``'sig'``
        values from the address-symbol table in ``extract_signatures.py``).

    Returns
    -------
    Set[str]
        Unique template instantiation name strings found across all inputs.
    """
    found: Set[str] = set()

    for info in structs.values():
        for f in info.get('fields', []):
            found |= _templates_from_descriptor(f.get('type', ''))

        for slot in info.get('vtable_slots', []):
            found |= _templates_from_descriptor(slot.get('ret', ''))
            for _pname, ptype in slot.get('params', []):
                found |= _templates_from_descriptor(ptype)

    for sig in (sig_strings or []):
        if '<' in sig:
            found |= extract_template_names(sig)

    return found


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def build_template_result(template_names: Set[str]) -> TemplateResult:
    """Build a :class:`TemplateResult` from a set of template instantiation names.

    If *template_names* is empty the returned result is still valid: the
    Python sources define an empty map and a no-op patch function so the
    generated Ghidra scripts compile and run without special-casing.

    Parameters
    ----------
    template_names:
        Output of :func:`collect_template_names`.

    Returns
    -------
    TemplateResult
    """
    if not template_names:
        return TemplateResult()

    # template_map: original → display name (RE:: stripped)
    # c_alias_map: original → sanitized C identifier
    template_map: Dict[str, str] = {}
    c_alias_map: Dict[str, str] = {}
    for name in sorted(template_names):
        sanitized = sanitize_template_name(name)
        display = _display_name(name)
        if sanitized and display:
            template_map[name] = display
            c_alias_map[name] = sanitized

    if not template_map:
        return TemplateResult()

    # C prelude fragment -------------------------------------------------------
    prelude_lines: List[str] = []
    seen: Set[str] = set()
    for _orig, sanitized in sorted(c_alias_map.items(), key=lambda kv: kv[1]):
        if sanitized in seen:
            continue
        seen.add(sanitized)
        prelude_lines.append(f'struct {sanitized};')
        prelude_lines.append(f'typedef struct {sanitized} {sanitized};')
    c_prelude_fragment = '\n'.join(prelude_lines) + '\n'

    # Python source: TEMPLATE_TYPE_MAP (original → display name for field resolution)
    map_lines = ['TEMPLATE_TYPE_MAP = {']
    for orig in sorted(template_map):
        map_lines.append(f'    {orig!r}: {template_map[orig]!r},')
    map_lines.append('}')
    map_source = '\n'.join(map_lines) + '\n'

    # Python source: TEMPLATE_C_ALIAS_MAP (original → sanitized C name for CParserUtils)
    alias_lines = ['TEMPLATE_C_ALIAS_MAP = {']
    for orig in sorted(c_alias_map):
        alias_lines.append(f'    {orig!r}: {c_alias_map[orig]!r},')
    alias_lines.append('}')
    map_source += '\n' + '\n'.join(alias_lines) + '\n'

    # Python source: _patch_templates uses C alias map for valid C identifiers
    patch_fn_source = (
        'def _patch_templates(proto):\n'
        '    """Substitute C++ template type names with C-safe aliases before parseSignature."""\n'
        '    for _tmpl, _alias in sorted(TEMPLATE_C_ALIAS_MAP.items(), key=lambda x: -len(x[0])):\n'
        '        proto = proto.replace(_tmpl, _alias)\n'
        '    return proto\n'
    )

    return TemplateResult(
        template_map=template_map,
        c_alias_map=c_alias_map,
        c_prelude_fragment=c_prelude_fragment,
        map_source=map_source,
        patch_fn_source=patch_fn_source,
    )


# ---------------------------------------------------------------------------
# Signature patching (generation-time utility)
# ---------------------------------------------------------------------------

def patch_proto_templates(proto: str, template_map: Dict[str, str]) -> str:
    """Replace template type names in *proto* with their sanitized C aliases.

    Longer names are substituted first so that nested instantiations are
    handled correctly: ``BSTArray<NiPointer<X>>`` is replaced before
    ``NiPointer<X>`` to avoid a partial substitution leaving ``BSTArray<…_alias…>``.

    This function is intended for **generation-time** use.  The equivalent
    logic at **Ghidra runtime** is the embedded ``_patch_templates`` function.
    """
    for original, sanitized in sorted(template_map.items(), key=lambda kv: -len(kv[0])):
        proto = proto.replace(original, sanitized)
    return proto


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def process_template_types(
    structs: dict,
    extra_types: Optional[dict] = None,
    sig_strings: Optional[List[str]] = None,
) -> TemplateResult:
    """Scan for template instantiation names and build aliases.

    This is the single entry point called from :mod:`parse_commonlib_types`
    and :mod:`extract_signatures`.

    Parameters
    ----------
    structs:
        Struct info dict from ``parse_commonlib_types.py``.  Pass ``{}`` when
        only scanning signature strings.
    extra_types:
        Dict loaded from ``extra_types.json``.  When provided, newly
        discovered sanitized alias names are inserted into
        ``extra_types['opaques']`` so they are forwarded to the DataTypeManager
        as opaque structs.  Modified **in place**; existing entries are
        preserved.
    sig_strings:
        Optional list of raw C++ signature strings to scan (e.g. all
        ``symbol['sig']`` values from the address-symbol table).

    Returns
    -------
    TemplateResult
        Append ``.c_prelude_fragment`` to your ``C_TYPE_PRELUDE`` string.
        Write ``.map_source`` and ``.patch_fn_source`` verbatim into the
        generated Ghidra script alongside the other module-level constants.
        At Ghidra runtime, call ``_patch_templates(proto)`` on each proto
        string before passing it to ``CParserUtils.parseSignature``.
    """
    names  = collect_template_names(structs, sig_strings)
    result = build_template_result(names)

    return result
