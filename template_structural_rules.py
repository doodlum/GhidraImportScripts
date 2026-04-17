"""
Structural size/field rules for C++ template types that can be resolved
from template arguments alone, without PDB type information.

Each rule is a function that receives the parsed (outer, args) of a
normalised template name and returns (size_bytes, fields_list) or
(0, []) if the rule does not apply.

Fields are dicts:  {'name': str, 'offset': int, 'size': int, 'type': str}
where 'type' is the same internal format used elsewhere in the pipeline:
  'ptr'        — 8-byte pointer
  'bytes:N'    — N opaque bytes
"""

import re as _re

# ---------------------------------------------------------------------------
# Primitive type → byte size table
# ---------------------------------------------------------------------------

INTEGRAL_SIZES = {
    'bool': 1,
    'char': 1, 'signed char': 1, 'unsigned char': 1,
    'short': 2, 'signed short': 2, 'unsigned short': 2,
    'int': 4, 'signed int': 4, 'unsigned int': 4,
    'long': 4, 'signed long': 4, 'unsigned long': 4,
    'long long': 8, 'signed long long': 8, 'unsigned long long': 8,
    # MSVC __int64 alias seen in PDB dumps
    'unsigned __int64': 8, '__int64': 8,
    # stdint
    'std::int8_t': 1,  'int8_t': 1,  'std::uint8_t': 1,  'uint8_t': 1,
    'std::int16_t': 2, 'int16_t': 2, 'std::uint16_t': 2, 'uint16_t': 2,
    'std::int32_t': 4, 'int32_t': 4, 'std::uint32_t': 4, 'uint32_t': 4,
    'std::int64_t': 8, 'int64_t': 8, 'std::uint64_t': 8, 'uint64_t': 8,
    # size/ptrdiff (64-bit target)
    'std::size_t': 8, 'size_t': 8,
    'std::ptrdiff_t': 8, 'ptrdiff_t': 8,
    'std::uintptr_t': 8, 'uintptr_t': 8,
    'std::intptr_t': 8, 'intptr_t': 8,
    # float/double
    'float': 4, 'double': 8,
}

# ---------------------------------------------------------------------------
# Reusable field-list templates
# ---------------------------------------------------------------------------

def _f(name, offset, size, typ=None):
    if typ is None:
        typ = 'bytes:{}'.format(size)
    return {'name': name, 'offset': offset, 'size': size, 'type': typ}


_PTR_FIELD  = [_f('_ptr', 0, 8, 'ptr')]
_IMPL1      = lambda sz: [_f('_impl', 0, sz)]
_IMPL4      = [_f('_impl', 0, 4)]
_IMPL8      = [_f('_impl', 0, 8)]

# BSTArray heap-allocator layout: data_ptr(8) + capacity(8) + size(8) = 24
_BSTARRAY_HEAP_FIELDS = [
    _f('_data',     0,  8, 'ptr'),
    _f('_capacity', 8,  8),
    _f('_size',     16, 8),
]

# BSSimpleList: head_ptr(8) + count(4) + pad(4) = 16
_BSTSIMPLELIST_FIELDS = [
    _f('_listHead', 0,  8, 'ptr'),
    _f('_listSize', 8,  4),
    _f('_pad0C',    12, 4),
]

# BSTScatterTable heap-allocator layout (confirmed from PDB): 48 bytes
# sentinel_ptr(8) + _pad08(8) + capacity(4) + free(4) + good(4) + pad(4) + allocator(8) + pad(8)
# Simplified as opaque blocks matching the PDB-confirmed 48-byte layout:
_BSTSCATTERTABLE_HEAP_FIELDS = [
    _f('_pad00', 0,  8, 'ptr'),
    _f('_pad08', 8,  8),
    _f('_capacity', 16, 4),
    _f('_free',     20, 4),
    _f('_good',     24, 4),
    _f('_pad1C',    28, 4),
    _f('_sentinel', 32, 8, 'ptr'),
    _f('_pad28',    40, 8),
]

# ---------------------------------------------------------------------------
# Parser helpers (inline so this module is self-contained)
# ---------------------------------------------------------------------------

_TMPL_WS_RE = _re.compile(r'\s+(?=[>,])|(?<=[<,])\s+')


def norm_tmpl(s):
    """Normalise template-type whitespace (strip spaces adjacent to <,>)."""
    return _TMPL_WS_RE.sub('', s) if s else s


def parse_tmpl(name):
    """Split 'Outer<A,B>' → ('Outer', ['A', 'B']). Returns (name, []) for non-templates."""
    lt = name.find('<')
    if lt < 0 or not name.endswith('>'):
        return name, []
    outer = name[:lt]
    inner = name[lt + 1:-1]
    args, depth, start = [], 0, 0
    for i, c in enumerate(inner):
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        elif c == ',' and depth == 0:
            a = inner[start:i].strip()
            if a:
                args.append(a)
            start = i + 1
    a = inner[start:].strip()
    if a:
        args.append(a)
    return outer, args


def _bare(name):
    """Strip leading 'RE::' or 'detail::' namespace prefix."""
    for prefix in ('RE::', 'detail::'):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _integral_size(typ):
    """Return byte size for a primitive C++ type string, or 0 if unknown."""
    return INTEGRAL_SIZES.get(typ.strip(), 0)


def _ptr_type_for(arg):
    """Build a typed pointer type string like 'ptr:struct:RE::NiNode' from a template arg.
    Returns plain 'ptr' if the arg is a primitive, pointer, or unrecognised type.
    """
    arg = arg.strip()
    if _integral_size(arg) or arg.endswith('*') or arg.endswith('* const'):
        return 'ptr'
    inner_o, _ = parse_tmpl(arg)
    bare = _bare(inner_o)
    if bare in INTEGRAL_SIZES:
        return 'ptr'
    # Build RE::-prefixed struct pointer
    full = arg if arg.startswith('RE::') else 'RE::' + arg
    return 'ptr:struct:{}'.format(full)


def _elem_size(arg, known_sizes=None):
    """Infer byte size of a template argument (primitive, raw pointer, or known smart ptr).
    known_sizes maps bare type name → size for structs/enums already resolved by the pipeline.
    """
    arg = arg.strip()
    sz = _integral_size(arg)
    if sz:
        return sz
    if arg.endswith('*') or arg.endswith('* const'):
        return 8
    inner_o, inner_a = parse_tmpl(arg)
    bare_inner = _bare(inner_o)
    if bare_inner in ('NiPointer', 'BSTSmartPointer', 'hkRefPtr') and inner_a:
        return 8
    # BSPointerHandle<T,...> — 4-byte handle (confirmed from PDB across all instances)
    if bare_inner in ('BSPointerHandle', 'BSUntypedPointerHandle', 'BSUntrackedPointerHandle'):
        return 4
    if known_sizes:
        # Try exact match, then strip leading RE::/detail:: namespace
        sz = known_sizes.get(arg, 0) or known_sizes.get(bare_inner, 0)
        if sz:
            return sz
    return 0


# ---------------------------------------------------------------------------
# Individual rule functions
# Each receives (outer_bare, args) and returns (size, fields) or (0, []).
# ---------------------------------------------------------------------------

def _rule_enum_wrapper(outer, args, known_sizes=None):
    """REX::EnumSet<E, U> and REX::Enum<E, U> — size = sizeof(U).
    If only one arg is given, falls back to known_sizes lookup on the enum type.
    """
    if outer not in ('REX::EnumSet', 'REX::Enum'):
        return 0, []
    if len(args) >= 2:
        sz = _integral_size(args[1])
        if sz:
            return sz, _IMPL1(sz)
    # 1-arg form: look up the enum's underlying size from already-resolved types
    if known_sizes and args:
        enum_bare = _bare(args[0])
        sz = known_sizes.get(args[0], 0) or known_sizes.get(enum_bare, 0)
        if sz:
            return sz, _IMPL1(sz)
    return 0, []


def _rule_bstarray(outer, args, known_sizes=None):
    """BSTArray<T[, Alloc]> — size depends on allocator."""
    if outer != 'BSTArray':
        return 0, []
    if not args:
        return 0, []
    alloc = _bare(args[1].strip()) if len(args) >= 2 else ''
    data_type = _ptr_type_for(args[0])

    if alloc in ('', 'BSTArrayHeapAllocator'):
        return 24, [
            _f('_data',     0,  8, data_type),
            _f('_capacity', 8,  8),
            _f('_size',     16, 8),
        ]

    if alloc == 'BSScrapArrayAllocator':
        return 32, [
            _f('_data',     0,  8, data_type),
            _f('_capacity', 8,  8),
            _f('_size',     16, 8),
            _f('_allocator', 24, 8, 'ptr'),
        ]

    m = _re.fullmatch(r'BSTSmallArrayHeapAllocator<(\d+)>', alloc)
    if m:
        n = int(m.group(1))
        sz = 16 + n
        return sz, [
            _f('_data',     0,  8, data_type),
            _f('_capacity', 8,  4),
            _f('_size',     12, 4),
            _f('_local',    16, n),
        ]

    return 0, []


def _rule_smart_ptr(outer, args, known_sizes=None):
    """NiPointer<T>, BSTSmartPointer<T>, hkRefPtr<T> — one 8-byte typed pointer."""
    if outer not in ('NiPointer', 'BSTSmartPointer', 'hkRefPtr') or not args:
        return 0, []
    return 8, [_f('_ptr', 0, 8, _ptr_type_for(args[0]))]


def _rule_bstsimplelist(outer, args):
    """BSSimpleList<T> — head pointer + count + pad = 16 bytes."""
    if outer != 'BSSimpleList' or not args:
        return 0, []
    return 16, list(_BSTSIMPLELIST_FIELDS)


def _rule_bstscattertable(outer, args):
    """BSTScatterTable<Key,Eq,Traits,BSTScatterTableHeapAllocator> — 48 bytes."""
    if outer != 'BSTScatterTable' or len(args) < 4:
        return 0, []
    alloc = _bare(args[3].strip())
    if alloc != 'BSTScatterTableHeapAllocator':
        return 0, []
    return 48, list(_BSTSCATTERTABLE_HEAP_FIELDS)


def _rule_bstscattertable_traits(outer, args):
    """BSTScatterTableTraits<K,V> — stateless traits type, size=1."""
    if outer != 'BSTScatterTableTraits' or len(args) < 2:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_bscrc32(outer, args):
    """BSCRC32<T> — stateless hash functor, size=1."""
    if outer != 'BSCRC32' or not args:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_std_equal_to(outer, args):
    """std::equal_to<T> — stateless comparator, size=1."""
    if outer != 'std::equal_to' or not args:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


def _rule_std_array(outer, args, known_sizes=None):
    """std::array<T, N> — size = N * sizeof(T)."""
    if outer != 'std::array' or len(args) < 2:
        return 0, []
    sz_elem = _elem_size(args[0], known_sizes)
    if not sz_elem:
        return 0, []
    try:
        n = int(args[1])
    except ValueError:
        return 0, []
    sz = sz_elem * n
    if not sz:
        return 0, []
    return sz, [_f('_data', 0, sz)]


def _rule_std_vector(outer, args):
    """std::vector<T[, Alloc]> — pointer + size + capacity = 24 bytes."""
    if outer != 'std::vector' or not args:
        return 0, []
    return 24, list(_BSTARRAY_HEAP_FIELDS)


def _rule_std_span(outer, args):
    """std::span<T[, Extent]> — pointer + size = 16 bytes (dynamic extent only)."""
    if outer != 'std::span' or not args:
        return 0, []
    # Static extent (non-dynamic) has size = pointer only = 8, but we can't
    # easily distinguish without constexpr eval; dynamic span is the common case.
    return 16, [_f('_data', 0, 8, 'ptr'), _f('_size', 8, 8)]


def _rule_std_basic_string(outer, args):
    """std::basic_string<CharT> — MSVC SSO layout = 32 bytes."""
    if outer != 'std::basic_string' or not args:
        return 0, []
    return 32, [
        _f('_bx',    0,  16),   # SSO union: inline buf or heap ptr
        _f('_size',  16, 8),
        _f('_res',   24, 8),
    ]


def _rule_nitilistitem(outer, args, known_sizes=None):
    """NiTListItem<T> — doubly-linked node: prev(8) + next(8) + data(sizeof T)."""
    if outer != 'NiTListItem' or not args:
        return 0, []
    elem_sz = _elem_size(args[0], known_sizes)
    if not elem_sz:
        return 0, []
    data_off = 16
    sz = (data_off + elem_sz + 7) & ~7
    return sz, [
        _f('_prev', 0,        8, 'ptr'),
        _f('_next', 8,        8, 'ptr'),
        _f('_data', data_off, elem_sz),
    ]


def _rule_bsttuple(outer, args, known_sizes=None):
    """BSTTuple<A, B> — std::pair-like; size derived from element sizes + alignment."""
    if outer != 'BSTTuple' or len(args) < 2:
        return 0, []
    sz_a = _elem_size(args[0], known_sizes)
    sz_b = _elem_size(args[1], known_sizes)
    if not sz_a or not sz_b:
        return 0, []
    # Standard struct layout: B aligned to min(sz_b, 8)
    align_b = min(sz_b, 8)
    off_b = (sz_a + align_b - 1) & ~(align_b - 1)
    total = off_b + sz_b
    # Round total up to alignment of the largest field
    align_total = max(min(sz_a, 8), min(sz_b, 8))
    total = (total + align_total - 1) & ~(align_total - 1)
    return total, [_f('first', 0, sz_a), _f('second', off_b, sz_b)]


def _rule_gallocator(outer, args):
    """GAllocatorGH<T, N> — stateless GFx heap allocator, size=1."""
    if outer != 'GAllocatorGH' or not args:
        return 0, []
    return 1, [_f('_pad', 0, 1)]


# ---------------------------------------------------------------------------
# Dispatch table — rules tried in order
# ---------------------------------------------------------------------------

_RULES = [
    _rule_enum_wrapper,
    _rule_bstarray,
    _rule_smart_ptr,
    _rule_bstsimplelist,
    _rule_bsttuple,
    _rule_gallocator,
    _rule_bstscattertable,
    _rule_bstscattertable_traits,
    _rule_bscrc32,
    _rule_std_equal_to,
    _rule_std_array,
    _rule_std_vector,
    _rule_std_span,
    _rule_std_basic_string,
    _rule_nitilistitem,
]


def structural_rule(orig_n, known_sizes=None):
    """Return (size, fields) for a normalised template type, or (0, []) if no rule applies.

    known_sizes: optional dict mapping type name (bare or full) → byte size, used to
    resolve element sizes for tuple/array rules when the element is a struct or enum
    already processed by the pipeline.
    """
    outer, args = parse_tmpl(orig_n)
    bare_outer = _bare(outer)
    for rule in _RULES:
        try:
            sz, fields = rule(bare_outer, args, known_sizes)
        except TypeError:
            # Rule doesn't accept known_sizes (shouldn't happen, but safe fallback)
            sz, fields = rule(bare_outer, args)
        if sz:
            return sz, fields
    return 0, []
