#!/usr/bin/env python3
"""
Parse CommonLibSSE headers using libclang and generate a Ghidra import script
(ghidrascripts/CommonLibTypes.py) that creates struct/class/enum type definitions.

Requires Python 3.x (64-bit) with the libclang package installed.
Run with: py -3.13 parse_commonlib_types.py
"""

import os
import sys
import re
import struct
import math

# ---------------------------------------------------------------------------
# libclang setup
# ---------------------------------------------------------------------------

def _find_libclang_dll():
    """Try to locate libclang.dll from the installed libclang package."""
    try:
        import clang
        pkg_dir = os.path.dirname(clang.__file__)
        candidate = os.path.join(pkg_dir, 'native', 'libclang.dll')
        if os.path.isfile(candidate):
            return candidate
    except ImportError:
        pass
    # Fallback locations
    fallbacks = [
        r'C:\Program Files\LLVM\bin\libclang.dll',
        r'C:\Program Files (x86)\LLVM\bin\libclang.dll',
    ]
    for fb in fallbacks:
        if os.path.isfile(fb):
            return fb
    return None


_dll = _find_libclang_dll()
if not _dll:
    print('ERROR: Could not find libclang.dll. Install libclang: pip install libclang')
    sys.exit(1)

import clang.cindex as ci
ci.Config.set_library_file(_dll)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMMONLIB_INCLUDE = os.path.join(SCRIPT_DIR, 'extern', 'CommonLibSSE', 'include')
SKYRIM_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Skyrim.h')
RE_INCLUDE = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'ghidrascripts')
OUTPUT_SCRIPT = os.path.join(OUTPUT_DIR, 'CommonLibTypes.py')
PDB_SE_PATH = os.path.join(SCRIPT_DIR, 'pdbs', 'GhidraImport_SE_D.pdb')

# ---------------------------------------------------------------------------
# PDB TPI parser — extracts RE:: struct layouts (field names + byte offsets)
# ---------------------------------------------------------------------------

def _pdb_read_numeric(data, pos):
    val = struct.unpack_from('<H', data, pos)[0]
    if val < 0x8000: return val, pos + 2
    if val == 0x8000: return struct.unpack_from('<b',  data, pos+2)[0], pos + 3
    if val == 0x8001: return struct.unpack_from('<h',  data, pos+2)[0], pos + 4
    if val == 0x8002: return struct.unpack_from('<H',  data, pos+2)[0], pos + 4
    if val == 0x8003: return struct.unpack_from('<i',  data, pos+2)[0], pos + 6
    if val == 0x8004: return struct.unpack_from('<I',  data, pos+2)[0], pos + 6
    if val == 0x8009: return struct.unpack_from('<q',  data, pos+2)[0], pos + 10
    if val == 0x800a: return struct.unpack_from('<Q',  data, pos+2)[0], pos + 10
    return 0, pos + 2

def _pdb_read_cstr(data, pos):
    end = data.index(b'\x00', pos)
    return data[pos:end].decode('utf-8', errors='replace'), end + 1

def _pdb_read_stream(data, page_size, stream_pages, sizes, idx):
    if idx >= len(sizes) or sizes[idx] == 0xFFFFFFFF:
        return b''
    buf = bytearray()
    for pg in stream_pages[idx]:
        buf += data[pg * page_size : (pg + 1) * page_size]
    return bytes(buf[:sizes[idx]])

def _pdb_parse_msf(data):
    page_size = struct.unpack_from('<I', data, 32)[0]
    dir_size  = struct.unpack_from('<I', data, 44)[0]
    blk_map   = struct.unpack_from('<I', data, 52)[0]
    n_blk     = math.ceil(dir_size / page_size)
    dir_data  = bytearray()
    for i in range(n_blk):
        pg = struct.unpack_from('<I', data, blk_map * page_size + i * 4)[0]
        dir_data += data[pg * page_size : (pg + 1) * page_size]
    dir_data = bytes(dir_data[:dir_size])
    n_streams = struct.unpack_from('<I', dir_data, 0)[0]
    sizes = [struct.unpack_from('<I', dir_data, 4 + i*4)[0] for i in range(n_streams)]
    stream_pages = []
    off = 4 + n_streams * 4
    for sz in sizes:
        n = math.ceil(sz / page_size) if sz != 0xFFFFFFFF else 0
        pages = [struct.unpack_from('<I', dir_data, off + i*4)[0] for i in range(n)]
        stream_pages.append(pages)
        off += n * 4
    return page_size, sizes, stream_pages

# CodeView leaf type constants
_LF_FIELDLIST  = 0x1203
_LF_BCLASS     = 0x1400
_LF_VBCLASS    = 0x1401
_LF_IVBCLASS   = 0x1402
_LF_INDEX      = 0x1404
_LF_VFUNCTAB   = 0x1409
_LF_ENUMERATE  = 0x1502
_LF_STRUCTURE  = 0x1505
_LF_CLASS      = 0x1504
_LF_MEMBER     = 0x150d
_LF_STMEMBER   = 0x150e
_LF_METHOD     = 0x150f
_LF_NESTTYPE   = 0x1510
_LF_ONEMETHOD  = 0x1511
_CV_fwdref     = 0x0080

def load_pdb_types(pdb_path):
    """
    Parse the TPI stream of a PDB file and return a dict:
      { 'RE::StructName': {
            'size': N,
            'fields': [('name', byte_offset), ...],   # own members only
            'bases':  [('RE::BaseName', base_offset), ...],  # direct bases + their offset
        } }
    Only includes non-forward-reference RE:: types with size > 0.
    """
    if not os.path.isfile(pdb_path):
        return {}

    with open(pdb_path, 'rb') as f:
        data = f.read()

    if data[:8] != b'Microsof':
        return {}

    page_size, sizes, stream_pages = _pdb_parse_msf(data)
    tpi = _pdb_read_stream(data, page_size, stream_pages, sizes, 2)
    if len(tpi) < 56:
        return {}

    _, hdr_size, ti_min, ti_max = struct.unpack_from('<IIII', tpi, 0)

    # Pass 1: build type index → byte offset map
    ti_offsets = {}
    pos = hdr_size
    ti = ti_min
    while pos + 4 <= len(tpi) and ti < ti_max:
        rec_len = struct.unpack_from('<H', tpi, pos)[0]
        if rec_len < 2:
            break
        ti_offsets[ti] = pos
        ti += 1
        pos = ((pos + 2 + rec_len) + 3) & ~3

    # Pass 2: build type index → struct name (for resolving LF_BCLASS references)
    ti_to_name = {}
    pos = hdr_size
    ti = ti_min
    while pos + 4 <= len(tpi) and ti < ti_max:
        rec_len = struct.unpack_from('<H', tpi, pos)[0]
        if rec_len < 2:
            break
        leaf = struct.unpack_from('<H', tpi, pos + 2)[0]
        if leaf in (_LF_STRUCTURE, _LF_CLASS):
            p = pos + 4 + 16          # skip count/prop/field_ti/derived/vshape
            _, p = _pdb_read_numeric(tpi, p)  # size
            name, _ = _pdb_read_cstr(tpi, p)
            if name and '<' not in name and '`' not in name:
                ti_to_name[ti] = name
        ti += 1
        pos = ((pos + 2 + rec_len) + 3) & ~3

    def parse_fieldlist(fl_ti):
        """Return (members, bases, vfuncs) from an LF_FIELDLIST.
        members: [(field_name, byte_offset)]
        bases:   [(base_struct_name, byte_offset_within_derived)]
        vfuncs:  [(method_name, vbaseoff)] — intro virtual methods only (mprop 4/5)
        """
        members = []
        bases = []
        vfuncs = []
        seen = set()
        queue = [fl_ti]
        while queue:
            cur = queue.pop(0)
            if cur in seen or cur not in ti_offsets:
                continue
            seen.add(cur)
            rpos = ti_offsets[cur]
            rec_len = struct.unpack_from('<H', tpi, rpos)[0]
            leaf = struct.unpack_from('<H', tpi, rpos + 2)[0]
            if leaf != _LF_FIELDLIST:
                continue
            p = rpos + 4
            end = rpos + 2 + rec_len
            while p < end:
                if p + 2 > end:
                    break
                if tpi[p] >= 0xF0:   # padding byte
                    p += 1
                    continue
                fld = struct.unpack_from('<H', tpi, p)[0]
                p += 2
                try:
                    if fld == _LF_MEMBER:
                        _attr, _typ = struct.unpack_from('<HI', tpi, p); p += 6
                        off, p = _pdb_read_numeric(tpi, p)
                        name, p = _pdb_read_cstr(tpi, p)
                        members.append((name, off))
                    elif fld == _LF_BCLASS:
                        _attr, btype_ti = struct.unpack_from('<HI', tpi, p); p += 6
                        off, p = _pdb_read_numeric(tpi, p)
                        base_name = ti_to_name.get(btype_ti, '')
                        if base_name:
                            bases.append((base_name, off))
                    elif fld == _LF_STMEMBER:
                        p += 2 + 4
                        _, p = _pdb_read_cstr(tpi, p)
                    elif fld == _LF_METHOD:
                        p += 2 + 4
                        _, p = _pdb_read_cstr(tpi, p)
                    elif fld == _LF_ONEMETHOD:
                        attr, _typ = struct.unpack_from('<HI', tpi, p); p += 6
                        mprop = (attr >> 2) & 7
                        vbaseoff = None
                        if mprop in (4, 5):
                            vbaseoff = struct.unpack_from('<i', tpi, p)[0]; p += 4
                        name, p = _pdb_read_cstr(tpi, p)
                        if vbaseoff is not None and name and '<' not in name:
                            vfuncs.append((name, vbaseoff))
                    elif fld == _LF_NESTTYPE:
                        p += 2 + 4
                        _, p = _pdb_read_cstr(tpi, p)
                    elif fld in (_LF_VBCLASS, _LF_IVBCLASS):
                        p += 2 + 4 + 4
                        _, p = _pdb_read_numeric(tpi, p)
                        _, p = _pdb_read_numeric(tpi, p)
                    elif fld == _LF_VFUNCTAB:
                        p += 2 + 4
                    elif fld == _LF_ENUMERATE:
                        p += 2
                        _, p = _pdb_read_numeric(tpi, p)
                        _, p = _pdb_read_cstr(tpi, p)
                    elif fld == _LF_INDEX:
                        p += 2
                        cont = struct.unpack_from('<I', tpi, p)[0]; p += 4
                        queue.append(cont)
                    else:
                        break
                except Exception:
                    break
                p = (p + 3) & ~3
        return members, bases, vfuncs

    # Pass 3: collect all non-forward RE:: struct definitions
    result = {}
    pos = hdr_size
    ti = ti_min
    while pos + 4 <= len(tpi) and ti < ti_max:
        rec_len = struct.unpack_from('<H', tpi, pos)[0]
        if rec_len < 2:
            break
        leaf = struct.unpack_from('<H', tpi, pos + 2)[0]
        if leaf in (_LF_STRUCTURE, _LF_CLASS):
            p = pos + 4
            _cnt, prop, field_ti, _der, _vsh = struct.unpack_from('<HHIII', tpi, p)
            p += 16
            sz, p = _pdb_read_numeric(tpi, p)
            name, _ = _pdb_read_cstr(tpi, p)
            is_fwd = bool(prop & _CV_fwdref)
            if (not is_fwd and sz > 0 and field_ti
                    and name.startswith('RE::') and '<' not in name):
                if name not in result:
                    members, bases, vfuncs = parse_fieldlist(field_ti)
                    result[name] = {
                        'size': sz,
                        'fields': members,
                        'bases': bases,   # [(base_name, base_offset)]
                        'vfuncs': vfuncs, # [(method_name, vbaseoff)]
                    }
        ti += 1
        pos = ((pos + 2 + rec_len) + 3) & ~3

    return result

PARSE_ARGS = [
    '-x', 'c++',
    '-std=c++23',
    '-fms-compatibility',
    '-fms-extensions',
    '-DWIN32', '-D_WIN64',
    '-DENABLE_SKYRIM_AE',
    '-I' + COMMONLIB_INCLUDE,
]

PARSE_OPTIONS = (
    ci.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES |
    ci.TranslationUnit.PARSE_INCOMPLETE
)

# ---------------------------------------------------------------------------
# Type mapping helpers
# ---------------------------------------------------------------------------

_PRIM_MAP = {
    ci.TypeKind.BOOL:       'bool',
    ci.TypeKind.CHAR_S:     'i8',
    ci.TypeKind.SCHAR:      'i8',
    ci.TypeKind.CHAR_U:     'u8',
    ci.TypeKind.UCHAR:      'u8',
    ci.TypeKind.SHORT:      'i16',
    ci.TypeKind.USHORT:     'u16',
    ci.TypeKind.INT:        'i32',
    ci.TypeKind.UINT:       'u32',
    ci.TypeKind.LONG:       'i32',   # Windows: long = 32-bit
    ci.TypeKind.ULONG:      'u32',
    ci.TypeKind.LONGLONG:   'i64',
    ci.TypeKind.ULONGLONG:  'u64',
    ci.TypeKind.FLOAT:      'f32',
    ci.TypeKind.DOUBLE:     'f64',
    ci.TypeKind.VOID:       'void',
    ci.TypeKind.WCHAR:      'u16',
}

_POINTER_KINDS = {
    ci.TypeKind.POINTER,
    ci.TypeKind.LVALUEREFERENCE,
    ci.TypeKind.RVALUEREFERENCE,
    ci.TypeKind.MEMBERPOINTER,
    ci.TypeKind.BLOCKPOINTER,
    ci.TypeKind.OBJCOBJECTPOINTER,
}

_FUNC_KINDS = {
    ci.TypeKind.FUNCTIONPROTO,
    ci.TypeKind.FUNCTIONNOPROTO,
}


def _get_full_qual_name(cursor):
    """Build fully qualified name, e.g. RE::BSFixedString."""
    parts = []
    c = cursor
    while c and c.kind != ci.CursorKind.TRANSLATION_UNIT:
        if c.spelling:
            parts.append(c.spelling)
        c = c.semantic_parent
    parts.reverse()
    return '::'.join(parts)


def _get_namespace_path(cursor):
    """Return namespace components (excluding the type name itself)."""
    parts = []
    c = cursor.semantic_parent
    while c and c.kind != ci.CursorKind.TRANSLATION_UNIT:
        if c.kind == ci.CursorKind.NAMESPACE and c.spelling:
            parts.append(c.spelling)
        c = c.semantic_parent
    parts.reverse()
    return parts


def _map_type(typ, depth=0):
    """Map a clang Type to our simplified type descriptor string."""
    if depth > 8:
        return 'ptr'

    kind = typ.kind

    # Primitives
    if kind in _PRIM_MAP:
        return _PRIM_MAP[kind]

    # Pointers and references → 8-byte pointer
    if kind in _POINTER_KINDS:
        return 'ptr'

    # Function types → treat as pointer
    if kind in _FUNC_KINDS:
        return 'ptr'

    # Elaborated type (e.g. "struct Foo", "enum Bar") → unwrap
    if kind == ci.TypeKind.ELABORATED:
        return _map_type(typ.get_named_type(), depth + 1)

    # Typedef → follow canonical
    if kind == ci.TypeKind.TYPEDEF:
        return _map_type(typ.get_canonical(), depth + 1)

    # Constant array
    if kind == ci.TypeKind.CONSTANTARRAY:
        elem = _map_type(typ.element_type, depth + 1)
        count = typ.element_count
        if count > 0:
            return 'arr:{}:{}'.format(elem, count)
        return 'ptr'

    # Struct/class record
    if kind == ci.TypeKind.RECORD:
        decl = typ.get_declaration()
        if decl and decl.spelling:
            name = _get_full_qual_name(decl)
            if name:
                return 'struct:' + name
        sz = typ.get_size()
        if sz > 0:
            return 'bytes:' + str(sz)
        return 'ptr'

    # Enum
    if kind == ci.TypeKind.ENUM:
        decl = typ.get_declaration()
        if decl and decl.spelling:
            name = _get_full_qual_name(decl)
            if name:
                return 'enum:' + name
        sz = typ.get_size()
        if sz > 0:
            return 'bytes:' + str(sz)
        return 'i32'

    # Incomplete array → pointer
    if kind == ci.TypeKind.INCOMPLETEARRAY:
        return 'ptr'

    # Fallback: use size
    sz = typ.get_size()
    if sz > 0:
        return 'bytes:' + str(sz)
    return 'ptr'


# ---------------------------------------------------------------------------
# AST walking
# ---------------------------------------------------------------------------

def _is_in_re_include(cursor):
    """Return True if the cursor is defined in the RE include directory."""
    loc = cursor.location
    if not loc.file:
        return False
    path = str(loc.file).replace('\\', '/')
    re_path = RE_INCLUDE.replace('\\', '/')
    return path.startswith(re_path)


def _collect_types(tu):
    """Walk the AST and collect enum/struct/class definitions from RE include."""
    enums = {}   # full_name → {name, size, category, values}
    structs = {} # full_name → {name, size, category, fields, bases, has_vtable}

    # Two-pass: first collect all names, then collect fields
    # (so we can resolve forward references)

    def walk(cursor):
        kind = cursor.kind

        if kind == ci.CursorKind.ENUM_DECL:
            if not _is_in_re_include(cursor):
                # Still recurse for nested types
                for c in cursor.get_children():
                    walk(c)
                return
            if not cursor.spelling:
                for c in cursor.get_children():
                    walk(c)
                return
            sz = cursor.type.get_size()
            if sz <= 0:
                for c in cursor.get_children():
                    walk(c)
                return

            # Only process the definition, not forward declarations
            if not cursor.is_definition():
                for c in cursor.get_children():
                    walk(c)
                return

            full_name = _get_full_qual_name(cursor)
            if full_name in enums:
                for c in cursor.get_children():
                    walk(c)
                return

            ns_path = _get_namespace_path(cursor)
            category = '/CommonLibSSE/' + '/'.join(ns_path) if ns_path else '/CommonLibSSE'

            values = []
            for child in cursor.get_children():
                if child.kind == ci.CursorKind.ENUM_CONSTANT_DECL:
                    values.append((child.spelling, child.enum_value))

            enums[full_name] = {
                'name': cursor.spelling,
                'full_name': full_name,
                'size': sz,
                'category': category,
                'values': values,
            }

        elif kind in (ci.CursorKind.STRUCT_DECL, ci.CursorKind.CLASS_DECL):
            if not _is_in_re_include(cursor):
                for c in cursor.get_children():
                    walk(c)
                return
            if not cursor.spelling or cursor.spelling.startswith('(unnamed'):
                for c in cursor.get_children():
                    walk(c)
                return

            sz = cursor.type.get_size()
            if sz <= 0:
                # Incomplete / forward-declared, still recurse
                for c in cursor.get_children():
                    walk(c)
                return

            # Only process the canonical definition, not forward declarations
            if not cursor.is_definition():
                for c in cursor.get_children():
                    walk(c)
                return

            full_name = _get_full_qual_name(cursor)
            if full_name in structs:
                for c in cursor.get_children():
                    walk(c)
                return

            ns_path = _get_namespace_path(cursor)
            category = '/CommonLibSSE/' + '/'.join(ns_path) if ns_path else '/CommonLibSSE'

            # Collect fields
            fields = []
            bases = []
            has_vtable = False

            for child in cursor.get_children():
                if child.kind == ci.CursorKind.CXX_BASE_SPECIFIER:
                    base_type = child.type
                    base_name = _get_full_qual_name(child.referenced) if child.referenced else ''
                    if not base_name:
                        # Try from spelling
                        sp = child.spelling.replace('public ', '').replace('private ', '').replace('protected ', '').strip()
                        base_name = sp
                    if base_name:
                        bases.append(base_name)

                elif child.kind == ci.CursorKind.FIELD_DECL:
                    fname = child.spelling
                    if not fname:
                        continue
                    # Get offset in bytes
                    try:
                        offset_bits = cursor.type.get_offset(fname)
                        if offset_bits < 0:
                            continue
                        offset = offset_bits // 8
                    except Exception:
                        continue

                    ftype_str = _map_type(child.type)
                    fsize = child.type.get_size()
                    if fsize < 0:
                        # Try to infer from type string
                        fsize = _type_str_size(ftype_str)

                    fields.append({
                        'name': fname,
                        'type': ftype_str,
                        'offset': offset,
                        'size': max(fsize, 0),
                    })

                elif child.kind == ci.CursorKind.CXX_METHOD:
                    if child.is_virtual_method():
                        has_vtable = True

            structs[full_name] = {
                'name': cursor.spelling,
                'full_name': full_name,
                'size': sz,
                'category': category,
                'fields': fields,
                'bases': bases,
                'has_vtable': has_vtable,
            }

        # Always recurse into namespaces
        if kind in (ci.CursorKind.NAMESPACE,
                    ci.CursorKind.TRANSLATION_UNIT,
                    ci.CursorKind.STRUCT_DECL,
                    ci.CursorKind.CLASS_DECL,
                    ci.CursorKind.ENUM_DECL):
            for c in cursor.get_children():
                walk(c)

    walk(tu.cursor)
    return enums, structs


def _type_str_size(type_str):
    """Estimate byte size from our type string."""
    sizes = {
        'bool': 1, 'i8': 1, 'u8': 1,
        'i16': 2, 'u16': 2,
        'i32': 4, 'u32': 4, 'f32': 4,
        'i64': 8, 'u64': 8, 'f64': 8,
        'ptr': 8, 'void': 0,
    }
    if type_str in sizes:
        return sizes[type_str]
    if type_str.startswith('bytes:'):
        return int(type_str[6:])
    if type_str.startswith('arr:'):
        # arr:ELEM:COUNT — count is always the last colon-terminated integer
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem_size = _type_str_size(rest[:last])
            return elem_size * count
        return 0
    if type_str.startswith('enum:'):
        return 4  # default enum size
    if type_str.startswith('struct:'):
        return 8  # unknown, assume pointer-sized
    return 0


# ---------------------------------------------------------------------------
# Ghidra script generation
# ---------------------------------------------------------------------------

GHIDRA_HEADER = '''\
# Ghidra import script: CommonLib SSE type definitions
# Generated by parse_commonlib_types.py
# Run in Ghidra via Script Manager
#
# @category CommonLib
# @description Import CommonLibSSE struct/class/enum type definitions

from ghidra.program.model.data import (
    StructureDataType, EnumDataType, ArrayDataType, PointerDataType,
    CategoryPath, DataTypeConflictHandler,
    ByteDataType, WordDataType, DWordDataType, QWordDataType,
    CharDataType, BooleanDataType,
    FloatDataType, DoubleDataType,
    ShortDataType, IntegerDataType, LongLongDataType,
    UnsignedShortDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
)

dtm = currentProgram.getDataTypeManager()
CONFLICT = DataTypeConflictHandler.REPLACE_HANDLER

created = {}  # full_name -> DataType

_BYTE  = ByteDataType()
_PTR   = PointerDataType()
_BOOL  = BooleanDataType()
_I16   = ShortDataType()
_U16   = UnsignedShortDataType()
_I32   = IntegerDataType()
_U32   = UnsignedIntegerDataType()
_I64   = LongLongDataType()
_U64   = UnsignedLongLongDataType()
_F32   = FloatDataType()
_F64   = DoubleDataType()

def get_builtin(type_str):
    if type_str == 'bool': return _BOOL
    if type_str == 'i8':   return _BYTE
    if type_str == 'u8':   return _BYTE
    if type_str == 'i16':  return _I16
    if type_str == 'u16':  return _U16
    if type_str == 'i32':  return _I32
    if type_str == 'u32':  return _U32
    if type_str == 'i64':  return _I64
    if type_str == 'u64':  return _U64
    if type_str == 'f32':  return _F32
    if type_str == 'f64':  return _F64
    if type_str == 'ptr':  return _PTR
    return None

def resolve_type(type_str):
    b = get_builtin(type_str)
    if b: return b
    if type_str.startswith('ptr'): return _PTR
    if type_str.startswith('bytes:'):
        n = int(type_str[6:])
        return ArrayDataType(_BYTE, n, 1) if n > 1 else _BYTE
    if type_str.startswith('arr:'):
        # arr:ELEM:COUNT — count is always the last colon-terminated integer
        rest = type_str[4:]
        last = rest.rfind(':')
        if last >= 0 and rest[last+1:].isdigit():
            count = int(rest[last+1:])
            elem = resolve_type(rest[:last])
            if elem and count > 0:
                return ArrayDataType(elem, count, elem.getLength())
        return None
    if type_str.startswith('enum:'):
        name = type_str[5:]
        return created.get(name) or created.get(name.split('::')[-1])
    if type_str.startswith('struct:'):
        name = type_str[7:]
        return created.get(name) or created.get(name.split('::')[-1])
    if type_str.startswith('vtblptr:'):
        name = type_str[8:]
        vtbl_dt = created.get('vtbl:' + name)
        if vtbl_dt:
            return PointerDataType(vtbl_dt, 8)
        return _PTR
    return None

def make_padding(size):
    if size == 1: return _BYTE
    return ArrayDataType(_BYTE, size, 1)

'''

GHIDRA_FOOTER = '''\

def run_import():
    # Pass 1: create all enums
    monitor.setMessage('Creating enums...')
    for en in ENUMS:
        name, size, category, values = en
        e = EnumDataType(CategoryPath(category), name, size)
        for vname, vval in values:
            try:
                e.add(vname, vval)
            except Exception:
                e.add(vname + '_', vval)
        dt = dtm.addDataType(e, CONFLICT)
        created[name] = dt
        created[category + '/' + name] = dt
        ns = category[len('/CommonLibSSE/'):].replace('/', '::')
        if ns:
            created[ns + '::' + name] = dt
    print('Created {} enums'.format(len(ENUMS)))

    # Pass 1.5: create vtable structs (function pointer tables)
    monitor.setMessage('Creating vtable structs...')
    for vt in VTABLES:
        vname, vtbl_size, category, slots = vt
        s = StructureDataType(CategoryPath(category), vname, vtbl_size)
        for slot_off, slot_name in slots:
            if slot_off + 8 <= vtbl_size:
                try:
                    s.replaceAtOffset(slot_off, _PTR, 8, slot_name, '')
                except Exception:
                    pass
        dt = dtm.addDataType(s, CONFLICT)
        created['vtbl:' + vname] = dt
    print('Created {} vtable structs'.format(len(VTABLES)))

    # Pass 2: create all structs (empty shells)
    monitor.setMessage('Creating struct shells...')
    for st in STRUCTS:
        name, size, category, fields, bases, has_vtable = st
        s = StructureDataType(CategoryPath(category), name, size)
        dt = dtm.addDataType(s, CONFLICT)
        created[name] = dt
        created[category + '/' + name] = dt
        # Also store as qualified namespace name (RE::StructName)
        ns = category[len('/CommonLibSSE/'):].replace('/', '::')
        if ns:
            created[ns + '::' + name] = dt
    print('Created {} struct shells'.format(len(STRUCTS)))

    # Pass 3: fill in struct fields using replaceAtOffset
    # (StructureDataType created with a fixed size is pre-filled with undefined bytes;
    # replaceAtOffset replaces those undefined slots without shifting anything)
    monitor.setMessage('Filling struct fields...')
    filled = 0
    for st in STRUCTS:
        name, size, category, fields, bases, has_vtable = st
        s = dtm.getDataType(CategoryPath(category), name)
        if not s:
            continue

        # Fields (pre-flattened — all base class members inlined at absolute offsets,
        # including __vftable slots for each virtual base)
        for field in fields:
            fname, ftype_str, foffset, fsize = field
            if fsize <= 0 or foffset + fsize > size:
                continue

            dt_field = resolve_type(ftype_str)
            # Use the resolved type if its size matches, otherwise fall back to raw bytes
            if dt_field and dt_field.getLength() == fsize:
                use_dt = dt_field
                use_name = fname
            else:
                use_dt = make_padding(fsize)
                use_name = fname + '_raw'

            try:
                s.replaceAtOffset(foffset, use_dt, fsize, use_name, '')
                cursor = foffset + fsize
            except Exception:
                pass

        filled += 1

    print('Filled {} structs'.format(filled))
    print('Import complete.')

run_import()
'''


def generate_script(enums, structs, vtable_structs, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    lines = [GHIDRA_HEADER]

    # Emit VTABLES
    lines.append('VTABLES = [')
    for vt in sorted(vtable_structs.values(), key=lambda v: v['name']):
        lines.append('    ({}, {}, {}, {}),'.format(
            repr(vt['name']), repr(vt['size']), repr(vt['category']),
            repr(vt['slots'])))
    lines.append(']')
    lines.append('')

    # Emit ENUMS
    lines.append('ENUMS = [')
    for en in sorted(enums.values(), key=lambda e: e['full_name']):
        name = en['name']
        size = en['size']
        category = en['category']
        values = en['values']
        val_str = repr(values)
        lines.append('    ({}, {}, {}, {}),'.format(
            repr(name), repr(size), repr(category), val_str))
    lines.append(']')
    lines.append('')

    # Emit STRUCTS
    lines.append('STRUCTS = [')
    for st in sorted(structs.values(), key=lambda s: s['full_name']):
        name = st['name']
        size = st['size']
        category = st['category']
        has_vtable = st['has_vtable']
        bases = st['bases']

        # Sort fields by offset, deduplicate names
        fields = sorted(st['fields'], key=lambda f: f['offset'])
        seen_names = {}
        deduped_fields = []
        for f in fields:
            n = f['name']
            if n in seen_names:
                seen_names[n] += 1
                n = '{}_{}'.format(n, seen_names[n])
            else:
                seen_names[n] = 0
            deduped_fields.append((n, f['type'], f['offset'], f['size']))

        lines.append('    ({}, {}, {}, {}, {}, {}),'.format(
            repr(name), repr(size), repr(category),
            repr(deduped_fields), repr(bases), repr(has_vtable)))
    lines.append(']')
    lines.append('')

    lines.append(GHIDRA_FOOTER)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return len(enums), len(structs)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _merge_pdb_into_structs(structs, pdb_types):
    """
    Cross-reference libclang struct data with PDB TPI data.
    Also stores PDB base class offsets on each struct for later flattening.
    """
    matched = size_ok = size_mismatch = supplemented = 0

    for pdb_name, pdb_info in pdb_types.items():
        short = pdb_name.split('::')[-1]
        clang_key = pdb_name if pdb_name in structs else short if short in structs else None
        if clang_key is None:
            continue

        matched += 1
        clang = structs[clang_key]
        pdb_sz = pdb_info['size']
        pdb_fields = pdb_info['fields']    # [(name, offset)] — own members only
        pdb_bases  = pdb_info['bases']     # [(base_name, base_offset)]

        # Always store PDB base offsets and vfuncs — used by flattening and vtable building
        clang['pdb_bases'] = pdb_bases
        clang['vfuncs'] = pdb_info.get('vfuncs', [])

        if clang['size'] == 1 and pdb_sz > 1:
            # libclang got an incomplete layout; use PDB size + own fields
            clang['size'] = pdb_sz
            clang['fields'] = _pdb_fields_to_clang(pdb_fields, pdb_sz)
            supplemented += 1

        elif clang['size'] == pdb_sz and pdb_sz > 1:
            size_ok += 1
            # Sizes match — use PDB field names where libclang has the same offset
            clang_field_map = {f['offset']: f for f in clang['fields']}
            for pdb_fname, pdb_foff in pdb_fields:
                if pdb_foff in clang_field_map:
                    clang_field_map[pdb_foff]['name'] = pdb_fname
        else:
            size_mismatch += 1

    print('PDB cross-reference: {} matched, {} size-ok, {} supplemented, {} mismatched'.format(
        matched, size_ok, supplemented, size_mismatch))


def _pdb_fields_to_clang(pdb_fields, total_size):
    """Convert [(name, offset)] from PDB into our field format, computing sizes from gaps."""
    if not pdb_fields:
        return []
    sorted_fields = sorted(pdb_fields, key=lambda x: x[1])
    result = []
    for i, (name, off) in enumerate(sorted_fields):
        if i + 1 < len(sorted_fields):
            next_off = sorted_fields[i + 1][1]
        else:
            next_off = total_size
        fsize = next_off - off
        if fsize <= 0:
            continue
        result.append({
            'name': name,
            'type': 'bytes:{}'.format(fsize),
            'offset': off,
            'size': fsize,
        })
    return result


def _build_vtable_structs(structs):
    """
    Build vtable type descriptors for each virtual class by collecting intro
    virtual methods (LF_ONEMETHOD mprop 4/5) from the class and its primary
    base chain.  Returns a dict: full_name → vtable descriptor.
    """
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    memo = {}  # full_name → {vbaseoff: method_name}

    def get_slots(full_name, depth=0):
        if depth > 20:
            return {}
        if full_name in memo:
            return memo[full_name]
        st = by_name.get(full_name)
        if not st:
            memo[full_name] = {}
            return {}
        memo[full_name] = {}  # cycle guard

        slots = {}

        # Inherit from primary base (first base placed at offset 0)
        pdb_bases = st.get('pdb_bases', [])
        if pdb_bases:
            primary_name, primary_off = pdb_bases[0]
            if primary_off == 0:
                bst = by_name.get(primary_name) or by_name.get(primary_name.split('::')[-1])
                if bst:
                    slots.update(get_slots(bst['full_name'], depth + 1))
        else:
            for base_ref in st.get('bases', []):
                bst = by_name.get(base_ref) or by_name.get(base_ref.split('::')[-1])
                if bst:
                    slots.update(get_slots(bst['full_name'], depth + 1))
                break

        # Own intro virtual methods override inherited ones at same offset
        for mname, vbaseoff in st.get('vfuncs', []):
            if vbaseoff >= 0 and mname:
                slots[vbaseoff] = mname

        memo[full_name] = slots
        return slots

    vtable_structs = {}
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        slots = get_slots(st['full_name'])
        if not slots:
            continue
        sorted_slots = sorted(slots.items())  # [(vbaseoff, name)]
        vtbl_size = sorted_slots[-1][0] + 8
        vname = st['name'] + '_vtbl'
        vtable_structs[st['full_name']] = {
            'name': vname,
            'category': st['category'],
            'slots': sorted_slots,
            'size': vtbl_size,
        }

    print('Built {} vtable structs'.format(len(vtable_structs)))
    return vtable_structs


def _inject_vtable_fields(structs, vtable_structs):
    """
    For every virtual struct that has no field at offset 0, prepend a __vftable
    pointer field with type 'vtblptr:Name_vtbl' (or plain 'ptr' if no vtable data).
    Must run BEFORE _flatten_structs so vtable pointers propagate through hierarchy.
    """
    count = 0
    for st in structs.values():
        if not st.get('has_vtable') and not st.get('vfuncs'):
            continue
        if st['size'] < 8:
            continue
        if any(f['offset'] == 0 for f in st['fields']):
            continue
        vt = vtable_structs.get(st['full_name'])
        vtbl_type = ('vtblptr:' + vt['name']) if vt else 'ptr'
        st['fields'].insert(0, {
            'name': '__vftable',
            'type': vtbl_type,
            'offset': 0,
            'size': 8,
        })
        count += 1
    print('Injected vtable pointer fields into {} structs'.format(count))


def _flatten_structs(structs):
    """
    In-place: for every struct, expand base class fields into the derived struct
    so the final field list covers the entire layout at absolute byte offsets.

    Uses pdb_bases ([(base_name, base_offset)]) when available for accurate
    base placement; falls back to assuming first base starts at offset 0.
    """
    # Build name → struct entry lookup
    by_name = {}
    for st in structs.values():
        by_name[st['full_name']] = st
        by_name[st['name']] = st

    memo = {}   # full_name → flattened fields list (cached)

    def get_flat(full_name, depth=0):
        if depth > 20:
            return []
        if full_name in memo:
            return memo[full_name]

        st = by_name.get(full_name)
        if not st:
            memo[full_name] = []
            return []

        # Prevent cycles
        memo[full_name] = []

        combined = {}  # offset → field dict  (own fields take priority)

        # --- Determine base class placements ---
        pdb_bases = st.get('pdb_bases', [])  # [(base_name, base_offset)] from PDB

        if pdb_bases:
            # PDB gave us exact offsets for each base
            for base_name, base_off in pdb_bases:
                base_st = by_name.get(base_name) or by_name.get(base_name.split('::')[-1])
                if not base_st:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    abs_off = base_off + f['offset']
                    if abs_off not in combined:
                        combined[abs_off] = dict(f, offset=abs_off)
        else:
            # No PDB base info — assume single base at offset 0
            for base_ref in st.get('bases', []):
                base_st = by_name.get(base_ref) or by_name.get(base_ref.split('::')[-1])
                if not base_st or base_st['size'] <= 1:
                    continue
                for f in get_flat(base_st['full_name'], depth + 1):
                    if f['offset'] not in combined:
                        combined[f['offset']] = f
                break  # only first base without offset info

        # --- Own fields (override base at same offset) ---
        for f in st['fields']:
            combined[f['offset']] = f

        flat = sorted(combined.values(), key=lambda f: f['offset'])
        memo[full_name] = flat
        return flat

    for st in structs.values():
        st['fields'] = get_flat(st['full_name'])

    # Count how many structs gained fields from flattening
    gained = sum(1 for st in structs.values() if len(st['fields']) > 0)
    print('Flattening: {} structs have field data after inheritance expansion'.format(gained))


def main():
    if not os.path.isfile(SKYRIM_H):
        print('ERROR: Could not find Skyrim.h at', SKYRIM_H)
        sys.exit(1)

    print('Parsing CommonLibSSE headers...')
    idx = ci.Index.create()
    tu = idx.parse(SKYRIM_H, args=PARSE_ARGS, options=PARSE_OPTIONS)

    errors = [d for d in tu.diagnostics if d.severity >= ci.Diagnostic.Error]
    if errors:
        print('Parse errors ({} total, showing first 5):'.format(len(errors)))
        for e in errors[:5]:
            print(' ', e.spelling)

    print('Collecting types...')
    enums, structs = _collect_types(tu)
    print('Found {} enums, {} structs/classes'.format(len(enums), len(structs)))

    # Cross-reference with PDB type info
    if os.path.isfile(PDB_SE_PATH):
        print('Loading PDB type info from {}...'.format(os.path.basename(PDB_SE_PATH)))
        pdb_types = load_pdb_types(PDB_SE_PATH)
        print('Found {} RE:: types in PDB'.format(len(pdb_types)))
        _merge_pdb_into_structs(structs, pdb_types)
    else:
        print('PDB not found at {}, skipping cross-reference'.format(PDB_SE_PATH))

    vtable_structs = _build_vtable_structs(structs)
    _inject_vtable_fields(structs, vtable_structs)
    _flatten_structs(structs)

    print('Generating Ghidra script...')
    n_enums, n_structs = generate_script(enums, structs, vtable_structs, OUTPUT_SCRIPT)
    print('Output: {} ({} enums, {} structs)'.format(OUTPUT_SCRIPT, n_enums, n_structs))


if __name__ == '__main__':
    main()
