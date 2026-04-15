"""
Extract function signatures from CommonLibSSE source code and generate
a Ghidra import script (CommonLibGhidra.py) with full signature coverage.

Handles three patterns:
1. REL::Relocation<ret(params)> name { RELOCATION_ID(se, ae) }  -- explicit signature
2. using func_t = decltype(&Class::Method); REL::Relocation<func_t> func { RELOCATION_ID(se, ae) }
   -- signature comes from the enclosing function declaration
3. using func_t = RetType(Params); -- inline typedef with RELOCATION_ID

Supports RELOCATION_ID(se, ae), REL::ID(id), REL::RelocationID(se, ae),
Offset::Class::Method references, and bare integer IDs.

Usage:
    python extract_signatures.py
    (run from the MainMenuVideo project root)
"""

import os
import re
import json
import struct
import math
import ctypes


class AddressLibrary:
    def __init__(self):
        self.se_db = {}
        self.ae_db = {}

    def load_bin(self, file_path):
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            f.read(4)  # fmt
            f.read(16)  # version
            name_len = struct.unpack('<I', f.read(4))[0]
            f.read(name_len)
            ptr_size = struct.unpack('<I', f.read(4))[0]
            addr_count = struct.unpack('<I', f.read(4))[0]
            pvid = 0; poffset = 0
            for _ in range(addr_count):
                type_byte = struct.unpack('<B', f.read(1))[0]
                low = type_byte & 0xF; high = type_byte >> 4
                if low == 0: id_val = struct.unpack('<Q', f.read(8))[0]
                elif low == 1: id_val = pvid + 1
                elif low == 2: id_val = pvid + struct.unpack('<B', f.read(1))[0]
                elif low == 3: id_val = pvid - struct.unpack('<B', f.read(1))[0]
                elif low == 4: id_val = pvid + struct.unpack('<H', f.read(2))[0]
                elif low == 5: id_val = pvid - struct.unpack('<H', f.read(2))[0]
                elif low == 6: id_val = struct.unpack('<H', f.read(2))[0]
                elif low == 7: id_val = struct.unpack('<I', f.read(4))[0]
                tpoffset = (poffset // ptr_size) if (high & 8) != 0 else poffset
                h_type = high & 7
                if h_type == 0: off_val = struct.unpack('<Q', f.read(8))[0]
                elif h_type == 1: off_val = tpoffset + 1
                elif h_type == 2: off_val = tpoffset + struct.unpack('<B', f.read(1))[0]
                elif h_type == 3: off_val = tpoffset - struct.unpack('<B', f.read(1))[0]
                elif h_type == 4: off_val = tpoffset + struct.unpack('<H', f.read(2))[0]
                elif h_type == 5: off_val = tpoffset - struct.unpack('<H', f.read(2))[0]
                elif h_type == 6: off_val = struct.unpack('<H', f.read(2))[0]
                elif h_type == 7: off_val = struct.unpack('<I', f.read(4))[0]
                if (high & 8) != 0: off_val *= ptr_size
                db[id_val] = off_val; pvid = id_val; poffset = off_val
        return db

    def load_all(self, base_path):
        self.se_db = self.load_bin(os.path.join(base_path, 'version-1-5-97-0.bin'))
        self.ae_db = self.load_bin(os.path.join(base_path, 'versionlib-1-6-1170-0.bin'))


def find_enclosing_function_sig(content, pos):
    """Given a position in the file (where decltype/RELOCATION_ID is),
    walk backwards to find the enclosing function declaration.
    Returns (ret_type, func_name, params, class_name, is_const) or None."""
    brace_depth = 0
    i = pos
    func_body_start = None
    while i >= 0:
        if content[i] == '}':
            brace_depth += 1
        elif content[i] == '{':
            if brace_depth == 0:
                # Check if this brace belongs to a control flow statement
                pre_brace = content[:i].rstrip()
                is_control_flow = False
                if re.search(r'\b(?:else|do|try)\s*$', pre_brace):
                    is_control_flow = True
                elif pre_brace.endswith(')'):
                    pd = 0; mp = None
                    for q in range(len(pre_brace) - 1, -1, -1):
                        if pre_brace[q] == ')': pd += 1
                        elif pre_brace[q] == '(':
                            pd -= 1
                            if pd == 0: mp = q; break
                    if mp is not None:
                        before_paren = pre_brace[:mp].rstrip()
                        if re.search(r'\b(?:if|else\s+if|for|while|switch)\s*(?:SKYRIM_REL_CONSTEXPR|constexpr)?\s*$', before_paren):
                            is_control_flow = True
                if is_control_flow:
                    i -= 1
                    continue
                func_body_start = i
                break
            brace_depth -= 1
        i -= 1

    if func_body_start is None:
        return None

    # Isolate just the function declaration
    pre_full = content[:func_body_start]
    decl_start = 0
    j = len(pre_full) - 1
    paren_d = 0; angle_d = 0
    while j >= 0:
        ch = pre_full[j]
        if ch == ')': paren_d += 1
        elif ch == '(': paren_d -= 1
        elif ch == '>':
            # Don't count '->' as template bracket
            if j > 0 and pre_full[j - 1] == '-':
                pass
            else:
                angle_d += 1
        elif ch == '<': angle_d -= 1
        if paren_d == 0 and angle_d <= 0:
            if ch in (';', '}', '{'):
                decl_start = j + 1
                break
        j -= 1

    decl_text = pre_full[decl_start:].strip()
    if not decl_text:
        return None

    last_paren = decl_text.rfind(')')
    if last_paren == -1:
        return None

    paren_depth = 0; open_paren = None
    for k in range(last_paren, -1, -1):
        if decl_text[k] == ')': paren_depth += 1
        elif decl_text[k] == '(':
            paren_depth -= 1
            if paren_depth == 0: open_paren = k; break

    if open_paren is None:
        return None

    params = decl_text[open_paren + 1:last_paren].strip()
    trailing = decl_text[last_paren + 1:].strip()
    before_params = decl_text[:open_paren].rstrip()

    name_match = re.search(r'((?:\w+::)*~?\w+)\s*$', before_params)
    if not name_match:
        return None

    full_name = name_match.group(1)
    ret_and_quals = before_params[:name_match.start()].strip()

    if '::' in full_name:
        parts = full_name.rsplit('::', 1)
        class_name = parts[0]
        func_name = parts[1]
    else:
        class_name = None
        func_name = full_name

    ret = ret_and_quals
    # Strip comments and preprocessor directives
    ret = re.sub(r'//[^\n]*', '', ret)
    ret = re.sub(r'#\w+[^\n]*', '', ret)
    ret = re.sub(r'^.*\b(?:public|private|protected)\s*:\s*', '', ret)
    ret = re.sub(r'\[\[.*?\]\]', '', ret)
    # Strip template declarations (template <class... Args>)
    ret = re.sub(r'\btemplate\s*<[^>]*>', '', ret)
    for qual in ['static', 'inline', 'virtual', 'constexpr', 'explicit',
                 'SKYRIM_REL_VR_VIRTUAL', 'friend']:
        ret = re.sub(r'\b' + qual + r'\b', '', ret)
    ret = ' '.join(ret.split())

    if not ret:
        if func_name.startswith('~') or func_name == class_name:
            ret = 'void'
        else:
            return None

    # Resolve trailing return type: auto Func(params) -> RetType
    if ret == 'auto' and trailing:
        trail_ret = re.match(r'->\s*([\w:<>*& ]+)', trailing)
        if trail_ret:
            ret = trail_ret.group(1).strip()

    is_const = bool(re.search(r'\bconst\b', trailing.split('override')[0])) if trailing else False
    return ret, func_name, params, class_name, is_const


def parse_file_for_signatures(file_path, addr_lib):
    """Parse a C++ file and extract function signatures with relocation IDs."""
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return results

    # Pattern 1: REL::Relocation<ret(params)> name { RELOCATION_ID(se, ae) }
    for m in re.finditer(
        r'REL::Relocation<([\w:<>*& ]+?)\((.*?)\)>\s+(\w+)\s*\{\s*'
        r'(?:RELOCATION_ID|REL::RelocationID)\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)',
        content
    ):
        ret, params, name, se_id_s, ae_id_s = m.groups()
        se_id = int(se_id_s); ae_id = int(ae_id_s)
        results.append({
            'name': name, 'class': None,
            'ret': ret.strip(), 'params': params.strip(),
            'se_id': se_id, 'ae_id': ae_id,
            'se_off': addr_lib.se_db.get(se_id),
            'ae_off': addr_lib.ae_db.get(ae_id),
            'pattern': 'explicit',
        })

    # Pattern 2: using func_t = decltype(&Class::Method);
    for m in re.finditer(
        r'using\s+func_t\s*=\s*decltype\s*\(\s*&([\w:]+)\s*\)\s*;'
        r'[^}]*?'
        r'(?:'
            r'(?:RELOCATION_ID|REL::RelocationID)\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)'
            r'|'
            r'REL::ID\s*\(\s*(\d+)\s*\)'
            r'|'
            r'Offset::(\w+(?:::\w+)*)\s*'
        r')',
        content, re.DOTALL
    ):
        decltype_ref = m.group(1)
        se_id = None; ae_id = None

        if m.group(2) is not None:
            se_id = int(m.group(2)); ae_id = int(m.group(3))
        elif m.group(4) is not None:
            se_id = int(m.group(4))
        elif m.group(5) is not None:
            pass  # Offset:: reference - resolved later

        if '::' in decltype_ref:
            parts = decltype_ref.rsplit('::', 1)
            class_name = parts[0]; method_name = parts[1]
        else:
            class_name = None; method_name = decltype_ref

        sig_info = find_enclosing_function_sig(content, m.start())
        if sig_info:
            ret, func_name, params, enc_class, is_const = sig_info
            # Use enclosing function's name/class if decltype references a different function
            # (e.g. VPrint uses decltype(&Print), or source bug uses wrong decltype ref)
            actual_name = method_name
            actual_class = class_name
            if enc_class and func_name:
                enc_key = enc_class + '::' + func_name
                decl_key = (class_name + '::' + method_name) if class_name else method_name
                if enc_key != decl_key:
                    actual_name = func_name
                    actual_class = enc_class
            results.append({
                'name': actual_name, 'class': actual_class,
                'ret': ret, 'params': params,
                'se_id': se_id, 'ae_id': ae_id,
                'se_off': addr_lib.se_db.get(se_id) if se_id else None,
                'ae_off': addr_lib.ae_db.get(ae_id) if ae_id else None,
                'pattern': 'decltype', 'is_const': is_const,
            })
        else:
            results.append({
                'name': method_name, 'class': class_name,
                'ret': '', 'params': '',
                'se_id': se_id, 'ae_id': ae_id,
                'se_off': addr_lib.se_db.get(se_id) if se_id else None,
                'ae_off': addr_lib.ae_db.get(ae_id) if ae_id else None,
                'pattern': 'decltype_no_sig',
            })

    # Pattern 3: using func_t = RetType(Params);
    for m in re.finditer(
        r'using\s+func_t\s*=\s*([\w:<>*& ]+?)\s*\(([^)]*)\)\s*;'
        r'[^}]*?'
        r'(?:'
            r'(?:RELOCATION_ID|REL::RelocationID)\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)'
            r'|'
            r'REL::ID\s*\(\s*(\d+)\s*\)'
        r')',
        content, re.DOTALL
    ):
        ret = m.group(1).strip(); params = m.group(2).strip()
        if 'decltype' in ret:
            continue

        se_id = None; ae_id = None
        if m.group(3) is not None:
            se_id = int(m.group(3)); ae_id = int(m.group(4))
        elif m.group(5) is not None:
            se_id = int(m.group(5))
        else:
            continue

        sig_info = find_enclosing_function_sig(content, m.start())
        func_name = 'func'; class_name = None
        if sig_info:
            enc_ret, func_name, enc_params, class_name, _ = sig_info
            # Prefer the enclosing function's signature over the raw typedef
            # The typedef includes ABI-level details (explicit this ptr, hidden output params)
            # while the enclosing function has the clean C++ signature
            if enc_ret:
                ret = enc_ret
                params = enc_params
        else:
            # No enclosing function found - strip explicit this pointer from typedef params
            if class_name and params:
                param_list = [p.strip() for p in params.split(',')]
                if param_list and re.match(r'\w[\w:]*\s*\*\s*$', param_list[0]):
                    param_list = param_list[1:]
                    params = ', '.join(param_list)

        results.append({
            'name': func_name, 'class': class_name,
            'ret': ret, 'params': params,
            'se_id': se_id, 'ae_id': ae_id,
            'se_off': addr_lib.se_db.get(se_id) if se_id else None,
            'ae_off': addr_lib.ae_db.get(ae_id) if ae_id else None,
            'pattern': 'typedef',
        })

    return results


def parse_offsets_h(file_path):
    """Parse Offsets.h to build SE/AE ID mappings for Offset::Class::Method references."""
    if not os.path.exists(file_path):
        return {}, {}

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split into AE and SE sections
    ae_section = content[:content.index('#else')] if '#else' in content else ''
    se_section = content[content.index('#else'):] if '#else' in content else content

    def parse_section(text):
        db = {}
        current_ns = []
        for line in text.split('\n'):
            ns_match = re.match(r'\s*namespace\s+(\w+)', line)
            if ns_match:
                current_ns.append(ns_match.group(1))
            elif '}' in line and current_ns:
                current_ns.pop()
            id_match = re.search(r'REL::ID\s+(\w+)\s*\(\s*static_cast<std::uint64_t>\((\d+)\)', line)
            if id_match and current_ns:
                name = '::'.join(current_ns) + '::' + id_match.group(1)
                # Strip RE::Offset:: prefix to get canonical name
                for prefix in ['RE::Offset::', 'Offset::']:
                    if name.startswith(prefix):
                        name = name[len(prefix):]
                        break
                db[name] = int(id_match.group(2))
        return db

    ae_ids = parse_section(ae_section)
    se_ids = parse_section(se_section)
    return se_ids, ae_ids


def parse_offsets_rtti_vtable(file_path, addr_lib):
    """Parse Offsets_RTTI.h and Offsets_VTABLE.h for RTTI/VTABLE offsets.
    Handles #ifdef SKYRIM_SUPPORT_AE / #else split with different ID formats."""
    offsets = {}
    if not os.path.exists(file_path):
        return offsets
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split into AE and SE sections
    if '#else' in content:
        else_pos = content.index('#else')
        ae_section = content[:else_pos]
        se_section = content[else_pos:]
    else:
        ae_section = ''
        se_section = content

    def extract_ids(text):
        """Extract name->id mappings from a section."""
        db = {}
        # Pattern 1: REL::ID Name(static_cast<std::uint64_t>(ID));  (SE format)
        for m in re.finditer(r'REL::ID\s+((?:RTTI|VTABLE)_\w+)\s*\(\s*static_cast<std::uint64_t>\((\d+)\)\s*\)', text):
            db[m.group(1)] = int(m.group(2))
        # Pattern 2: REL::ID Name{ ID };  (AE RTTI format, bare int)
        for m in re.finditer(r'REL::ID\s+((?:RTTI|VTABLE)_\w+)\s*\{\s*(\d+)\s*\}', text):
            db[m.group(1)] = int(m.group(2))
        # Pattern 3: std::array<REL::ID, N> VTABLE_Name{ REL::ID(ID) };  (VTABLE format)
        for m in re.finditer(r'std::array<REL::ID,\s*\d+>\s+(VTABLE_\w+)\s*\{\s*REL::ID\((\d+)\)\s*\}', text):
            db[m.group(1)] = int(m.group(2))
        return db

    ae_ids = extract_ids(ae_section)
    se_ids = extract_ids(se_section)

    # Merge into offsets dict with SE and AE offsets
    all_names = set(list(ae_ids.keys()) + list(se_ids.keys()))
    for name in all_names:
        se_id = se_ids.get(name)
        ae_id = ae_ids.get(name)
        offsets[name] = {
            'se': addr_lib.se_db.get(se_id) if se_id else None,
            'ae': addr_lib.ae_db.get(ae_id) if ae_id else None,
        }

    return offsets


def scan_static_functions(commonlib_dir):
    """Scan header files to find which Class::Method pairs are declared as static."""
    static_methods = set()
    include_dir = os.path.join(commonlib_dir, 'include')
    if not os.path.exists(include_dir):
        return static_methods

    for root, _, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith('.h'):
                continue
            try:
                with open(os.path.join(root, fname), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                continue

            class_stack = []
            depth = 0
            i = 0
            while i < len(content):
                c = content[i]
                if c == '{': depth += 1
                elif c == '}':
                    depth -= 1
                    while class_stack and class_stack[-1][1] >= depth:
                        class_stack.pop()
                elif c == '/' and i + 1 < len(content) and content[i + 1] == '/':
                    nl = content.find('\n', i)
                    i = nl if nl != -1 else len(content)
                elif c == '/' and i + 1 < len(content) and content[i + 1] == '*':
                    end = content.find('*/', i + 2)
                    i = end + 1 if end != -1 else len(content)
                elif c in ('c', 's'):
                    m = re.match(r'(?:class|struct)\s+(\w+)', content[i:])
                    if m:
                        rest = content[i + m.end():].lstrip()
                        if rest and rest[0] in ('{', ':'):
                            class_stack.append((m.group(1), depth))
                        i += m.end() - 1
                    if class_stack:
                        sm = re.match(
                            r'static\s+(?!constexpr\b|inline\b|assert\b|cast\b|const\b)[\w:<>*& ]+?\s+(\w+)\s*\(',
                            content[i:]
                        )
                        if sm:
                            static_methods.add(f"{class_stack[-1][0]}::{sm.group(1)}")
                i += 1

    return static_methods


def parse_header_classes(file_path):
    """Parse a header file for class data: virtual functions, members, size, RTTI, VTABLE."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return {}

    classes = {}
    class_pattern = re.compile(r'(class|struct)\s+(\w+)(?:\s*:\s*([^\{]+))?\s*\{')
    pos = 0
    while True:
        match = class_pattern.search(content, pos)
        if not match: break
        ctype, cname, parents_raw = match.groups()
        start_brace = match.end() - 1

        # Find matching brace
        depth = 0
        end_brace = -1
        for idx in range(start_brace, len(content)):
            if content[idx] == '{': depth += 1
            elif content[idx] == '}':
                depth -= 1
                if depth == 0: end_brace = idx; break
        if end_brace == -1:
            pos = match.end(); continue

        body = content[start_brace + 1:end_brace]
        cls_data = {'name': cname, 'functions': [], 'members': [], 'size': None}

        # Virtual functions with index comments
        for vf in re.finditer(
            r'(?:virtual\s+)?([\w:<>*& ]+?)\s*(~?\w+)\s*\((.*?)\)(?:[^;]*?);\s*//\s*([0-9A-Fa-f]+)',
            body
        ):
            ret, fname, params, index = vf.groups()
            cls_data['functions'].append({
                'name': fname, 'index': int(index, 16),
                'ret': ret.strip(), 'params': params.strip()
            })

        # Members with offset comments
        for mm in re.finditer(
            r'^\s*(?!virtual|static|using|typedef|#|public|protected|private|return)'
            r'([\w:<>*& ]+)\s+(\w+)\s*;\s*//\s*([0-9A-Fa-f]+)',
            body, re.MULTILINE
        ):
            mtype, mname, moff = mm.groups()
            if '(' not in mtype.strip() and mname not in ['override', 'const']:
                cls_data['members'].append({
                    'name': mname, 'type': mtype.strip(), 'offset': int(moff, 16)
                })

        # Class size
        size_m = re.search(rf'static_assert\(sizeof\({cname}\) == (0x[0-9A-Fa-f]+)\);', content)
        if size_m:
            cls_data['size'] = int(size_m.group(1), 16)

        # RTTI / VTABLE
        rtti_m = re.search(r'RTTI = (RTTI_\w+);', body)
        if rtti_m: cls_data['rtti_ref'] = rtti_m.group(1)
        vtable_m = re.search(r'VTABLE = (VTABLE_\w+);', body)
        if vtable_m: cls_data['vtable_ref'] = vtable_m.group(1)

        classes[cname] = cls_data
        pos = match.end()

    return classes


def _undecorate(name):
    """Demangle an MSVC-mangled symbol name using dbghelp.UnDecorateSymbolName."""
    try:
        buf = ctypes.create_string_buffer(512)
        if ctypes.windll.dbghelp.UnDecorateSymbolName(name.encode(), buf, 512, 0x1000):
            return buf.value.decode('ascii', errors='replace')
    except Exception:
        pass
    return name


def load_se_pdb_names(file_path):
    """Parse a PDB (MSF7) file and return dict of rva -> name for all public function symbols."""
    if not os.path.exists(file_path):
        return {}

    with open(file_path, 'rb') as f:
        data = f.read()

    if not data.startswith(b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'):
        return {}

    # MSF superblock
    page_size = struct.unpack_from('<I', data, 32)[0]
    dir_size  = struct.unpack_from('<I', data, 44)[0]
    blk_map   = struct.unpack_from('<I', data, 52)[0]

    # Stream directory
    n_dir_pages = math.ceil(dir_size / page_size)
    dir_page_list = struct.unpack_from(f'<{n_dir_pages}I', data, blk_map * page_size)
    dir_data = b''.join(data[p * page_size:(p + 1) * page_size] for p in dir_page_list)[:dir_size]

    n_streams = struct.unpack_from('<I', dir_data, 0)[0]
    sizes = struct.unpack_from(f'<{n_streams}I', dir_data, 4)

    o = 4 + n_streams * 4
    stream_pages = []
    for sz in sizes:
        if sz == 0 or sz == 0xFFFFFFFF:
            stream_pages.append([])
        else:
            np = math.ceil(sz / page_size)
            stream_pages.append(list(struct.unpack_from(f'<{np}I', dir_data, o)))
            o += np * 4

    def read_stream(idx):
        if idx >= n_streams or sizes[idx] in (0, 0xFFFFFFFF):
            return b''
        return b''.join(data[p * page_size:(p + 1) * page_size] for p in stream_pages[idx])[:sizes[idx]]

    # DBI stream (stream 3)
    dbi = read_stream(3)
    if len(dbi) < 64:
        return {}

    (_, _, _,
     _, _,
     _, _,
     sym_rec_idx, _,
     mod_sz, sec_contrib_sz, sec_map_sz, src_sz, type_srv_sz, _,
     opt_dbg_sz, ec_sz,
     _, _, _) = struct.unpack_from('<iIIHHHHHHiiiiiIiiHHI', dbi)

    # Section headers stream index (offset 10 within optional debug header)
    opt_off = 64 + mod_sz + sec_contrib_sz + sec_map_sz + src_sz + type_srv_sz + ec_sz
    sec_hdr_idx = struct.unpack_from('<H', dbi, opt_off + 10)[0] if opt_dbg_sz >= 12 else 0xFFFF

    # Section virtual addresses (needed to convert seg:off -> RVA)
    sections = []
    if sec_hdr_idx != 0xFFFF:
        sec_data = read_stream(sec_hdr_idx)
        sections = [struct.unpack_from('<I', sec_data, i * 40 + 12)[0] for i in range(len(sec_data) // 40)]

    # Parse symbol records stream for S_PUB32 (public function) records
    sym_data = read_stream(sym_rec_idx)
    S_PUB32 = 0x110E
    result = {}
    o = 0
    while o + 4 <= len(sym_data):
        rec_len, rec_typ = struct.unpack_from('<HH', sym_data, o)
        rec_end = o + 2 + rec_len
        if rec_len < 2 or rec_end > len(sym_data):
            break
        if rec_typ == S_PUB32 and rec_end >= o + 14:
            pub_flags, off, seg = struct.unpack_from('<IIH', sym_data, o + 4)
            if pub_flags & 0x2 and 1 <= seg <= len(sections):
                nul = sym_data.find(b'\x00', o + 14, rec_end)
                if nul != -1:
                    name = sym_data[o + 14:nul].decode('ascii', errors='replace')
                    if name.startswith('?'):
                        name = _undecorate(name)
                    # Skip pure auto-generated names with no semantic content
                    if re.match(r'^FUN_[0-9A-Fa-f]+$', name):
                        o = rec_end
                        continue
                    # Strip embedded full-address suffix (e.g. WriteToSaveGame_1404D62A0)
                    name = re.sub(r'_14[0-9A-Fa-f]{6,8}$', '', name)
                    # Replace __ namespace separator with ::, then collapse any over-long runs
                    name = re.sub(r':{3,}', '::', name.replace('__', '::'))
                    result[sections[seg - 1] + off] = name
        o = rec_end

    return result


def load_ae_rename_db(file_path, ae_db):
    """Load skyrimae.rename: lines of '<ae_id> <name>', skip version line. Trailing * and _ are stripped from names."""
    result = {}  # ae_offset -> name
    if not os.path.exists(file_path):
        return result
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    for line in lines[1:]:  # skip version line
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        if len(parts) != 2:
            continue
        name = parts[1].rstrip('*').rstrip('_')
        try:
            ae_id = int(parts[0])
        except ValueError:
            continue
        off = ae_db.get(ae_id)
        if off:
            result[off] = name
    return result


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    commonlib_dir = os.path.join(base_dir, 'extern', 'CommonLibSSE')
    assert os.path.exists(commonlib_dir), f"CommonLibSSE not found at {commonlib_dir}"

    addr_lib_dir = os.path.join(base_dir, 'addresslibrary')
    assert os.path.exists(addr_lib_dir), f"Address library not found at {addr_lib_dir}"

    print(f"CommonLibSSE: {commonlib_dir}")
    print(f"AddressLibrary: {addr_lib_dir}")

    addr_lib = AddressLibrary()
    addr_lib.load_all(addr_lib_dir)
    print(f"SE entries: {len(addr_lib.se_db)}, AE entries: {len(addr_lib.ae_db)}")

    # Parse Offsets.h for SE/AE ID mappings
    include_root = os.path.join(commonlib_dir, 'include')
    se_offset_ids, ae_offset_ids = parse_offsets_h(
        os.path.join(include_root, 'RE', 'Offsets.h')
    )
    print(f"Offset IDs: {len(se_offset_ids)} SE, {len(ae_offset_ids)} AE")

    # Parse RTTI/VTABLE offsets
    rtti_offsets = parse_offsets_rtti_vtable(
        os.path.join(include_root, 'RE', 'Offsets_RTTI.h'), addr_lib
    )
    vtable_offsets = parse_offsets_rtti_vtable(
        os.path.join(include_root, 'RE', 'Offsets_VTABLE.h'), addr_lib
    )
    print(f"RTTI offsets: {len(rtti_offsets)}, VTABLE offsets: {len(vtable_offsets)}")

    # Collect all source files
    all_files = []
    for folder in ['include', 'src']:
        folder_path = os.path.join(commonlib_dir, folder)
        if not os.path.exists(folder_path): continue
        for root, _, files in os.walk(folder_path):
            for f in files:
                if f.endswith('.h') or f.endswith('.cpp'):
                    all_files.append(os.path.join(root, f))
    print(f"Found {len(all_files)} source files")

    # Extract signatures
    all_sigs = []
    for i, fp in enumerate(all_files):
        sigs = parse_file_for_signatures(fp, addr_lib)
        all_sigs.extend(sigs)
        if (i + 1) % 100 == 0:
            print(f"  Parsed {i+1}/{len(all_files)} files, {len(all_sigs)} signatures so far")
    print(f"\nExtracted {len(all_sigs)} total signatures")

    # Resolve Offset:: references using Offsets.h ID mappings
    resolved_count = 0
    for s in all_sigs:
        if s.get('se_off') or s.get('ae_off'):
            continue  # Already resolved
        # Build the Offset:: lookup key from class::name
        offset_key = s['class'] + '::' + s['name'] if s.get('class') else s['name']
        se_id = se_offset_ids.get(offset_key)
        ae_id = ae_offset_ids.get(offset_key)
        if se_id:
            s['se_id'] = se_id
            s['se_off'] = addr_lib.se_db.get(se_id)
        if ae_id:
            s['ae_id'] = ae_id
            s['ae_off'] = addr_lib.ae_db.get(ae_id)
        if se_id or ae_id:
            resolved_count += 1
    print(f"Resolved {resolved_count} Offset:: references")

    # Build lookup tables
    sig_by_se_off = {}
    sig_by_ae_off = {}
    for s in all_sigs:
        if s.get('se_off') and (s['se_off'] not in sig_by_se_off or not sig_by_se_off[s['se_off']].get('ret')):
            sig_by_se_off[s['se_off']] = s
        if s.get('ae_off') and (s['ae_off'] not in sig_by_ae_off or not sig_by_ae_off[s['ae_off']].get('ret')):
            sig_by_ae_off[s['ae_off']] = s

    sig_by_name = {}
    for s in all_sigs:
        if s['ret']:
            key = s['class'] + '::' + s['name'] if s['class'] else s['name']
            if key not in sig_by_name:
                sig_by_name[key] = s

    print(f"Lookup: {len(sig_by_se_off)} by SE offset, {len(sig_by_ae_off)} by AE offset, {len(sig_by_name)} by name")

    # Scan for static methods
    print("Scanning for static function declarations...")
    static_methods = scan_static_functions(commonlib_dir)
    print(f"Found {len(static_methods)} static member functions")

    # Parse all headers for class data (virtual funcs, members, RTTI, VTABLE)
    print("Parsing header class data...")
    all_classes = {}
    for root, _, files in os.walk(os.path.join(include_root, 'RE')):
        for f in files:
            if f.endswith('.h') and 'Offsets' not in f:
                try:
                    classes = parse_header_classes(os.path.join(root, f))
                    all_classes.update(classes)
                except:
                    pass
    print(f"Parsed {len(all_classes)} classes")

    # Clean up extracted signature data
    def clean_sig_part(s):
        """Strip comments, preprocessor, and noise from a signature component."""
        s = re.sub(r'//[^\n]*', '', s)
        s = re.sub(r'#\w+[^\n]*', '', s)
        s = re.sub(r'\bnamespace\s+\w+\s*\{', '', s)
        s = re.sub(r'\b(?:public|private|protected)\s*:\s*', '', s)
        s = ' '.join(s.split())
        return s.strip()

    for s in all_sigs:
        if s.get('ret'):
            s['ret'] = clean_sig_part(s['ret'])
        if s.get('params'):
            s['params'] = clean_sig_part(s['params'])

    # Build SYMBOLS array
    # Each symbol: {n: name, s: se_offset, a: ae_offset, t: 'func'|'label', sig: '...'}
    symbols = []
    seen_offsets_se = set()
    seen_offsets_ae = set()

    # From extracted signatures (functions with RELOCATION_ID)
    for s in all_sigs:
        name = s['class'] + '::' + s['name'] if s['class'] else s['name']
        se_off = s.get('se_off')
        ae_off = s.get('ae_off')

        if se_off and se_off in seen_offsets_se:
            continue
        if se_off: seen_offsets_se.add(se_off)
        if ae_off: seen_offsets_ae.add(ae_off)

        sig_str = ''
        if s.get('ret'):
            sig_str = f"{s['ret']}({s['params']})"
            # Check static
            parts = name.split('::')
            for j in range(len(parts) - 1):
                if '::'.join(parts[j:]) in static_methods:
                    sig_str = 'static ' + sig_str
                    break

        sym = {'n': name, 't': 'func', 'sig': sig_str, 'src': 'CommonLibSSE'}
        if se_off: sym['s'] = se_off
        if ae_off: sym['a'] = ae_off
        symbols.append(sym)

    # From RTTI offsets (labels)
    for name, offs in rtti_offsets.items():
        if offs.get('se') and offs['se'] not in seen_offsets_se:
            seen_offsets_se.add(offs['se'])
            sym = {'n': name, 't': 'label', 'sig': '', 'src': 'CommonLibSSE'}
            if offs.get('se'): sym['s'] = offs['se']
            if offs.get('ae'): sym['a'] = offs['ae']
            symbols.append(sym)

    # From VTABLE offsets (labels)
    for name, offs in vtable_offsets.items():
        if offs.get('se') and offs['se'] not in seen_offsets_se:
            seen_offsets_se.add(offs['se'])
            sym = {'n': name, 't': 'label', 'sig': '', 'src': 'CommonLibSSE'}
            if offs.get('se'): sym['s'] = offs['se']
            if offs.get('ae'): sym['a'] = offs['ae']
            symbols.append(sym)

    # From Offsets.h (functions referenced by Offset::Class::Method)
    for offset_name, se_id in se_offset_ids.items():
        ae_id = ae_offset_ids.get(offset_name)
        se_off = addr_lib.se_db.get(se_id)
        ae_off = addr_lib.ae_db.get(ae_id) if ae_id else None

        if se_off and se_off in seen_offsets_se:
            continue
        if se_off: seen_offsets_se.add(se_off)

        # Convert Offset namespace to Class::Method
        name = offset_name.replace('::', '::')
        sig_str = ''
        if name in sig_by_name:
            info = sig_by_name[name]
            if info.get('ret'):
                sig_str = f"{info['ret']}({info['params']})"

        sym = {'n': name, 't': 'func', 'sig': sig_str, 'src': 'CommonLibSSE'}
        if se_off: sym['s'] = se_off
        if ae_off: sym['a'] = ae_off
        symbols.append(sym)

    # Fallback: add names from AE rename database for any addresses not yet covered.
    # name_counts_ae tracks names already assigned an AE address (from any source).
    rename_db_path = os.path.join(base_dir, 'extern', 'AddressLibraryDatabase', 'skyrimae.rename')
    ae_rename = load_ae_rename_db(rename_db_path, addr_lib.ae_db)
    name_counts_ae = {}
    name_counts_se = {}
    for s in symbols:
        if s.get('a'):
            name_counts_ae[s['n']] = name_counts_ae.get(s['n'], 0) + 1
        if s.get('s'):
            name_counts_se[s['n']] = name_counts_se.get(s['n'], 0) + 1
    rename_added = 0
    for ae_off, name in ae_rename.items():
        if ae_off in seen_offsets_ae:
            continue
        seen_offsets_ae.add(ae_off)
        if name in name_counts_ae:
            continue  # Name already has an AE address from a higher-priority source
        name_counts_ae[name] = 1
        symbols.append({'n': name, 't': 'func', 'sig': '', 'a': ae_off, 'src': 'skyrimae.rename'})
        rename_added += 1
    print(f"Added {rename_added} symbols from AE rename database")

    # Fallback: add names from SE PDB for any SE addresses not yet covered.
    # Treated independently from AE rename — same name can appear in both versions.
    se_pdb_path = os.path.join(base_dir, 'pdbs', 'SkyrimSE.pdb')
    se_pdb = load_se_pdb_names(se_pdb_path)
    print(f"Loaded {len(se_pdb)} public function symbols from SE PDB")
    pdb_added = 0
    for se_off, name in se_pdb.items():
        if se_off in seen_offsets_se:
            continue
        seen_offsets_se.add(se_off)
        if name in name_counts_se:
            continue  # Name already has an SE address from a higher-priority source
        name_counts_se[name] = 1
        symbols.append({'n': name, 't': 'func', 'sig': '', 's': se_off, 'src': 'SkyrimSE.pdb'})
        pdb_added += 1
    print(f"Added {pdb_added} symbols from SE PDB")

    # Normalize __ -> :: in all symbol names
    for s in symbols:
        if '__' in s['n']:
            s['n'] = re.sub(r':{3,}', '::', s['n'].replace('__', '::'))

    # Count stats
    funcs = [s for s in symbols if s['t'] == 'func']
    with_sig = len([s for s in funcs if s.get('sig') and not s['sig'].startswith('static ')])
    with_sig += len([s for s in funcs if s.get('sig', '').startswith('static ')])
    labels = len([s for s in symbols if s['t'] == 'label'])

    print(f"\nGenerated {len(symbols)} symbols:")
    print(f"  Functions: {len(funcs)} ({with_sig} with signatures)")
    print(f"  Labels: {labels}")

    # Enums are already defined in the PDB, so we skip enum extraction
    enums = []

    # Write CommonLibGhidra.py
    output_path = os.path.join(base_dir, 'ghidrascripts', 'CommonLibGhidra.py')

    # Read the template (Ghidra script code)
    template_path = os.path.join(base_dir, 'ghidra_script_template.py')

    # Generate the script inline
    symbols_json = json.dumps(symbols, separators=(',', ':'))
    enums_json = json.dumps(enums, separators=(',', ':'))

    # Read the Ghidra script template
    ghidra_code = generate_ghidra_script()

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(ghidra_code)
        f.write(f"\nSYMBOLS = {symbols_json}\n")
        f.write(f"ENUMS = {enums_json}\n")
        f.write("\nif __name__ == '__main__':\n    run()\n")

    print(f"\nWrote {output_path}")
    print(f"  {len(symbols)} symbols, {len(enums)} enums")


def generate_ghidra_script():
    """Return the Ghidra script code as a string."""
    return '''# CommonLibGhidra.py - CommonLibSSE Ghidra Import Script
# @author extract_signatures.py
# @category Skyrim

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.cparser.C import CParserUtils
import re


def convert_sig_to_ghidra(sig, func_name):
    """Convert a CommonLib C++ signature to a Ghidra-compatible C prototype."""
    if not sig or sig == 'func_t':
        return None

    if 'RELOCATION_ID' in sig or 'func_t>' in sig or 'decltype' in sig:
        return None
    if ')(' in sig:
        return None
    if ':(' in sig:
        return None

    # Detect static before stripping
    is_static = bool(re.search(r'\\bstatic\\b', sig))

    sig = ' '.join(sig.split())

    # Clean noise
    sig = re.sub(r'^//\\s*[0-9A-Fa-f]+\\s*', '', sig)
    sig = re.sub(r'^//\\s*', '', sig)
    sig = re.sub(r'\\s*//[^\\n]*', '', sig)
    sig = re.sub(r'#\\w+\\b[^\\n]*', '', sig)
    sig = re.sub(r'\\b(?:public|private|protected)\\s*:\\s*', '', sig)
    sig = re.sub(r'\\boverride\\s+\\w+\\s*\\([^)]*\\)\\s*', '', sig)
    sig = re.sub(r'\\bRUNTIME_DATA_CONTENT\\b', '', sig)
    sig = re.sub(r'!\\w+\\([^)]*\\)\\s+', '', sig)

    sig = sig.replace('[[nodiscard]]', '')
    sig = re.sub(r'\\bstatic\\b', '', sig)
    sig = re.sub(r'\\bvirtual\\b', '', sig)
    sig = sig.strip()

    # Pre-simplify templates
    sig_pre = sig
    for _ in range(5):
        prev = sig_pre
        sig_pre = re.sub(r'\\w[\\w:]*<[^<>]*>\\s*\\*', 'void *', sig_pre)
        sig_pre = re.sub(r'\\w[\\w:]*<[^<>]*>', 'void', sig_pre)
        if sig_pre == prev: break
    sig = sig_pre

    # Find param list opening paren
    candidates = []
    depth = 0
    for i, c in enumerate(sig):
        if c == '<': depth += 1
        elif c == '>': depth -= 1
        elif c == '(' and depth == 0:
            candidates.append(i)

    if not candidates:
        return None

    paren_idx = None
    for idx in reversed(candidates):
        before = sig[:idx].rstrip()
        if before and re.search(r'[\\w*&]\\s*$', before):
            stripped_ret = before.strip()
            if stripped_ret and not re.match(
                r'^(if|for|while|switch|return|override|namespace|class|struct)\\b',
                stripped_ret.split()[-1] if stripped_ret.split() else ''
            ):
                paren_idx = idx
                break

    if paren_idx is None or paren_idx == 0:
        return None

    ret_type_raw = sig[:paren_idx].strip()
    params = sig[paren_idx:]

    # Clean ret type
    ret_type = ret_type_raw
    for pat in [r'.*\\b(?:public|private|protected)\\s*:\\s*',
                r'.*\\b(?:override)\\s+\\w+\\s*\\([^)]*\\)\\s*',
                r'.*//[^/]*\\s+',
                r'.*#\\w+[^(]*\\s+',
                r'.*!\\w+\\([^)]*\\)\\s+',
                r'.*\\bnamespace\\s+\\w+\\s*\\{\\s*',
                r'.*\\bmembers\\b\\s*']:
        m = re.match(pat, ret_type, re.DOTALL)
        if m: ret_type = ret_type[m.end():]

    ret_type = ret_type.strip()
    if not ret_type:
        return None

    def simplify_type(t, is_return=False):
        t = re.sub(r'\\s*=\\s*[^,)]*$', '', t)
        t = t.replace('std::uint64_t', 'ulonglong')
        t = t.replace('std::int64_t', 'longlong')
        t = t.replace('std::uint32_t', 'uint')
        t = t.replace('std::int32_t', 'int')
        t = t.replace('std::uint16_t', 'ushort')
        t = t.replace('std::int16_t', 'short')
        t = t.replace('std::uint8_t', 'uchar')
        t = t.replace('std::int8_t', 'char')
        t = t.replace('std::size_t', 'ulonglong')
        t = t.replace('std::ptrdiff_t', 'longlong')
        t = re.sub(r'\\bconst\\b\\s*', '', t)
        t = re.sub(r'(\\w[\\w:<>]*)\\s*&', r'\\1 *', t)
        for _ in range(5):
            prev = t
            t = re.sub(r'\\w[\\w:]*<[^<>]*>\\s*\\*', 'void *', t)
            t = re.sub(r'\\w[\\w:]*<[^<>]*>', 'void', t)
            if t == prev: break
        t = re.sub(r'Args\\s*\\.\\.\\..*', '', t)
        t = re.sub(r'\\w+::', '', t)
        return t.strip()

    ret_type = simplify_type(ret_type, is_return=True)
    if not ret_type:
        return None
    parts = ret_type.split()
    if len(parts) > 1 and parts[-1] not in ('*',) and not parts[-1].endswith('*'):
        ret_type = ' '.join(parts[:-1])

    # Parse params
    params_inner = params[1:-1].strip() if params.endswith(')') else params[1:].rstrip(')').strip()

    if params_inner == '' or params_inner == 'void':
        ghidra_params = 'void'
    else:
        param_list = []
        current = ''; depth = 0
        for c in params_inner:
            if c == '<': depth += 1
            elif c == '>': depth -= 1
            elif c == ',' and depth == 0:
                param_list.append(current.strip()); current = ''; continue
            current += c
        if current.strip(): param_list.append(current.strip())

        ghidra_params_list = []
        for p in param_list:
            p = simplify_type(p)
            if not p: continue
            tokens = p.split()
            if len(tokens) == 2 and tokens[0] == 'void' and '*' not in tokens[1]:
                p = 'void * ' + tokens[1]
            if tokens:
                last = tokens[-1].rstrip('*')
                if last in ('int','uint','float','double','bool','void','char',
                            'short','long','uchar','ushort','ulonglong','longlong') or last.endswith('*'):
                    p = p + ' param' + str(len(ghidra_params_list))
            ghidra_params_list.append(p)

        ghidra_params = ', '.join(ghidra_params_list) if ghidra_params_list else 'void'

    simple_name = func_name.split('::')[-1] if '::' in func_name else func_name

    # Add this pointer for member functions
    if '::' in func_name and not is_static:
        class_name = func_name.rsplit('::', 1)[0]
        class_name = class_name.split('::')[-1] if '::' in class_name else class_name
        this_param = class_name + ' * this'
        if ghidra_params == 'void':
            ghidra_params = this_param
        else:
            ghidra_params = this_param + ', ' + ghidra_params

    return ret_type + ' ' + simple_name + '(' + ghidra_params + ')'


_SAFE_TYPES = {
    'void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double',
    'uchar', 'ushort', 'uint', 'ulong', 'longlong', 'ulonglong',
    'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
    'byte', 'word', 'dword', 'qword', 'pointer', 'unsigned', 'signed',
}

def sanitize_unknown_types(proto):
    """Replace unknown types with void* for Ghidra parse fallback."""
    m = re.match(r'(.*?)\\s+(\\w+)\\s*\\((.*)\\)$', proto)
    if not m: return proto
    ret, name, params = m.group(1), m.group(2), m.group(3)

    def sanitize_token(t):
        t = t.strip()
        if not t or t == 'void': return t
        parts = t.split()
        base = parts[0].rstrip('*')
        if base.lower() in _SAFE_TYPES: return t
        is_ptr = '*' in t
        if is_ptr:
            star_count = t.count('*')
            stars = ' ' + '*' * star_count
            param_name = ''
            if len(parts) > 1 and '*' not in parts[-1]:
                param_name = ' ' + parts[-1]
            return 'void' + stars + param_name
        else:
            if len(parts) > 1 and parts[-1].isidentifier():
                return 'void * ' + parts[-1]
            return 'void *'

    ret_base = ret.rstrip('*').rstrip().split()[-1] if ret.split() else ret
    if ret_base.lower() not in _SAFE_TYPES:
        if '*' in ret: ret = 'void ' + '*' * ret.count('*')
        else: ret = 'void *'

    if params.strip() == 'void':
        safe_params = 'void'
    else:
        safe_params = ', '.join(sanitize_token(p.strip()) for p in params.split(','))

    return ret + ' ' + name + '(' + safe_params + ')'


def run():
    program = currentProgram
    name = program.getName()

    # Version detection: SE (1.5.x) vs AE (1.6.x)
    version_key = 's'  # default SE
    if '1.6' in name or 'AE' in name or 'ae' in name:
        version_key = 'a'
    elif 'SE' in name or 'se' in name or '1.5' in name:
        version_key = 's'

    symbol_table = program.getSymbolTable()
    base_addr = program.getImageBase()
    dtm = program.getDataTypeManager()
    fm = program.getFunctionManager()

    print('Starting CommonLibSSE Reconstruction...')
    print('Target Version: ' + ('AE' if version_key == 'a' else 'SE'))

    count_sym = 0; count_func = 0; count_sig = 0; count_sig_fail = 0
    used_names_at_addr = {}
    name_occurrence_count = {}

    tx = program.startTransaction('CommonLibImport')
    try:
        print('Applying ' + str(len(SYMBOLS)) + ' symbols...')
        for i, s in enumerate(SYMBOLS):
            off = s.get(version_key)
            if not off: continue

            addr = base_addr.add(off)
            sname = s['n']

            if addr not in used_names_at_addr:
                used_names_at_addr[addr] = set()
            if sname in used_names_at_addr[addr]:
                continue

            if sname in name_occurrence_count:
                name_occurrence_count[sname] += 1
                final_name = sname + '_' + str(name_occurrence_count[sname])
            else:
                name_occurrence_count[sname] = 0
                final_name = sname

            try:
                symbol_table.createLabel(addr, final_name, SourceType.USER_DEFINED)
                used_names_at_addr[addr].add(sname)
                count_sym += 1
                if s.get('src') and s['t'] == 'label':
                    cu = program.getListing().getCodeUnitAt(addr)
                    if cu:
                        cu.setComment(0, 'Source: ' + s['src'])
            except: pass

            if s['t'] == 'func':
                try:
                    f = fm.getFunctionAt(addr)
                    if not f:
                        cmd = DisassembleCommand(addr, None, True)
                        cmd.applyTo(program)
                        f = createFunction(addr, final_name)

                    if f:
                        curr_name = f.getName()
                        if curr_name.startswith('FUN_') or curr_name.startswith('sub_'):
                            f.setName(final_name, SourceType.USER_DEFINED)

                        comment_parts = []
                        se_id = s.get('si')
                        ae_id = s.get('ai')
                        if se_id and ae_id:
                            comment_parts.append('RELOCATION_ID(' + str(se_id) + ', ' + str(ae_id) + ')')
                        elif se_id:
                            comment_parts.append('REL::ID(' + str(se_id) + ')')
                        elif ae_id:
                            comment_parts.append('REL::ID(' + str(ae_id) + ')')
                        if s.get('src'):
                            comment_parts.append('Source: ' + s['src'])
                        if comment_parts:
                            cu = program.getListing().getCodeUnitAt(addr)
                            if cu:
                                cu.setComment(0, '\\n'.join(comment_parts))

                        if 'sig' in s and s['sig']:
                            proto = convert_sig_to_ghidra(s['sig'], final_name)
                            if proto:
                                applied = False
                                # Try original with real types first
                                try:
                                    func_def = CParserUtils.parseSignature(None, program, proto, True)
                                    if func_def:
                                        cmd = ApplyFunctionSignatureCmd(addr, func_def, SourceType.USER_DEFINED, True, False)
                                        cmd.applyTo(program)
                                        applied = True
                                except: pass
                                # Fall back to sanitized (unknown types -> void*)
                                if not applied:
                                    proto_safe = sanitize_unknown_types(proto)
                                    if proto_safe != proto:
                                        try:
                                            func_def = CParserUtils.parseSignature(None, program, proto_safe, True)
                                            if func_def:
                                                cmd = ApplyFunctionSignatureCmd(addr, func_def, SourceType.USER_DEFINED, True, False)
                                                cmd.applyTo(program)
                                                applied = True
                                        except: pass
                                if applied:
                                    count_sig += 1
                                else:
                                    count_sig_fail += 1
                                    if count_sig_fail <= 20:
                                        print('SIG FAIL: ' + proto[:120])
                        count_func += 1
                except: pass

            if i % 5000 == 0 and i > 0:
                print('Progress: ' + str(i) + ' items processed...')

        # Enums skipped - already defined in PDB

    finally:
        program.endTransaction(tx, True)

    print('Reconstruction Complete.')
    print('Labels: ' + str(count_sym) + ', Functions: ' + str(count_func))
    print('Signatures applied: ' + str(count_sig) + ', Signatures failed: ' + str(count_sig_fail))

'''


if __name__ == '__main__':
    main()
