"""Shared ELF parsing, hashing, and version utilities for BPF fixtures."""

import hashlib
import struct
from pathlib import Path
from typing import Any, Dict, List, Tuple

EM_BPF = 247
R_BPF_64_64 = 1
SHT_RELA = 4
SHT_REL = 9
FORBIDDEN_SECTIONS = [".BTF", ".BTF.ext", ".rel.BTF"]


def compute_sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def parse_version_file(path: Path) -> Dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"VERSION file not found at {path}")
    data = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            data[key.strip()] = val.strip()
    return data


def parse_elf(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Parse ELF64 Little-Endian header, sections, relocations, and maps."""
    with path.open("rb") as f:
        data = f.read()

    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError(f"File is not an ELF binary: {path}")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class != 2 or ei_data != 1:
        raise ValueError(f"Expected 64-bit Little-Endian ELF (class=2, data=1), got {ei_class}, {ei_data}")

    e_machine = struct.unpack_from("<H", data, 18)[0]
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    shstr_offset = 0
    shstr_size = 0
    if e_shstrndx < e_shnum:
        offset = e_shoff + e_shstrndx * e_shentsize
        shstr_offset = struct.unpack_from("<Q", data, offset + 24)[0]
        shstr_size = struct.unpack_from("<Q", data, offset + 32)[0]

    shstrtab = data[shstr_offset:shstr_offset + shstr_size]

    sections: List[Dict[str, Any]] = []
    symtab_sec = None
    strtab_sec = None

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", data, off + 0)[0]
        sh_type = struct.unpack_from("<I", data, off + 4)[0]
        sh_flags = struct.unpack_from("<Q", data, off + 8)[0]
        sh_addr = struct.unpack_from("<Q", data, off + 16)[0]
        sh_offset = struct.unpack_from("<Q", data, off + 24)[0]
        sh_size = struct.unpack_from("<Q", data, off + 32)[0]
        sh_link = struct.unpack_from("<I", data, off + 40)[0]
        sh_info = struct.unpack_from("<I", data, off + 44)[0]

        name_bytes = shstrtab[sh_name_idx:].split(b"\x00", 1)[0]
        name = name_bytes.decode("utf-8", errors="replace")

        sec_dict = {
            "index": i,
            "name": name,
            "type": sh_type,
            "flags": sh_flags,
            "addr": sh_addr,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "info": sh_info,
        }
        sections.append(sec_dict)
        if name == ".symtab":
            symtab_sec = sec_dict
        elif name == ".strtab":
            strtab_sec = sec_dict

    # Symbols
    symbols: Dict[int, str] = {}
    if symtab_sec and strtab_sec:
        sym_data = data[symtab_sec["offset"]:symtab_sec["offset"] + symtab_sec["size"]]
        str_data = data[strtab_sec["offset"]:strtab_sec["offset"] + strtab_sec["size"]]
        entry_size = 24
        for s_idx in range(len(sym_data) // entry_size):
            s_off = s_idx * entry_size
            st_name_idx = struct.unpack_from("<I", sym_data, s_off)[0]
            sym_name = str_data[st_name_idx:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            symbols[s_idx] = sym_name

    # Relocations
    relocations: List[Dict[str, Any]] = []
    for sec in sections:
        if sec["type"] in (SHT_RELA, SHT_REL):
            rel_data = data[sec["offset"]:sec["offset"] + sec["size"]]
            entry_size = 16 if sec["type"] == SHT_REL else 24
            count = sec["size"] // entry_size
            for r_idx in range(count):
                r_off = r_idx * entry_size
                offset = struct.unpack_from("<Q", rel_data, r_off)[0]
                info = struct.unpack_from("<Q", rel_data, r_off + 8)[0]
                r_sym = info >> 32
                r_type = info & 0xFFFFFFFF
                sym_name = symbols.get(r_sym, f"sym_{r_sym}")
                relocations.append({
                    "section": sec["name"],
                    "offset": offset,
                    "sym_index": r_sym,
                    "sym_name": sym_name,
                    "type": r_type,
                })

    # Maps
    maps: Dict[str, Dict[str, int]] = {}
    maps_sec = next((s for s in sections if s["name"] == "maps"), None)
    if maps_sec:
        map_bytes = data[maps_sec["offset"]:maps_sec["offset"] + maps_sec["size"]]
        map_def_size = 20  # struct bpf_map_def
        if symtab_sec and strtab_sec:
            sym_data = data[symtab_sec["offset"]:symtab_sec["offset"] + symtab_sec["size"]]
            str_data = data[strtab_sec["offset"]:strtab_sec["offset"] + strtab_sec["size"]]
            entry_size = 24
            for s_idx in range(len(sym_data) // entry_size):
                s_off = s_idx * entry_size
                st_name_idx = struct.unpack_from("<I", sym_data, s_off)[0]
                st_info = sym_data[s_off + 4]
                st_shndx = struct.unpack_from("<H", sym_data, s_off + 6)[0]
                st_value = struct.unpack_from("<Q", sym_data, s_off + 8)[0]
                sym_name = str_data[st_name_idx:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")

                if st_shndx == maps_sec["index"] and (st_info & 0xF) == 1 and sym_name:
                    m_off = st_value
                    if m_off + map_def_size <= len(map_bytes):
                        m_type, m_ksize, m_vsize, m_max, m_flags = struct.unpack_from("<IIIII", map_bytes, m_off)
                        maps[sym_name] = {
                            "type": m_type,
                            "key_size": m_ksize,
                            "value_size": m_vsize,
                            "max_entries": m_max,
                            "map_flags": m_flags,
                        }

    header = {
        "machine": e_machine,
        "endianness": "little",
        "shnum": e_shnum,
    }

    return header, sections, relocations, maps
