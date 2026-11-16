"""Derive an ELF symbol view for perf while preserving its entire load image.

Linux perf treats visible STT_NOTYPE labels as symbols. Rust's local `.L*`
assembler labels and RISC-V ISA/data mapping symbols can consequently shadow real
STT_FUNC symbols. This view hides those labels from perf, without removing or
changing any function symbol.
The captured ELF remains authoritative; the view has its own content identity.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct

TRANSFORMATION = 'elf64-le-local-notype-debug-and-rv64-mapping-visibility-hidden-v2'
# RISC-V psABI mapping symbols: $d[.<suffix>], $x[.<suffix>], or
# $x<ISA>[.<suffix>]. Restrict ISA forms to the RV64 named-extension encoding
# used by these ELF64 artifacts; arbitrary dollar-prefixed labels stay visible.
# https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc
RV64_MAPPING = re.compile(rb'\$(?:d|x(?:rv64[ieg](?:[0-9]+p[0-9]+)?(?:_[a-z][a-z0-9]*)*)?)(?:\..+)?')


def hide_local_labels(original: bytes) -> tuple[bytes, int]:
    def read(fmt: str, offset: int):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(original):
            raise ValueError('truncated ELF structure')
        return struct.unpack_from(fmt, original, offset)

    def span(offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(original):
            raise ValueError('truncated ELF span')
        return original[offset:offset + size]

    header = span(0, 64)
    if header[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('symbol view requires ELF64 little-endian')
    kind, machine, version, _, phoff, shoff, _, ehsize, phsize, phcount, shsize, shcount, _ = read('<HHIQQQIHHHHHH', 16)
    if (kind not in (2, 3) or machine not in (243, 258) or version != 1 or ehsize != 64
            or phsize != 56 or not 0 < phcount <= 4096 or shsize != 64 or not 0 < shcount <= 32768):
        raise ValueError('unsupported ELF table shape')
    loads = []
    for index in range(phcount):
        ptype, _, offset, _, _, filesz, memsz, _ = read('<IIQQQQQQ', phoff + index * phsize)
        if ptype == 1:
            span(offset, filesz)
            if filesz > memsz:
                raise ValueError('invalid PT_LOAD sizes')
            loads.append((offset, offset + filesz))
    if not loads:
        raise ValueError('ELF has no PT_LOAD segment')
    sections = [read('<IIQQQQIIQQ', shoff + index * shsize) for index in range(shcount)]
    edits = set()
    for section in sections:
        if section[1] != 2:  # Static symbol table only; dynamic linkage is untouched.
            continue
        _, _, _, _, offset, size, string_index, _, _, entry_size = section
        if entry_size != 24 or size % entry_size or size // entry_size > 4_000_000 or string_index >= shcount:
            raise ValueError('invalid ELF symbol table')
        span(offset, size)
        strings_section = sections[string_index]
        if strings_section[1] != 3:
            raise ValueError('symbol string table link is invalid')
        strings = span(strings_section[4], strings_section[5])
        for position in range(offset, offset + size, entry_size):
            name_index, info, other, section_index, _, symbol_size = read('<IBBHQQ', position)
            if name_index >= len(strings):
                raise ValueError('symbol string offset is invalid')
            end = strings.find(b'\0', name_index)
            if end < 0:
                raise ValueError('unterminated symbol name')
            name = strings[name_index:end]
            mapping_label = machine == 243 and symbol_size == 0 and RV64_MAPPING.fullmatch(name) is not None
            # st_info == 0 means STB_LOCAL | STT_NOTYPE. Function entries,
            # global/weak labels, symbol names/addresses/sizes remain byte-identical.
            if info == 0 and section_index != 0 and (name.startswith(b'.L') or mapping_label) and other & 3 not in (1, 2):
                edit = position + 5  # Elf64_Sym.st_other only.
                if any(start <= edit < end for start, end in loads):
                    raise ValueError('symbol visibility edit overlaps PT_LOAD file bytes')
                edits.add(edit)
    derived = bytearray(original)
    for position in edits:
        derived[position] = (derived[position] & ~3) | 2  # STV_HIDDEN; preserve architecture bits.
    for start, end in loads:
        if derived[start:end] != original[start:end]:
            raise ValueError('symbol view altered loaded bytes')
    return bytes(derived), len(edits)


def prepare_symbol_view(source: Path, destination: Path) -> dict:
    original = source.read_bytes()
    derived, count = hide_local_labels(original)
    with destination.open('xb') as output:
        output.write(derived)
    return {'transformation': TRANSFORMATION,
            'original_sha256': hashlib.sha256(original).hexdigest(),
            'derived_sha256': hashlib.sha256(derived).hexdigest(),
            'hidden_local_labels': count, 'load_bytes_unchanged': True,
            'function_symbols_unchanged': True}
