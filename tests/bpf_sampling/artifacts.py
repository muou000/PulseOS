"""Content-addressed ELF artifacts; filenames never establish executable identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


def elf_identity(data: bytes) -> dict:
    """Read LE ELF64 load segments and actual GNU notes, with bounded tables."""
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('artifact must be a little-endian ELF64 object')
    elf_type, machine = struct.unpack_from('<HH', data, 16)
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    ehsize, phsize, phnum, shsize, shnum, shstr = struct.unpack_from('<HHHHHH', data, 52)
    if ehsize != 64 or (phnum and phsize != 56) or (shnum and shsize != 64):
        raise ValueError('unsupported ELF table entry size')
    def span(offset, size):
        if offset > len(data) or size > len(data) - offset:
            raise ValueError('ELF table or segment outside artifact')
        return data[offset:offset + size]
    span(phoff, phsize * phnum)
    span(shoff, shsize * shnum)
    segments, note_ranges = [], set()
    for index in range(phnum):
        kind, flags, offset, vaddr, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + index * phsize)
        span(offset, filesz)
        if kind == 1:
            if filesz > memsz or vaddr + memsz > 1 << 64 or (align > 1 and (align & (align - 1) or vaddr % align != offset % align)):
                raise ValueError('invalid ELF load segment')
            segments.append(dict(offset=offset, vaddr=vaddr, filesz=filesz, memsz=memsz, flags=flags, align=align))
        elif kind == 4:
            note_ranges.add((offset, filesz))
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * shsize) for index in range(shnum)]
    if shnum and shstr >= shnum:
        raise ValueError('invalid ELF section name table')
    names = span(sections[shstr][4], sections[shstr][5]) if shnum and shstr else b''
    debug_sections, external_debuglink = [], None
    for name_offset, kind, _, _, offset, size, _, _, _, _ in sections:
        if kind == 7:
            span(offset, size)
            note_ranges.add((offset, size))
        if names:
            end = names.find(b'\0', name_offset)
            if name_offset >= len(names) or end < 0:
                raise ValueError('invalid ELF section name')
            name = names[name_offset:end].decode('utf-8', errors='strict')
            if name.startswith(('.debug_', '.zdebug_')) and size:
                span(offset, size)
                debug_sections.append(name)
            if name == '.gnu_debuglink':
                value = span(offset, size)
                terminator = value.find(b'\0')
                crc_offset = (terminator + 4) & ~3
                if terminator <= 0 or crc_offset + 4 > len(value):
                    raise ValueError('invalid GNU debuglink')
                external_debuglink = {'name': value[:terminator].decode('utf-8'),
                                      'crc32': struct.unpack_from('<I', value, crc_offset)[0]}
    build_ids = set()
    for offset, size in note_ranges:
        notes, cursor = span(offset, size), 0
        while cursor < len(notes):
            if len(notes) - cursor < 12:
                if not any(notes[cursor:]):
                    break
                raise ValueError('truncated ELF note header')
            namesz, descsz, kind = struct.unpack_from('<III', notes, cursor)
            cursor += 12
            name_end = cursor + namesz
            desc_start = cursor + ((namesz + 3) & ~3)
            desc_end = desc_start + descsz
            next_note = desc_start + ((descsz + 3) & ~3)
            if name_end > len(notes) or desc_end > len(notes) or next_note > len(notes):
                raise ValueError('truncated ELF note payload')
            if kind == 3 and notes[cursor:name_end] == b'GNU\0':
                if not descsz:
                    raise ValueError('empty GNU build-id')
                build_ids.add(notes[desc_start:desc_end].hex())
            cursor = next_note
    if len(build_ids) > 1:
        raise ValueError('conflicting GNU build-id notes')
    return dict(sha256=hashlib.sha256(data).hexdigest(),
                gnu_build_id=next(iter(build_ids), None), elf_type=elf_type,
                machine=machine, load_segments=segments,
                debug_sections=sorted(debug_sections), external_debuglink=external_debuglink)


def bundle(run: Path, paths: list[Path]) -> dict:
    """Copy supplied exact executed ELFs, retaining their embedded debug data."""
    destination = run / 'artifacts'
    destination.mkdir(exist_ok=True)
    entries = {}
    for path in paths:
        data = path.read_bytes()
        identity = elf_identity(data)
        digest = identity['sha256']
        relative = f'artifacts/{digest}.elf'
        saved = run / relative
        if saved.exists() and saved.read_bytes() != data:
            raise ValueError('content-addressed artifact path already has different bytes')
        saved.write_bytes(data)
        embedded = any(name in ('.debug_info', '.zdebug_info') for name in identity['debug_sections'])
        entries[digest] = {**identity, 'path': relative, 'debug_sha256': digest if embedded else None,
                           'debug_build_id': identity['gnu_build_id'] if embedded else None,
                           'debug_status': 'embedded' if embedded else 'external-unavailable' if identity['external_debuglink'] else 'absent'}
    manifest = {'version': 1, 'artifacts': list(entries.values())}
    kernel = next((path for path in paths if path.name == 'kernel.elf'), None)
    if kernel is not None:
        from stack_evidence import elf_symbols
        symbols, _ = elf_symbols(kernel)
        if not symbols.get('_stext', 0) < symbols.get('_etext', 0):
            raise ValueError('kernel ELF lacks a nonempty reference text range')
        manifest['kernel'] = {'sha256': hashlib.sha256(kernel.read_bytes()).hexdigest(),
                              'reference_symbol': '_stext', 'reference_address': symbols['_stext'],
                              'text_start': symbols['_stext'], 'text_end': symbols['_etext'],
                              'relocation': None}
    (run / 'artifacts.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def verify(run: Path) -> dict:
    """Reject a stale manifest, same-name replacement, or missing exact artifact."""
    manifest = json.loads((run / 'artifacts.json').read_text())
    if manifest.get('version') != 1 or not isinstance(manifest.get('artifacts'), list):
        raise ValueError('unsupported artifact bundle')
    seen = set()
    for entry in manifest['artifacts']:
        digest = entry['sha256']
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest) or digest in seen:
            raise ValueError('invalid or duplicate artifact SHA256')
        seen.add(digest)
        if entry['path'] != f'artifacts/{digest}.elf':
            raise ValueError('artifact path is not content addressed')
        identity = elf_identity((run / entry['path']).read_bytes())
        if any(entry.get(key) != value for key, value in identity.items()):
            raise ValueError('artifact bytes differ from captured identity')
        embedded = any(name in ('.debug_info', '.zdebug_info') for name in identity['debug_sections'])
        expected_debug = (digest, identity['gnu_build_id'], 'embedded') if embedded else (
            None, None, 'external-unavailable' if identity['external_debuglink'] else 'absent')
        if (entry.get('debug_sha256'), entry.get('debug_build_id'), entry.get('debug_status')) != expected_debug:
            raise ValueError('debug artifact identity differs from ELF contents')
    return manifest
