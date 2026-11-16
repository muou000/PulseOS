"""Check real frozen chains against the exact payload/kernel ELF in a run."""
from pathlib import Path
import bisect
import hashlib
import json
import struct
import archive as raw_archive


def elf_symbols(path: Path) -> tuple[dict[str, int], list[tuple[int, int, str]]]:
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('stack evidence requires LE ELF64')
    section_offset = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count = struct.unpack_from('<HH', data, 58)
    if entry_size != 64 or section_offset + count * entry_size > len(data):
        raise ValueError('invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset + index * 64) for index in range(count)]
    names, functions = {}, []
    for section in sections:
        if section[1] != 2:
            continue
        offset, size, string_index, symbol_size = section[4], section[5], section[6], section[9]
        if symbol_size != 24 or size % 24 or string_index >= count or offset + size > len(data):
            raise ValueError('invalid ELF symbol table')
        strings = sections[string_index]
        table = data[strings[4]:strings[4] + strings[5]]
        for position in range(offset, offset + size, 24):
            name_offset, info, _, section_index, address, length = struct.unpack_from('<IBBHQQ', data, position)
            if section_index == 0 or name_offset >= len(table):
                continue
            end = table.find(b'\0', name_offset)
            if end < 0:
                raise ValueError('unterminated ELF symbol')
            name = table[name_offset:end].decode('utf-8', errors='replace')
            names[name] = address
            if info & 15 == 2 and length:
                functions.append((address, address + length, name))
    if not names or not functions:
        raise ValueError('ELF lacks symbol evidence')
    return names, sorted(functions)


def verify(run: Path) -> dict:
    inputs = json.loads((run / 'inputs.json').read_text())
    if inputs.get('context_format') != 'software-stack-v3' or not inputs.get('kernel_elf_matches_boot'):
        raise ValueError('stack evidence lacks native context/boot ELF identity')
    for name, key in [('payload.elf', 'payload_sha256'), ('kernel.elf', 'kernel_elf_sha256')]:
        if hashlib.sha256((run / name).read_bytes()).hexdigest() != inputs[key]:
            raise ValueError('stack evidence ELF hash differs from executed input')
    archive = json.loads((run / 'archive.json').read_text())
    target = archive.get('stack_target')
    if not isinstance(target, dict) or set(target) != {'pid','tid'} or any(not isinstance(value,int) or not 0 < value < (1 << 32) for value in target.values()):
        raise ValueError('stack evidence lacks exact target PID/TID')
    if any(archive['snapshots'][point]['pid'] != target['pid'] for point in ('before','after')):
        raise ValueError('stack target differs from proc snapshot identity')
    symbols, _ = elf_symbols(run / 'payload.elf')
    _, kernel = elf_symbols(run / 'kernel.elf')
    starts = [row[0] for row in kernel]
    def resolve(address, returning):
        # Return PCs denote the instruction after a call. Subtract one byte only
        # for symbol lookup; original capture addresses are never modified.
        lookup = address - int(returning)
        index = bisect.bisect_right(starts, lookup) - 1
        if index >= 0 and kernel[index][0] <= lookup < kernel[index][1]:
            return kernel[index][2]
        return None
    raw = (run / 'records.pbraw').read_bytes()
    if raw[:8] != b'PBRW0001':
        raise ValueError('stack evidence lacks raw archive')
    offset, counts, examples, source_counts, statuses = 64, {'user_a': 0, 'user_b': 0, 'kernel': 0, 'kernel_mmap': 0}, {}, {}, {}
    probes = {name: 0 for name in ('zero','unmapped','cycle','badra','misaligned','deep')}
    while offset < len(raw):
        _, cpu, size, _, _ = struct.unpack_from('<QIIII', raw, offset)
        offset += 24
        frame = raw[offset:offset + size]
        offset += size
        if len(frame) != size or size < 8:
            raise ValueError('truncated stack evidence')
        if struct.unpack_from('<I', frame)[0] != 9:
            continue
        logical_id, kind, payload = raw_archive.source_context(frame)
        if kind != 3 or len(payload) != 640:
            raise ValueError('nonstack record in native stack evidence')
        ip, mode = struct.unpack_from('<QI', payload, 48)
        pid, tid = struct.unpack_from("<II", payload, 28)
        is_target = (pid, tid) == (target["pid"], target["tid"])
        source, = struct.unpack_from('<Q', payload, 64)
        n, status = struct.unpack_from('<HH', payload, 108)
        ips = list(struct.unpack_from(f'<{n}Q', payload, 128))
        source_counts[source] = source_counts.get(source, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1
        if mode == 2 and is_target:
            for name, expected in [('zero',1),('unmapped',4),('cycle',3),('badra',5),('misaligned',2),('deep',6)]:
                if symbols[f'sample_probe_{name}_start'] <= ip < symbols[f'sample_probe_{name}_end']:
                    if status not in (expected,11):
                        raise ValueError(f'actual {name} probe returned wrong stack status {status}')
                    if status == expected:
                        probes[name] += 1
            for letter in ('a', 'b'):
                if symbols[f'sample_loop_{letter}'] <= ip < symbols[f'sample_loop_{letter}_end'] and len(ips) >= 3 and ips[1:3] == [symbols[f'sample_middle_{letter}_return'], symbols[f'sample_chain_{letter}_return']]:
                    name = f'user_{letter}'
                    counts[name] += 1
                    examples.setdefault(name, {'cpu': cpu, 'source': source, 'pid': pid, 'tid': tid, 'status': status, 'ips': ips})
        elif mode == 1 and len(ips) >= 3:
            names = [resolve(address, index > 0) for index, address in enumerate(ips)]
            if all(names[:3]) and len(set(names[:3])) >= 3:
                counts['kernel'] += 1
                example = {'cpu': cpu, 'source': source, 'pid': pid, 'tid': tid, 'status': status, 'ips': ips, 'symbols': names}
                examples.setdefault('kernel', example)
                if is_target and any(name and ('sys_mmap' in name or 'sys_munmap' in name or 'try_fault_in_user_range' in name) for name in names):
                    counts['kernel_mmap'] += 1
                    examples.setdefault('kernel_mmap', example)
    if min(counts['user_a'], counts['user_b'], counts['kernel'], counts['kernel_mmap']) < 2:
        raise ValueError(f'RAW/ELF lacks verified multi-layer user and actual mmap kernel chains: {counts}')
    if min(probes.values()) == 0:
        raise ValueError(f'RAW lacks negative stack diagnostics: {probes}')
    expected_sources = 16 if inputs['mode'] == 'cpu' else 1
    if len(source_counts) != expected_sources:
        raise ValueError('RAW stack source instances incomplete')
    result = {'context_format': 'software-stack-v3', 'counts': counts, 'source_counts': source_counts, 'status_counts': statuses,
              'target': target, 'examples': examples, 'negative_probes': probes, 'payload_sha256': inputs['payload_sha256'], 'kernel_elf_sha256': inputs['kernel_elf_sha256']}
    (run / 'stack-evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
