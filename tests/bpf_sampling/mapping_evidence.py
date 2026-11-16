"""Independent RAW/proc/ELF evidence checks for the dynamic mapping workload."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

import archive
import artifacts
from stack_evidence import elf_symbols


def check_loop_artifact(path: Path) -> None:
    data = path.read_bytes()
    identity = artifacts.elf_identity(data)
    symbols, functions = elf_symbols(path)
    address = symbols.get('mapped_busy_loop')
    if address is None:
        raise ValueError('mapping workload loop symbol missing')
    matches = [segment for segment in identity['load_segments']
               if segment['flags'] & 1 and segment['vaddr'] <= address < segment['vaddr'] + segment['filesz']]
    if len(matches) != 1 or matches[0]['offset'] + address - matches[0]['vaddr'] != 4096:
        raise ValueError('mapping workload loop must start at executable file offset 4096')
    loops = [(start, end) for start, end, name in functions if start == address and name == 'mapped_busy_loop']
    if len(loops) != 1 or loops[0][1] - loops[0][0] > 32:
        raise ValueError('mapping workload loop has unexpected size')
    # These exact leaf instructions use only the integer argument and return
    # registers. Their relative branch remains within the mapped page.
    code = data[4096:4096 + loops[0][1] - loops[0][0]]
    expected = {243: bytes.fromhex('7d1519c16ff0dfff8280'),
                258: bytes.fromhex('84fcff029ffcff472000004c')}
    if code != expected.get(identity['machine']):
        raise ValueError('mapping loop differs from checked relocation-free instruction sequence')


def normalized_lines(text: str) -> list[str]:
    return [re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line).strip()
            for line in text.replace('\r', '').splitlines()]


def extract_snapshots(text: str) -> dict[str, bytes]:
    lines = normalized_lines(text)
    result = {}
    for point in ('before', 'after'):
        begins = [archive.fields(line) for line in lines if line.startswith(f'ARCHIVE MAPPINGS_BEGIN point={point} ')]
        ends = [line for line in lines if line == f'ARCHIVE MAPPINGS_END point={point}']
        if len(begins) != 1 or len(ends) != 1:
            raise ValueError('missing or duplicate original mapping journal snapshot')
        raw = archive.chunks(lines, 'ARCHIVE MAPPINGS_DATA ', point)
        if len(raw) != int(begins[0]['bytes']) or zlib.crc32(raw) != int(begins[0]['crc']):
            raise ValueError('mapping journal snapshot length/checksum mismatch')
        result[point] = raw
    return result


def parse_journal(raw: bytes) -> tuple[dict, list[dict]]:
    lines = raw.decode('utf-8').splitlines()
    if len(lines) < 2 or not lines[0].startswith('PULSE_BPF_MAPPINGS ') or not lines[-1].startswith('END '):
        raise ValueError('mapping journal header/trailer missing')
    header, trailer = archive.fields(lines[0]), archive.fields(lines[-1])
    if header.get('version') != '2' or header.get('available') != '1' or any(header[k] != trailer[k] for k in ('records', 'dropped', 'snapshot_ns')):
        raise ValueError('mapping journal framing mismatch')
    entries, index, sequence, timestamp = [], 1, 0, 0
    while index < len(lines) - 1:
        line = lines[index]
        row = archive.fields(line) | {'record': line.split()[0]}
        index += 1
        if int(row['seq']) != sequence + 1 or not timestamp <= int(row['ts']) <= int(header['snapshot_ns']):
            raise ValueError('mapping journal sequence/timestamp discontinuity')
        sequence, timestamp = int(row['seq']), int(row['ts'])
        if row['record'] == 'SPACE':
            row['maps'] = []
            for _ in range(int(row['count'])):
                if index >= len(lines) or not lines[index].startswith('MAP '):
                    raise ValueError('mapping snapshot incomplete')
                row['maps'].append({key: int(value) for key, value in archive.fields(lines[index]).items()})
                index += 1
            if index >= len(lines) or lines[index] != 'ENDSPACE':
                raise ValueError('mapping snapshot terminator missing')
            index += 1
        entries.append(row)
    if int(header['records']) != len(entries) or int(header['dropped']) != 0:
        raise ValueError('mapping gate requires complete original journal; loss remains partial')
    return header, entries


def resolve_sample(rows: list[dict], timestamp: int, task: int, ip: int) -> dict | None:
    def mutating(target: str, identity: int) -> bool:
        pending = {}
        for row in rows:
            if row['record'] != 'MUTATION' or row['target'] != target or int(row['id']) != identity:
                continue
            if row['complete'] == '0':
                pending[row['token']] = int(row['ts'])
            else:
                start = pending.pop(row['token'], None)
                if start is None or start <= timestamp <= int(row['ts']):
                    return True
        return any(start <= timestamp for start in pending.values())
    if mutating('task', task):
        return None
    tasks = [row for row in rows if row['record'] == 'TASK' and int(row['task']) == task]
    if any(int(row.get('begin_ns', row['ts'])) <= timestamp <= int(row['ts']) for row in tasks):
        return None
    visible = [row for row in tasks if int(row['ts']) < timestamp]
    if not visible or visible[-1]['kind'] == 'exit':
        return None
    identity = visible[-1]
    space = identity['space']
    if mutating('space', int(space)):
        return None
    revisions = [row for row in rows if row['record'] == 'SPACE' and row['space'] == space]
    if any(int(row['begin_ns']) <= timestamp <= int(row['ts']) for row in revisions):
        return None
    visible = [row for row in revisions if int(row['ts']) < timestamp]
    if not visible:
        return None
    pending = set()
    for row in rows:
        if row['record'] == 'TLB' and row['space'] == space and int(row['ts']) <= timestamp:
            if int(row['ts']) == timestamp:
                return None
            if row['complete'] == '1':
                pending.discard(row['token'])
            else:
                pending.add(row['token'])
    if pending:
        return None
    maps = [row for row in visible[-1]['maps'] if row['start'] <= ip < row['start'] + row['len'] and row['perms'] & 4]
    if len(maps) != 1:
        return None
    mapping = maps[0]
    objects = [row for row in rows if row['record'] == 'OBJECT' and int(row['object']) == mapping['object'] and int(row['ts']) < timestamp]
    if len(objects) != 1 or objects[0]['sha256'] == 'unknown':
        return None
    return {'space': int(space), 'exec': int(identity['exec']), 'pid': int(identity['pid']),
            'task_class': identity['class'], 'object': mapping['object'], 'sha256': objects[0]['sha256'],
            'pgoff': mapping['pgoff'], 'file_offset': mapping['pgoff'] + ip - mapping['start']}


def extract_and_verify(run: Path, text: str) -> dict:
    snapshots = extract_snapshots(text)
    for point, raw in snapshots.items():
        (run / f'mappings-{point}.txt').write_bytes(raw)
    (run / 'mappings.txt').write_bytes(snapshots['after'])
    manifest = artifacts.verify(run)
    inputs = json.loads((run / 'inputs.json').read_text())
    if hashlib.sha256((run / 'artifacts.json').read_bytes()).hexdigest() != inputs['artifact_bundle_sha256']:
        raise ValueError('artifact bundle changed since workload deployment')
    before_header, before_rows = parse_journal(snapshots['before'])
    after_header, rows = parse_journal(snapshots['after'])
    if rows[:len(before_rows)] != before_rows or int(before_header['snapshot_ns']) >= int(after_header['snapshot_ns']):
        raise ValueError('initial journal is not an ordered prefix of final journal')
    session = json.loads((run / 'archive.json').read_text())
    if not int(before_header['snapshot_ns']) <= min(source['enable_before'] for source in session['sources']) or int(after_header['snapshot_ns']) < session['stop_ns']:
        raise ValueError('mapping snapshots do not enclose source enable/stop window')
    object_hashes = {row.get('sha256') for row in rows if row['record'] == 'OBJECT'}
    expected_hashes = {inputs['payload_sha256'], hashlib.sha256((run / 'mapping-child.elf').read_bytes()).hexdigest()}
    if not expected_hashes <= object_hashes:
        raise ValueError('producer did not bind both actually executed user ELFs by content SHA256')
    tasks = [row for row in rows if row['record'] == 'TASK']
    if not {'exec', 'rename', 'exit'} <= {row.get('kind') for row in tasks}:
        raise ValueError('mapping journal lacks actual exec/rename/exit events')
    markers = [archive.fields(line) for line in normalized_lines(text) if line.startswith('MAPPING WORK ')]
    if len(markers) != 6 or {row.get('phase') for row in markers} != {'mapped', 'renamed', 'fork', 'exec', 'remapped', 'partial_remapped'}:
        raise ValueError('mapping workload phases missing or duplicated')
    complete = [archive.fields(line) for line in normalized_lines(text) if line.startswith('MAPPING COMPLETE ')]
    if len(complete) != 1 or complete[0].get('status') != '0' or complete[0]['old'] == complete[0]['moved']:
        raise ValueError('mapping mutation/fork completion unavailable')
    kernel_rows = [row for row in rows if row['record'] == 'KERNEL']
    kernel = manifest.get('kernel')
    if len(kernel_rows) != 1 or not kernel:
        raise ValueError('kernel runtime text/reference evidence missing')
    runtime = kernel_rows[0]
    relocation = int(runtime['reference']) - kernel['reference_address']
    if (bytes.fromhex(runtime['symbol_hex']).decode() != kernel['reference_symbol'] or
            int(runtime['start']) != kernel['text_start'] + relocation or
            int(runtime['len']) != kernel['text_end'] - kernel['text_start']):
        raise ValueError('kernel runtime range/reference differs from exact boot ELF')
    tlb = {}
    for row in rows:
        if row['record'] == 'TLB':
            tlb.setdefault((row['space'], row['token']), []).append(row['complete'])
    if not any(states == ['0', '1'] for states in tlb.values()):
        raise ValueError('real mapping mutation lacks completed TLB evidence')
    examples, counts = {}, {row['phase']: 0 for row in markers}
    resolved_counts = counts.copy()
    artifact_by_sha = {entry['sha256']: entry for entry in manifest['artifacts']}
    raw = (run / 'records.pbraw').read_bytes()
    offset = 64
    while offset < len(raw):
        sequence, cpu, size, _, _ = struct.unpack_from('<QIIII', raw, offset)
        offset += 24
        frame = raw[offset:offset + size]
        offset += size
        if struct.unpack_from('<I', frame)[0] != 9:
            continue
        logical_id, kind, payload = archive.source_context(frame)
        if kind not in (1, 3):
            raise ValueError("mapping evidence requires declared software records")
        timestamp, = struct.unpack_from('<Q', payload, 16)
        pid, tid = struct.unpack_from('<II', payload, 28)
        task, ip, mode = struct.unpack_from('<QQI', payload, 40)
        source_id = struct.unpack_from('<Q', payload, 64)[0] if kind == 3 else None
        if mode != 2:
            continue
        for row in markers:
            if pid == int(row['pid']) and int(row['start_ns']) <= timestamp < int(row['end_ns']) and int(row['start']) <= ip < int(row['start']) + int(row['len']):
                counts[row['phase']] += 1
                resolved = resolve_sample(rows, timestamp, task, ip)
                if resolved is not None:
                    expected = inputs['payload_sha256'] if row['phase'] != 'exec' else hashlib.sha256((run / 'mapping-child.elf').read_bytes()).hexdigest()
                    if resolved['sha256'] != expected or resolved['pid'] != pid or resolved['task_class'] != 'user' or resolved['pgoff'] != 4096:
                        raise ValueError('producer mapping/task/object differs from executed workload')
                    entry = artifact_by_sha[expected]
                    loads = [segment for segment in entry['load_segments'] if segment['flags'] & 1 and segment['offset'] <= resolved['file_offset'] < segment['offset'] + segment['filesz']]
                    if len(loads) != 1 or loads[0]['vaddr'] + resolved['file_offset'] - loads[0]['offset'] != 0x401000 + ip - int(row['start']):
                        raise ValueError('nonzero pgoff failed exact ELF PT_LOAD translation')
                    resolved_counts[row['phase']] += 1
                    examples.setdefault(row['phase'], dict(sequence=sequence, cpu=cpu, timestamp_ns=timestamp, tid=tid, task_id=task, ip=ip, source_id=source_id, **resolved))
    if min(counts.values()) == 0:
        raise ValueError(f'no real user samples for mapping mutation phase: {counts}')
    if min(resolved_counts.values()) == 0:
        raise ValueError(f'no provable mapping for real workload samples: {resolved_counts}')
    if examples['fork']['space'] == examples['mapped']['space'] or examples['fork']['object'] != examples['mapped']['object'] or examples['exec']['space'] == examples['fork']['space'] or examples['exec']['exec'] <= examples['fork']['exec']:
        raise ValueError('fork inheritance/exec address-space generation evidence invalid')
    result = {'counts': counts, 'resolved_counts': resolved_counts, 'examples': examples, 'workload': markers,
              'complete': complete[0], 'artifacts': [entry['sha256'] for entry in manifest['artifacts']],
              'kernel_relocation': relocation, 'completed_tlb_tokens': sum(states == ['0', '1'] for states in tlb.values()),
              'journal_sha256': hashlib.sha256(snapshots['after']).hexdigest(),
              'before_sha256': hashlib.sha256(snapshots['before']).hexdigest()}
    (run / 'mapping-evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def check_report(run: Path, report: dict) -> dict:
    """Cross-check the standalone Rust analyzer against independent RAW facts."""
    evidence = json.loads((run / 'mapping-evidence.json').read_text())
    if not report.get('mapping_metadata') or report.get('journal_dropped') != 0:
        raise ValueError('standalone analyzer did not preserve complete mapping journal')
    if report.get('busy_time_ns') is not None or report.get('idle_time_ns') is not None:
        raise ValueError('mapping report invented precise CPU utilization')
    for phase, expected in evidence['examples'].items():
        matches = [row for row in report['samples'] if all(row[key] == expected[source] for key, source in
                   [('timestamp_ns', 'timestamp_ns'), ('cpu', 'cpu'), ('task', 'task_id'), ('pid', 'pid'), ('tid', 'tid'), ('ip', 'ip')])
                   and row.get('source_id') == expected.get('source_id')]
        if len(matches) != 1:
            raise ValueError(f'standalone analyzer missing original RAW sample: {phase}')
        row = matches[0]
        mapping, elf = row['mapping'], row['elf']
        if not mapping or not elf or row['unknown_reason'] is not None:
            raise ValueError(f'standalone analyzer cannot verify known mutation sample: {phase}: {row}')
        if any(mapping[key] != expected[source] for key, source in
               [('space', 'space'), ('exec', 'exec'), ('object', 'object'), ('sha256', 'sha256'), ('byte_pgoff', 'pgoff'), ('file_offset', 'file_offset')]):
            raise ValueError(f'standalone analyzer differs from RAW mapping oracle: {phase}')
        if elf['sha256'] != expected['sha256'] or elf['name'] != 'mapped_busy_loop' or elf['elf_address'] != 0x400000 + expected['file_offset']:
            raise ValueError(f'standalone analyzer used wrong ELF/function/offset: {phase}')
    return {'verified_phases': sorted(evidence['examples']),
            'mapped_user_samples': report['mapped_user_samples'],
            'verified_elf_samples': report['verified_elf_samples']}
