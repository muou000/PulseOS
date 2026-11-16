#!/usr/bin/env python3
"""Replay SHA-indexed mapping bundles without original run or disk-image paths.

An independent struct/CRC decoder compares every RAW and normalized record.
The temporal oracle then checks actual journal/ELF/analyzer agreement. Only
indexed regular files may be extracted into the disposable replay directory.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import zlib

import archive
import artifacts
import capture
import mapping_evidence
from verify_observation_evidence import Record, decode_raw, compare_records


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_records(data: bytes, arch: str) -> tuple[list[Record], int]:
    if len(data) < 120:
        raise ValueError('capture truncated')
    fields = struct.unpack_from('<8sIIIIQQQQQQQ', data)
    magic, version, schema, hsize, target, mstart, mlen, rstart, count, rlen, tstart, tlen = fields
    if (magic != b'PBCAP001' or version != 6 or schema != 1 or hsize != 80 or mstart != 80
            or target != {'riscv64': 1, 'loongarch64': 2}[arch] or mlen == 0
            or rstart != mstart + mlen or tstart != rstart + rlen or tlen != 40 or tstart + tlen != len(data)):
        raise ValueError('invalid capture-v6 framing')
    magic, tail_count, tail_bytes, crc, status, tail_size, reserved = struct.unpack_from('<8sQQIIII', data, tstart)
    if (magic != b'PBCAPTRL' or tail_count != count or tail_bytes != rlen or tail_size != 40
            or reserved or status not in range(4) or zlib.crc32(data[:tstart]) != crc):
        raise ValueError('capture-v6 checksum/trailer mismatch')
    rows, cursor = [], rstart
    while cursor < tstart:
        if tstart - cursor < 48:
            raise ValueError('capture normalized header truncated')
        event, schema, time, cpu, pid, tid, reserved, task, size, pad = struct.unpack_from('<IIQIIIIQII', data, cursor)
        cursor += 48
        if reserved or pad or size > tstart - cursor:
            raise ValueError('capture normalized payload invalid')
        rows.append(Record(event, schema, time, cpu, pid, tid, task, data[cursor:cursor + size]))
        cursor += size
    if len(rows) != count:
        raise ValueError('capture normalized count mismatch')
    return rows, status


def verify_run(run: Path, capture_name: str = 'capture.pbcapture') -> dict:
    inputs = json.loads((run / 'inputs.json').read_text())
    result = json.loads((run / 'result.json').read_text())
    if result.get('passed') is not True or result.get('errors'):
        raise ValueError('bundle was not a passing actual guest run')
    raw, metadata, stats = archive.extract((run / 'guest.log').read_text(), inputs['mode'])
    if raw != (run / 'records.pbraw').read_bytes() or json.loads(json.dumps(metadata)) != json.loads((run / 'archive.json').read_text()):
        raise ValueError('original output differs from saved RAW/metadata')
    for point, value in stats.items():
        if value != (run / f'stats-{point}.txt').read_bytes():
            raise ValueError('original counters differ from proc snapshot')
    for name, key in [('kernel.elf', 'kernel_elf_sha256'), ('payload.elf', 'payload_sha256')]:
        if digest(run / name) != inputs[key]:
            raise ValueError('executed ELF bytes differ from run identity')
    kernel = run / 'kernel.elf'
    if inputs['arch'] == 'riscv64':
        boot = run / 'independent-kernel.bin'
        capture.command(['rust-objcopy', '--binary-architecture=riscv64', str(kernel), '--strip-all', '-O', 'binary', str(boot)])
    else:
        boot = kernel
    provenance = json.loads((run / 'kernel.provenance.json').read_text())
    boot_kind = 'binary' if inputs['arch'] == 'riscv64' else 'elf'
    if (digest(boot) != inputs['kernel_sha256'] or provenance['artifacts']['elf']['sha256'] != digest(kernel)
            or provenance['artifacts'][boot_kind]['sha256'] != digest(boot)):
        raise ValueError('bundled kernel ELF cannot reproduce boot/provenance identity')
    build = json.loads((run / 'payload-build.json').read_text())
    for source, expected in build['source_inputs'].items():
        if digest(run / Path(source).name) != expected:
            raise ValueError('payload source differs from build input')
    artifacts.verify(run)
    saved = json.loads((run / 'mapping-evidence.json').read_text())
    computed = mapping_evidence.extract_and_verify(run, (run / 'guest.log').read_text())
    if computed != saved:
        raise ValueError('mapping oracle changed during independent replay')
    raw_rows, raw_counts = decode_raw(raw, inputs['mode'])
    normalized, status = normalized_records((run / capture_name).read_bytes(), inputs['arch'])
    compare_records(raw_rows, normalized)
    analyzer = str(capture.REPO / 'target/debug/bpf-analyzer')
    summary = json.loads(capture.command([analyzer, str(run / capture_name), '--json']))
    report = json.loads(capture.command([analyzer, str(run / capture_name), '--mapping-report', '--bundle', str(run)]))
    agreement = mapping_evidence.check_report(run, report)
    if summary['records_count'] != len(raw_rows) or summary['attribution_claim_allowed']:
        raise ValueError('analyzer count/attribution differs from original evidence')
    fresh = run / 'independent-reimport.pbcapture'
    capture.command([str(capture.REPO / 'target/debug/examples/runtime_import'), str(run), str(fresh)])
    reimported, reimport_status = normalized_records(fresh.read_bytes(), inputs['arch'])
    compare_records(raw_rows, reimported)
    if reimport_status != status:
        raise ValueError('reimport changed capture completeness')
    fresh_report = json.loads(capture.command([analyzer, str(fresh), '--mapping-report', '--bundle', str(run)]))
    if fresh_report != report:
        raise ValueError('reimport changed temporal mapping/ELF analysis')
    negative_cases = []
    for case in ('missing-elf', 'same-name-wrong-elf'):
        with tempfile.TemporaryDirectory(prefix='pulse-193-negative-') as directory:
            negative_bundle = Path(directory)
            if case == 'same-name-wrong-elf':
                (negative_bundle / 'artifacts').mkdir()
                parent, child = run / 'payload.elf', run / 'mapping-child.elf'
                for expected, wrong in [(parent, child), (child, parent)]:
                    (negative_bundle / 'artifacts' / f'{digest(expected)}.elf').write_bytes(wrong.read_bytes())
            negative = json.loads(capture.command([analyzer, str(run / capture_name), '--mapping-report', '--bundle', str(negative_bundle)]))
            for example in computed['examples'].values():
                matched = [row for row in negative['samples'] if row['timestamp_ns'] == example['timestamp_ns']
                           and row['task'] == example['task_id'] and row['ip'] == example['ip'] and row['cpu'] == example['cpu']]
                if len(matched) != 1 or matched[0]['elf'] is not None or not matched[0]['mapping'] or not matched[0]['unknown_reason']:
                    raise ValueError('missing/wrong ELF replay falsely resolved a real workload sample')
            negative_cases.append(case)
    return {'capture_status': summary['status'], 'raw_normalized_equal': True,
            'reimport_report_equal': True, 'phase_counts': computed['counts'],
            'resolved_counts': computed['resolved_counts'],
            'completed_tlb_tokens': computed['completed_tlb_tokens'],
            'kernel_relocation': computed['kernel_relocation'], 'negative_cases': negative_cases,
            'boot_reconstructed_from_elf': True, **agreement, **raw_counts}


def verify_index(evidence: Path) -> dict:
    index = json.loads((evidence / 'index.json').read_text())
    report = {'format': 'pulse-mapping-evidence-replay', 'version': 1, 'runs': {}}
    for name, entry in index['runs'].items():
        bundle = evidence / entry['bundle']
        if digest(bundle) != entry['bundle_sha256']:
            raise ValueError(f'{name} bundle SHA mismatch')
        with tempfile.TemporaryDirectory(prefix='pulse-193-replay-') as temporary:
            destination = Path(temporary)
            with tarfile.open(bundle, 'r:gz') as stream:
                members = stream.getmembers()
                if len(members) != len(entry['members_sha256']) or {member.name for member in members} != set(entry['members_sha256']):
                    raise ValueError('bundle member set differs from SHA index')
                for member in members:
                    path = Path(member.name)
                    if not member.isfile() or path.is_absolute() or '..' in path.parts:
                        raise ValueError('nonregular or unsafe bundle member')
                    raw = stream.extractfile(member).read()
                    if hashlib.sha256(raw).hexdigest() != entry['members_sha256'][member.name]:
                        raise ValueError('bundle member SHA mismatch')
                    target = destination / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)
            result = verify_run(destination, entry.get('analysis_capture', 'capture.pbcapture'))
            report['runs'][name] = {'members_verified': len(members), 'bundle_sha256': entry['bundle_sha256'], **result}
    if 'validation' in index:
        entry = index['validation']
        bundle = evidence / entry['bundle']
        if digest(bundle) != entry['bundle_sha256']:
            raise ValueError('validation bundle SHA mismatch')
        with tarfile.open(bundle, 'r:gz') as stream:
            members = stream.getmembers()
            if len(members) != len(entry['members_sha256']) or {m.name for m in members} != set(entry['members_sha256']):
                raise ValueError('validation member set differs from index')
            for member in members:
                if not member.isfile() or hashlib.sha256(stream.extractfile(member).read()).hexdigest() != entry['members_sha256'][member.name]:
                    raise ValueError('validation member type/SHA mismatch')
        report['validation'] = {'members_verified': len(members), 'bundle_sha256': entry['bundle_sha256']}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    if not args.no_build:
        capture.command(['cargo', 'build', '-p', 'bpf-capture', '--example', 'runtime_import'])
        capture.command(['cargo', 'build', '-p', 'bpf-analyzer'])
    result = verify_index(args.evidence.resolve())
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
