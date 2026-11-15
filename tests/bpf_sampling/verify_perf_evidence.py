#!/usr/bin/env python3
"""Replay indexed #194 evidence in fresh directories without original run paths.

The original guest result is retained, including host-validator failures. The
current RAW/capture, mapping, stack and perf oracles are separate replay gates.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
import stack_evidence
from verify_mapping_evidence import normalized_records
from verify_observation_evidence import Record, compare_records

_spec = importlib.util.spec_from_file_location('perf_pipeline', capture.REPO / 'scripts/perf_pipeline.py')
pipeline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pipeline)
_symbols_spec = importlib.util.spec_from_file_location('perf_symbols', capture.REPO / 'scripts/perf_symbols.py')
symbols = importlib.util.module_from_spec(_symbols_spec)
_symbols_spec.loader.exec_module(symbols)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_stack_raw(data: bytes) -> list[Record]:
    """Decode unchanged stack-v3 RAW independently of the Rust importer."""
    if len(data) < 64:
        raise ValueError('truncated RAW evidence')
    magic, start, stop, count, size, crc, dropped, reserved = struct.unpack_from('<8sQQQQII16s', data)
    if (magic != b'PBRW0001' or reserved != bytes(16) or not 0 < start < stop
            or size != len(data) - 64 or zlib.crc32(data[64:]) != crc):
        raise ValueError('invalid RAW archive header/CRC')
    cursor, frame_count, records = 64, 0, []
    while cursor < len(data):
        if len(data) - cursor < 24:
            raise ValueError('truncated RAW frame envelope')
        sequence, cpu, length, crc, reserved = struct.unpack_from('<QIIII', data, cursor)
        cursor += 24
        if (sequence != frame_count or cpu >= 8 or reserved or length < 8
                or length % 8 or length > len(data) - cursor):
            raise ValueError('invalid RAW frame envelope')
        frame = data[cursor:cursor + length]
        cursor += length
        kind, misc, declared = struct.unpack_from('<IHH', frame)
        if declared != length or zlib.crc32(frame) != crc:
            raise ValueError('RAW frame CRC or length differs')
        frame_count += 1
        if kind == 2:
            if length != 24:
                raise ValueError('invalid RAW loss record')
            continue
        if kind != 9 or length != 656 or struct.unpack_from('<I', frame, 8)[0] != 640:
            raise ValueError('expected native software-stack-v3 RAW sample')
        raw = frame[12:652]
        period, address, time, source_cpu, pid, tid, reserved, task, ip, mode, version = struct.unpack_from('<QQQIIIIQQII', raw)
        if (source_cpu != cpu or not start <= time <= stop or reserved or version != 2
                or not period or not task or not ip or mode not in (1, 2)):
            raise ValueError('RAW CPU sample identity/version differs')
        payload = struct.pack('<QQQII', period, address, ip, mode, 0) + raw[64:]
        records.append(Record(0x1002, 3, time, cpu, pid, tid, task, payload))
    if frame_count != count or not records:
        raise ValueError('RAW envelope count differs or contains no samples')
    return records


def extract_indexed(bundle: Path, entry: dict, destination: Path) -> int:
    if digest(bundle) != entry['bundle_sha256']:
        raise ValueError('evidence bundle SHA-256 mismatch')
    expected = entry['members_sha256']
    with tarfile.open(bundle, 'r:gz') as stream:
        members = stream.getmembers()
        if len(members) != len(expected) or {member.name for member in members} != set(expected):
            raise ValueError('evidence member set differs from SHA index')
        for member in members:
            relative = Path(member.name)
            if not member.isfile() or relative.is_absolute() or '..' in relative.parts:
                raise ValueError('nonregular or unsafe evidence archive member')
            raw = stream.extractfile(member).read()
            if hashlib.sha256(raw).hexdigest() != expected[member.name]:
                raise ValueError('evidence member SHA-256 mismatch')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    return len(members)


def verify_acquisition(run: Path) -> dict:
    inputs = json.loads((run / 'inputs.json').read_text())
    original = json.loads((run / 'result.json').read_text())
    if inputs.get('context_format') != 'software-stack-v3' or original.get('qemu_exit') != 0:
        raise ValueError('evidence lacks native stack capture or successful QEMU completion')
    raw, metadata, stats = archive.extract((run / 'guest.log').read_text(), inputs['mode'])
    if raw != (run / 'records.pbraw').read_bytes() or json.loads(json.dumps(metadata)) != json.loads((run / 'archive.json').read_text()):
        raise ValueError('original serial stream differs from saved RAW/archive metadata')
    for point, value in stats.items():
        if value != (run / f'stats-{point}.txt').read_bytes():
            raise ValueError('saved counters differ from original serial proc snapshots')
    raw_rows = decode_stack_raw(raw)
    normalized, status = normalized_records((run / 'capture.pbcapture').read_bytes(), inputs['arch'])
    compare_records(raw_rows, normalized)
    for name, key in [('kernel.elf', 'kernel_elf_sha256'), ('payload.elf', 'payload_sha256')]:
        if digest(run / name) != inputs[key]:
            raise ValueError('executed ELF differs from recorded content identity')
    boot = run / 'kernel.elf'
    if inputs['arch'] == 'riscv64':
        boot = run / 'replay-kernel.bin'
        capture.command(['rust-objcopy', '--binary-architecture=riscv64', str(run / 'kernel.elf'), '--strip-all', '-O', 'binary', str(boot)])
    provenance = json.loads((run / 'kernel.provenance.json').read_text())
    boot_kind = 'binary' if inputs['arch'] == 'riscv64' else 'elf'
    if (digest(boot) != inputs['kernel_sha256']
            or provenance['artifacts']['elf']['sha256'] != digest(run / 'kernel.elf')
            or provenance['artifacts'][boot_kind]['sha256'] != digest(boot)):
        raise ValueError('ELF cannot reproduce kernel boot/provenance identity')
    build = json.loads((run / 'payload-build.json').read_text())
    for source, expected in build['source_inputs'].items():
        if digest(run / Path(source).name) != expected:
            raise ValueError('payload source differs from original build input')
    artifacts.verify(run)
    stacks = stack_evidence.verify(run)
    mappings = mapping_evidence.extract_and_verify(run, (run / 'guest.log').read_text())
    analyzer = str(capture.REPO / 'target/debug/bpf-analyzer')
    mapping_report = json.loads(capture.command([analyzer, str(run / 'capture.pbcapture'), '--mapping-report', '--bundle', str(run)]))
    agreement = mapping_evidence.check_report(run, mapping_report)
    fresh = run / 'replay-capture.pbcapture'
    capture.command([str(capture.REPO / 'target/debug/examples/runtime_import'), str(run), str(fresh)])
    reimported, fresh_status = normalized_records(fresh.read_bytes(), inputs['arch'])
    compare_records(raw_rows, reimported)
    if fresh_status != status:
        raise ValueError('reimport changed capture integrity status')
    return {'raw_samples': len(raw_rows), 'raw_normalized_equal': True,
            'reimport_normalized_equal': True, 'capture_status_code': status,
            'boot_reconstructed_from_elf': True, 'stack_counts': stacks['counts'],
            'mapping_counts': mappings['counts'], 'original_guest_gate_passed': original['passed'],
            'original_guest_gate_errors': original['errors'], **agreement}


def verify_index(evidence: Path, perf: Path | None = None, flamegraph: Path | None = None) -> dict:
    index = json.loads((evidence / 'index.json').read_text())
    if index.get('format') != 'pulse-real-perf-evidence' or index.get('format_version') != 1:
        raise ValueError('unsupported evidence index')
    result = {'format': 'pulse-perf-evidence-replay', 'version': 1, 'runs': {}}
    for name, entry in index['runs'].items():
        bundle_name = Path(entry['bundle'])
        if bundle_name.name != str(bundle_name):
            raise ValueError('bundle path must be local to evidence directory')
        with tempfile.TemporaryDirectory(prefix='pulse-194-replay-') as temporary:
            run = Path(temporary)
            members = extract_indexed(evidence / bundle_name, entry, run)
            acquisition = verify_acquisition(run)
            exported = verify_exports(run, perf, flamegraph)
            result['runs'][name] = {'members_verified': members, **acquisition, 'perf': exported}
    return result


def inside(run: Path, relative: str) -> Path:
    path = (run / relative).resolve(strict=True)
    if Path(relative).is_absolute() or not path.is_relative_to(run):
        raise ValueError('acceptance path escapes evidence bundle')
    return path


def verify_exports(run: Path, perf: Path | None, flamegraph: Path | None) -> dict:
    import perf_evidence
    acceptance = json.loads((run / 'acceptance-report.json').read_text())
    if acceptance.get('passed') is not True or not acceptance.get('cases'):
        raise ValueError('perf acceptance report is absent or failed')
    raw = (run / 'records.pbraw').read_bytes()
    reports = {}
    for case in acceptance['cases']:
        name = case['name']
        if not name or any(char not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for char in name) or name in reports:
            raise ValueError('invalid or duplicate perf acceptance case')
        data, manifest_path = inside(run, case['data']), inside(run, case['manifest'])
        saved = inside(run, case['pipeline'])
        manifest = json.loads(manifest_path.read_text())
        result = json.loads((saved / 'result.json').read_text())
        if (digest(data) != manifest['perf_data_sha256'] or digest(data) != result['perf_data_sha256']
                or digest(manifest_path) != result['manifest_sha256']
                or digest(run / 'capture.pbcapture') != manifest['capture_sha256']):
            raise ValueError('perf data/manifest/capture identities disagree')
        query = case['query']
        for key, value in query.items():
            if manifest['query'].get('task_id' if key == 'task' else key) != value:
                raise ValueError('perf acceptance query differs from exported query')
        unit = case['weight_unit']
        if unit != manifest['weight_unit'] or unit != result['weight_unit']:
            raise ValueError('perf acceptance units disagree')
        regenerated = run / f'reexported-{name}.data'
        argv = [str(capture.REPO / 'target/debug/bpf-analyzer'), str(run / 'capture.pbcapture'),
                '--bundle', str(run), '--perf-data', str(regenerated),
                '--weight', 'samples' if unit == 'samples' else 'period']
        for key, value in query.items():
            argv += ['--' + key.replace('_', '-'), str(value)]
        capture.command(argv)
        if (regenerated.read_bytes() != data.read_bytes()
                or Path(str(regenerated) + '.json').read_bytes() != manifest_path.read_bytes()):
            raise ValueError('current exporter differs from archived data or query provenance')
        checked = perf_evidence.verify(raw, (saved / 'dump.stdout').read_text(), query,
                                       (saved / 'report.stdout').read_text())
        if checked != case['verification']:
            raise ValueError('independent RAW/native-perf verification differs from saved acceptance')
        if case.get('function_ranges'):
            elf = run / ('kernel.elf' if query.get('mode') == 'kernel' else 'payload.elf')
            _, functions = stack_evidence.elf_symbols(elf)
            ranges = {}
            for function_name in case['function_ranges']:
                matches = [(start, end) for start, end, symbol in functions if symbol == function_name]
                if len(matches) != 1:
                    raise ValueError('expected function lacks unique verified ELF extent')
                ranges[function_name] = list(matches[0])
            if ranges != case['function_ranges']:
                raise ValueError('function weight ranges differ from actual ELF symbols')
            weights = perf_evidence.verify_function_weights(perf_evidence.raw_samples(raw, query),
                                                           checked['function_rows'], ranges)
            if weights != case['function_weights']:
                raise ValueError('native perf function weights differ from original RAW PCs')
        expected = manifest['sample_count'] if unit == 'samples' else manifest['total_period_ns']
        observed = pipeline.inspect_perf_script((saved / 'script.stdout').read_text())
        pipeline.inspect_buildids((saved / 'buildid-list.stdout').read_text(), manifest)
        if manifest.get('kernel_artifact_path'):
            original_elf = inside(run, manifest['kernel_artifact_path'])
            view = saved / 'kernel-symbols.elf'
            derived, hidden = symbols.hide_local_labels(original_elf.read_bytes())
            expected_view = {
                'transformation': symbols.TRANSFORMATION,
                'original_sha256': digest(original_elf),
                'derived_sha256': hashlib.sha256(derived).hexdigest(),
                'hidden_local_labels': hidden, 'load_bytes_unchanged': True,
                'function_symbols_unchanged': True,
            }
            if view.read_bytes() != derived or result['kernel_symbol_view'] != expected_view:
                raise ValueError('kernel symbol view differs from verified ELF visibility-only derivation')
        if (observed['sample_count'] != manifest['sample_count']
                or observed['total_period_ns'] != manifest['total_period_ns']
                or pipeline.inspect_folded((saved / 'flamegraph.folded').read_text()) != expected):
            raise ValueError('native script/folded totals differ from RAW-verified export')
        for symbol in case['expect_symbols']:
            if symbol not in observed['symbols']:
                raise ValueError('native perf lacks known workload function')
        if case.get('expect_chain'):
            perf_evidence.verify_named_chain((saved / 'script.stdout').read_text(),
                                            (saved / 'calltree.stdout').read_text(), case['expect_chain'])
        pipeline.inspect_svg((saved / 'flamegraph.svg').read_text(), expected, unit, case['expect_symbols'])
        if result['flamegraph'] != {'revision': pipeline.FLAMEGRAPH_REVISION, 'sha256': pipeline.FLAMEGRAPH_SHA256}:
            raise ValueError('saved FlameGraph consumer differs from pinned source')
        if perf is not None:
            fresh = run / f'replayed-{name}'
            args = argparse.Namespace(data=data, manifest=manifest_path, bundle=run,
                                      perf=perf.resolve(), flamegraph=flamegraph.resolve(),
                                      output=fresh, expect_symbol=case['expect_symbols'])
            pipeline.run_pipeline(args)
            repeated = perf_evidence.verify(raw, (fresh / 'dump.stdout').read_text(), query,
                                            (fresh / 'report.stdout').read_text())
            if repeated != checked:
                raise ValueError('fresh native consumers changed RAW/perf results')
            if case.get('expect_chain'):
                perf_evidence.verify_named_chain((fresh / 'script.stdout').read_text(),
                                                (fresh / 'calltree.stdout').read_text(), case['expect_chain'])
        reports[name] = {'weight_unit': unit, 'weight': expected,
                         'fresh_external_consumers': perf is not None, 'reexport_identical': True,
                         'known_call_tree_verified': bool(case.get('expect_chain')), **checked}
    return reports


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--perf', type=Path)
    parser.add_argument('--flamegraph', type=Path)
    args = parser.parse_args()
    if bool(args.perf) != bool(args.flamegraph):
        parser.error('--perf and --flamegraph must be provided together for fresh external consumers')
    if not args.no_build:
        capture.command(['cargo', 'build', '-p', 'bpf-capture', '--example', 'runtime_import'])
        capture.command(['cargo', 'build', '-p', 'bpf-analyzer'])
    result = verify_index(args.evidence.resolve(), args.perf, args.flamegraph)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
