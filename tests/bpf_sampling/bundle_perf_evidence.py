#!/usr/bin/env python3
"""Package original captures and RAW-verified native perf/SVG evidence for #194."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

import capture
import verify_perf_evidence

FILES = (
    'guest.log records.pbraw capture.pbcapture archive.json inputs.json result.json '
    'acceptance-report.json capture-replay-result.json stack-evidence.json '
    'mapping-evidence.json mapping-report.json mapping-negative-report.json '
    'mappings.txt mappings-before.txt mappings-after.txt '
    'artifacts.json stats-before.txt stats-after.txt import.log '
    'analyzer.json analyzer-table.txt analyzer-loss.txt '
    'kernel.elf kernel.provenance.json payload.elf mapping-child.elf payload-build.json '
    'guest.rs mapping_guest.ld mapping_workload.rs stack_workload.rs archive.rs worktree.patch'
).split()


def create_bundle(run: Path, destination: Path) -> dict:
    acceptance = json.loads((run / 'acceptance-report.json').read_text())
    if acceptance.get('passed') is not True or not acceptance.get('cases'):
        raise ValueError('cannot package absent or failing perf acceptance')
    paths = {name: run / name for name in FILES}
    for directory in ('artifacts', 'perf'):
        for path in (run / directory).rglob('*'):
            if path.is_symlink():
                raise ValueError('symlink is not self-contained evidence')
            if path.is_file():
                paths[str(path.relative_to(run))] = path
    members = {}
    # Every member is read before publishing an archive, so absent original
    # evidence cannot leave a plausible partial acceptance bundle.
    payloads = {name: path.read_bytes() for name, path in paths.items()}
    with destination.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as stream:
                for name, data in sorted(payloads.items()):
                    members[name] = hashlib.sha256(data).hexdigest()
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    stream.addfile(info, io.BytesIO(data))
    return members


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='append', required=True, metavar='NAME=PATH')
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    parser.add_argument('--perf', required=True, type=Path)
    parser.add_argument('--flamegraph', required=True, type=Path)
    parser.add_argument('--no-build', action='store_true')
    args = parser.parse_args()
    if not args.no_build:
        capture.command(['cargo', 'build', '-p', 'bpf-capture', '--example', 'runtime_import'])
        capture.command(['cargo', 'build', '-p', 'bpf-analyzer'])
    args.output.mkdir(parents=True, exist_ok=False)
    index = {'format': 'pulse-real-perf-evidence', 'format_version': 1,
             'date': '2026-11-15', 'runs': {}}
    for value in args.run:
        name, raw_path = value.split('=', 1)
        if not name or any(char not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for char in name) or name in index['runs']:
            raise ValueError('invalid or duplicate evidence bundle name')
        run = Path(raw_path).resolve()
        bundle = args.output / f'{name}.tar.gz'
        members = create_bundle(run, bundle)
        original = json.loads((run / 'result.json').read_text())
        native = json.loads((run / 'archive.json').read_text())
        acceptance = json.loads((run / 'acceptance-report.json').read_text())
        index['runs'][name] = {
            'run': str(run.relative_to(capture.REPO)), 'bundle': bundle.name,
            'bundle_sha256': verify_perf_evidence.digest(bundle), 'members_sha256': members,
            'original_guest_gate_passed': original['passed'], 'original_guest_gate_errors': original['errors'],
            'perf_acceptance_passed': True, 'raw_samples': native['samples'],
            'transport_lost': native['transport_lost'], 'export_dropped': native['export_dropped'],
            'cases': [{key: case[key] for key in ('name', 'query', 'weight_unit', 'verification')}
                      for case in acceptance['cases']],
        }
    index_path = args.output / 'index.json'
    index_path.write_text(json.dumps(index, indent=2) + '\n')
    replay = verify_perf_evidence.verify_index(args.output.resolve(), args.perf, args.flamegraph)
    replay_path = args.output / 'replay-report.json'
    replay_path.write_text(json.dumps(replay, indent=2) + '\n')
    index['independent_replay'] = {'file': replay_path.name, 'sha256': verify_perf_evidence.digest(replay_path)}
    index_path.write_text(json.dumps(index, indent=2) + '\n')
    print(json.dumps(replay, indent=2))


if __name__ == '__main__':
    main()
