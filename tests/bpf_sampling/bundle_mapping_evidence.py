#!/usr/bin/env python3
"""Create deterministic, self-contained #193 evidence archives from passing runs."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

import capture
import verify_mapping_evidence


FILES = (
    'guest.log records.pbraw capture.pbcapture archive.json inputs.json result.json '
    'mapping-evidence.json mapping-report.json mapping-negative-report.json '
    'mappings.txt mappings-before.txt mappings-after.txt artifacts.json '
    'stats-before.txt stats-after.txt analyzer.json analyzer-table.txt analyzer-loss.txt import.log '
    'kernel.elf kernel.provenance.json payload.elf mapping-child.elf payload-build.json '
    'guest.rs mapping_guest.ld mapping_workload.rs archive.rs worktree.patch'
).split()


def create_bundle(run: Path, destination: Path) -> dict:
    # Fail before publishing if the acquisition capture predates the final v4
    # decoder. Such a run requires explicit separate replay, never replacement
    # of original capture/result files by this archival command.
    analyzer = str(capture.REPO / 'target/debug/bpf-analyzer')
    capture.command([analyzer, str(run / 'capture.pbcapture'), '--json'])
    paths = {name: run / name for name in FILES}
    paths.update({str(path.relative_to(run)): path for path in (run / 'artifacts').glob('*.elf')})
    members = {}
    with destination.open('wb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, path in sorted(paths.items()):
                    data = path.read_bytes()
                    members[name] = hashlib.sha256(data).hexdigest()
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    archive.addfile(info, io.BytesIO(data))
    return members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='append', required=True, metavar='NAME=PATH')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    capture.command(['cargo', 'build', '-p', 'bpf-capture', '--example', 'runtime_import'])
    capture.command(['cargo', 'build', '-p', 'bpf-analyzer'])
    args.output.mkdir(parents=True, exist_ok=True)
    index = {'format': 'pulse-real-mapping-capture-evidence', 'format_version': 1,
             'date': '2026-11-15', 'runs': {}}
    for value in args.run:
        name, raw_path = value.split('=', 1)
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name) or name in index['runs']:
            raise ValueError('invalid or duplicate evidence bundle name')
        run = Path(raw_path).resolve()
        result = json.loads((run / 'result.json').read_text())
        if result.get('passed') is not True or result.get('errors'):
            raise ValueError('cannot archive a failed run as acceptance evidence')
        bundle = args.output / f'{name}.tar.gz'
        members = create_bundle(run, bundle)
        evidence = json.loads((run / 'mapping-evidence.json').read_text())
        native = json.loads((run / 'archive.json').read_text())
        inputs = json.loads((run / 'inputs.json').read_text())
        index['runs'][name] = {'run': str(run.relative_to(capture.REPO)),
            'bundle': bundle.name, 'bundle_sha256': verify_mapping_evidence.digest(bundle),
            'members_sha256': members, 'analysis_capture': 'capture.pbcapture',
            'passed': True, 'samples': native['samples'], 'quality': native['quality'],
            'transport_lost': native['transport_lost'], 'export_dropped': native['export_dropped'],
            'phase_counts': evidence['counts'], 'resolved_counts': evidence['resolved_counts'],
            'completed_tlb_tokens': evidence['completed_tlb_tokens'],
            'kernel_relocation': evidence['kernel_relocation'],
            'kernel_build_source': inputs['kernel_build_provenance']['source'],
            'kernel_elf_sha256': inputs['kernel_elf_sha256'], 'measurements': native['measurements']}
    index_path = args.output / 'index.json'
    index_path.write_text(json.dumps(index, indent=2) + '\n')
    replay = verify_mapping_evidence.verify_index(args.output.resolve())
    replay_path = args.output / 'replay-report.json'
    replay_path.write_text(json.dumps(replay, indent=2) + '\n')
    index['independent_replay'] = {'file': replay_path.name, 'sha256': verify_mapping_evidence.digest(replay_path)}
    index_path.write_text(json.dumps(index, indent=2) + '\n')
    print(json.dumps(replay, indent=2))


if __name__ == '__main__':
    main()
