"""Convert verified runtime records through the Rust writer and host analyzer."""
from pathlib import Path
import hashlib
import json
import subprocess

REPO = Path(__file__).resolve().parents[2]


def command(args: list[str]) -> str:
    result = subprocess.run(args, cwd=REPO, text=True, capture_output=True, timeout=120)
    # Permission errors are not recoverable by changing output directories.
    if 'Permission denied' in result.stderr or 'Read-only file system' in result.stderr:
        raise PermissionError(result.stderr[-2000:])
    if result.returncode:
        raise ValueError(f"capture command failed ({result.returncode}): {args}\n{result.stderr[-2000:]}")
    return result.stdout


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            result.update(chunk)
    return result.hexdigest()


def convert(run: Path) -> dict:
    inputs = json.loads((run / 'inputs.json').read_text())
    archive = json.loads((run / 'archive.json').read_text())
    for name, key in [('kernel', 'kernel_sha256'), ('kernel.elf', 'kernel_elf_sha256'), ('disk.img', 'boot_image_sha256')]:
        if digest(run / name) != inputs[key]:
            raise ValueError(f"saved {name} differs from captured artifact identity")
    command(['cargo', 'build', '-p', 'bpf-capture', '--example', 'runtime_import'])
    command(['cargo', 'build', '-p', 'bpf-analyzer'])
    path = run / 'capture.pbcapture'
    converted = command([str(REPO/'target/debug/examples/runtime_import'), str(run), str(path)])
    (run/'import.log').write_text(converted)
    analyzer = str(REPO/'target/debug/bpf-analyzer')
    summary = command([analyzer, str(path), '--json'])
    report = command([analyzer, str(path), '--loss'])
    table = command([analyzer, str(path), '--table'])
    result = json.loads(summary)
    if result['records_count'] != archive['samples'] or result['records_count'] == 0:
        raise ValueError('normalized capture differs from actual consumed sample count')
    if result['attribution_claim_allowed']:
        raise ValueError('runtime capture claimed unsupported complete attribution')
    if inputs.get('fault') == 'export-overflow' and (archive['export_dropped'] == 0 or result['is_complete']):
        raise ValueError('overflow injection did not produce an incomplete capture')
    if inputs.get('fault') == 'ring-overflow' and (not any(
            issue['scope'] == 'transport' and issue['delta'] > 0 for issue in archive['observed_issues']) or result['is_complete']):
        raise ValueError('ring overflow injection did not produce an incomplete capture with real transport loss')
    semantic = None
    if inputs['mode'] in ('sched','fault'):
        name = 'scheduler' if inputs['mode']=='sched' else 'faults'
        flag = '--sched-report' if inputs['mode']=='sched' else '--fault-report'
        raw_report = command([analyzer,str(path),flag,'--json'])
        semantic_report = json.loads(raw_report)[name]
        valid = semantic_report['summary']['count'] if name=='scheduler' else semantic_report['valid_events']
        if valid == 0:
            raise ValueError(f'capture has no valid {name} instances')
        (run/f'{name}-report.json').write_text(raw_report+'\n')
        (run/f'{name}-report.txt').write_text(command([analyzer,str(path),flag]))
        semantic = {'report':name, 'valid_instances':valid}
    (run/'analyzer.json').write_text(summary + '\n')
    (run/'analyzer-loss.txt').write_text(report)
    (run/'analyzer-table.txt').write_text(table)
    return {'path': str(path), 'sha256': digest(path), 'records': result['records_count'],
            'status': result['status'], 'attribution_claim_allowed': result['attribution_claim_allowed'], 'semantic_report': semantic}
