#!/usr/bin/env python3
"""Archive authentic #196 before/after runs without copying rootfs images."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import fault_class_evidence

FILES=('guest.log records.pbraw capture.pbcapture archive.json inputs.json result.json '
       'device-reads.log device-events.txt fault-boundaries.json fault-file-layout.json '
       'fault-file-bmap.txt fault-data faults-report.json faults-report.txt stats-before.txt '
       'stats-after.txt analyzer.json analyzer-table.txt analyzer-loss.txt import.log '
       'kernel.elf kernel.provenance.json payload.elf payload-build.json guest.rs guest.ld '
       'archive.rs fault_workload.rs fault_classes.rs worktree.patch').split()


def bundle(name,run,output):
    result=json.loads((run/'result.json').read_text())
    baseline=name.endswith('-baseline')
    if baseline:
        if result.get('passed') is not False or not any('target classification differs from device oracle' in e for e in result['errors']):
            raise ValueError('baseline must fail for its actual Unknown classification')
    else:
        if result.get('passed') is not True or result.get('errors'):
            raise ValueError('acceptance evidence must be a passing run')
        fault_class_evidence.verify(run)
    paths={name:run/name for name in FILES}
    extra='baseline-oracle.py' if baseline else 'fault-classification-evidence.json'
    paths[extra]=run/extra
    archive=output/(name+'.tar.gz')
    hashes={}
    with archive.open('wb') as destination:
        with gzip.GzipFile(filename='',mode='wb',fileobj=destination,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as tar:
                for member,path in sorted(paths.items()):
                    data=path.read_bytes();hashes[member]=hashlib.sha256(data).hexdigest()
                    info=tarfile.TarInfo(member)
                    info.size,info.mode,info.mtime=len(data),0o644,0
                    tar.addfile(info,io.BytesIO(data))
    inputs=json.loads((run/'inputs.json').read_text())
    return dict(bundle=archive.name,bundle_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                members_sha256=hashes,kind='red_baseline' if baseline else 'acceptance',
                arch=inputs['arch'],run=str(run),kernel_sha256=inputs['kernel_sha256'],
                kernel_elf_sha256=inputs['kernel_elf_sha256'],passed=result['passed'],errors=result['errors'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='append',required=True,metavar='NAME=PATH')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    index=dict(format='pulse-fault-classification-evidence',version=1,date='2026-11-15',runs={})
    for item in args.run:
        name,path=item.split('=',1)
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name) or name in index['runs']:
            raise ValueError('invalid or duplicate bundle name')
        index['runs'][name]=bundle(name,Path(path),args.output)
    (args.output/'index.json').write_text(json.dumps(index,indent=2)+'\n')
    replay=fault_class_evidence.verify_index(args.output)
    report=args.output/'replay-report.json'
    report.write_text(json.dumps(replay,indent=2)+'\n')
    index['independent_replay']=dict(file=report.name,sha256=hashlib.sha256(report.read_bytes()).hexdigest())
    (args.output/'index.json').write_text(json.dumps(index,indent=2)+'\n')


if __name__=='__main__':main()
