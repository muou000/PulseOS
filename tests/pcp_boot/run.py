#!/usr/bin/env python3
"""Diagnose the real boot PCP assertions, stopping at their precise final marker.

Every requested boot is retained. Any failed boot makes the batch fail; this is
not a retry-until-green runner. No guest injection or backing-image mutation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time

BASE=Path(__file__).resolve().parent
PASS=b'[PCP_GUEST] All PCP cache & watermark checks PASSED!'

def boot(command, path, timeout, require_early):
    started=time.monotonic()
    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    assert proc.stdout is not None
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
    data=bytearray();finish_at=None;verdict=None
    try:
        while time.monotonic()-started < timeout:
            for key,_ in selector.select(0.25):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                data.extend(chunk)
            raw=bytes(data)
            if len(raw)>8*1024*1024:
                verdict='output_limit';break
            text=raw.decode(errors='replace')
            for line in text.splitlines():
                if line.startswith('qemu-system-') and re.search(r'Permission denied|Read-only file system|Operation not permitted',line):
                    raise PermissionError(line)
            if verdict is None:
                if b'panicked at' in raw or b'kernel panic' in raw:
                    verdict='pcp_assertion' if b'panicked at modules/axalloc/src/buddy_slab.rs:' in raw else 'other_panic'
                    finish_at=time.monotonic()+0.2
                elif PASS in raw:
                    verdict='pcp_pass';finish_at=time.monotonic()+0.02
            if finish_at is not None and time.monotonic()>=finish_at:
                break
            if proc.poll() is not None and not selector.get_map():
                break
        if verdict is None:verdict='timeout' if proc.poll() is None else 'exited_before_marker'
    finally:
        selector.close()
        if proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
        # Preserve already-read bytes even on diagnostic errors.
        path.write_bytes(data)
        proc.stdout.close()
        if proc.stdin is not None:proc.stdin.close()
    if verdict in ('pcp_assertion','other_panic'):
        # The first read may contain only the panic prefix. Classify from the
        # complete grace-period output, not that possibly fragmented prefix.
        verdict='pcp_assertion' if (b'[PCP_GUEST] Starting' in data and
            b'panicked at modules/axalloc/src/buddy_slab.rs:' in data) else 'other_panic'
    if verdict=='pcp_pass' and require_early:
        raw=bytes(data)
        start=raw.find(b'[PCP_GUEST] Starting')
        finish=raw.find(PASS)+len(PASS)
        primary=re.search(rb'Primary CPU [0-9]+ init OK\.',raw)
        if start<0 or primary is None or primary.start()<finish:
            verdict='unsafe_startup_order'
        initialized={int(cpu,16) for cpu in re.findall(rb'Secondary CPU ([0-9a-f]+) init OK\.',raw[:max(0,start)])}
        if b'[PCP_GUEST] Active CPU count: 8' not in raw or len(initialized)!=7:
            verdict='missing_initialized_cpus'
        for marker in (b'itimer hook registered',b'[BPF_GUEST]',b'[FUTEX_GUEST]',b'[PROC_REG_GUEST]'):
            prior=raw.find(marker)
            if prior>=0 and (start<0 or prior<start):verdict='unsafe_startup_order'
    elapsed=time.monotonic()-started
    clean=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',data.decode(errors='replace')).replace('\r','')
    context=[]
    lines=clean.splitlines()
    for i,line in enumerate(lines):
        if '[PCP_GUEST]' in line or '[DEBUG-PCP]' in line or 'panicked at' in line:
            context.extend(lines[i:i+6] if 'panicked at' in line else [line])
    return {'verdict':verdict,'elapsed_seconds':elapsed,'qemu_exit':proc.returncode,'signal_lines':context}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--arch',choices=['riscv64','loongarch64'],required=True)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--runs',type=int,default=1)
    p.add_argument('--timeout',type=float,default=30)
    p.add_argument('--label',default='boot')
    p.add_argument('--require-early',action='store_true',help='require eight initialized caches and PCP completion before the primary release marker/application workers')
    a=p.parse_args()
    if not 1<=a.runs<=100:p.error('--runs must be 1..100')
    if not re.fullmatch(r'[a-zA-Z0-9_-]+',a.label):p.error('invalid label')
    kernel=a.kernel.resolve(strict=True);image=a.image.resolve(strict=True)
    qemu=shutil.which('qemu-system-'+a.arch)
    if not qemu:raise ValueError('missing target QEMU')
    folder=BASE/'runs';folder.mkdir(exist_ok=True)
    output=Path(tempfile.mkdtemp(prefix=a.label+'-',dir=folder))
    command=[qemu,'-machine','virt','-kernel',str(kernel),'-m','8G','-nographic','-smp','8']
    if a.arch=='riscv64':command+=['-bios','default']
    command+=['-drive',f'file={image},if=none,format=raw,id=x0,snapshot=on']
    if a.arch=='riscv64':command+=['-device','virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0','-no-reboot','-device','virtio-net-device,netdev=net','-netdev','user,id=net']
    else:command+=['-device','virtio-blk-pci,drive=x0','-no-reboot','-device','virtio-net-pci,netdev=net0','-netdev','user,id=net0']
    command+=['-rtc','base=utc']
    print('Evidence:',output,flush=True)
    inputs={'command':command,'kernel_sha256':hashlib.sha256(kernel.read_bytes()).hexdigest(),
            'image':str(image),'image_bytes':image.stat().st_size,'runs':a.runs,'timeout':a.timeout,'require_early':a.require_early}
    (output/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    results=[]
    for i in range(a.runs):
        result=boot(command,output/f'boot-{i:03}.log',a.timeout,a.require_early);results.append(result)
        (output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        print(f"boot={i} verdict={result['verdict']} seconds={result['elapsed_seconds']:.3f}",flush=True)
        if result['verdict']!='pcp_pass':
            print('\n'.join(result['signal_lines'][-8:]),flush=True)
    passed=sum(r['verdict']=='pcp_pass' for r in results)
    print(f'PCP_BATCH passed={passed} failed={len(results)-passed} total={len(results)} evidence={output}',flush=True)
    return int(passed!=len(results))

if __name__=='__main__':raise SystemExit(main())
