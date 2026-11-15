"""Compare target fault records with QEMU's independent VirtIO read trace.

No timing threshold or kernel-provided classification is used as the I/O
oracle. The guest blocks on stdin at each boundary; the host records the trace
byte cursor before acknowledging it. debugfs bmap binds file pages to sectors.
Trace format: QEMU hw/block/trace-events, virtio_blk_handle_read/rw_complete.
https://github.com/qemu/qemu/blob/v9.2.0/hw/block/trace-events
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import struct
import tarfile
import tempfile
from verify_observation_evidence import check, compare_records, decode_capture, decode_raw, verify_faults

CASES=('anonymous','cold','hot','cow','cached_target_cold_neighbor','cold_neighbor')
LIFECYCLE_CASES={
    'prepared_pin_drop','fault_io_unsupported_and_error','fault_io_retry_and_cancel',
    'stale_file_replace','deferred_file_unmap','partial_file_unmap','partial_anonymous_unmap',
    'unused_file_mapping_drop','file_fork_cow','fault_io_owner_waiter',
    'fault_io_hot_target_cold_neighbor','fault_io_cancel_error_retry',
    'fault_io_unsupported_generation_retry','cache_identity_publication',
    'cache_write_failure_retry','cache_redirty_checkpoint','cache_durability_recovery',
    'cache_snapshot_identity_generations','fault_io_block_cache_neighbor','sync_failure_refuses_reset',
}
MARKER=re.compile(r'^FAULT_CLASS kind=(\w+) point=(begin|end) address=(\d+) pid=(\d+) tid=(\d+) time_ns=(\d+)[ \t]*\n',re.M)
READ=re.compile(r'virtio_blk_handle_read vdev (0x[0-9a-f]+) req (0x[0-9a-f]+) sector (\d+) nsectors (\d+)$')
COMPLETE=re.compile(r'virtio_blk_rw_complete vdev (0x[0-9a-f]+) req (0x[0-9a-f]+) ret (-?\d+)$')


class Boundaries:
    def __init__(self, run: Path):
        self.run=run
        self.rows=[]

    def __call__(self, text, stdin):
        matches=list(MARKER.finditer(text))
        for match in matches[len(self.rows):]:
            kind,point,address,pid,tid,time=match.groups()
            index=len(self.rows)
            check(index < 2*len(CASES) and kind==CASES[index//2]
                  and point==('begin' if index%2==0 else 'end'), 'fault boundary order changed')
            self.rows.append(dict(kind=kind,point=point,address=int(address),pid=int(pid),tid=int(tid),
                                  time_ns=int(time),trace_offset=(self.run/'device-reads.log').stat().st_size))
            (self.run/'fault-boundaries.json').write_text(json.dumps(self.rows,indent=2)+'\n')
            stdin.write(b'g\n');stdin.flush()


def prepare(image, guest_dir, run, helpers):
    data=bytes([0x41])*4096+bytes([0x42])*4096
    source=run/'fault-data'
    source.write_bytes(data)
    check(not any(c in str(source) for c in '\\"\n\r'),'unsupported fixture path')
    target=guest_dir+'/fault-data'
    helpers.debugfs(image,f'write "{source}" {target}',write=True)
    dumped=run/'fault-data-injected'
    helpers.debugfs(image,f'dump {target} "{dumped}"')
    check(dumped.read_bytes()==data,'injected fault data differs')
    dumped.unlink()
    with image.open('rb') as stream:
        stream.seek(1024+24)
        block_size=1024 << struct.unpack('<I',stream.read(4))[0]
    check(block_size in (1024,2048,4096),'unsupported ext4 block geometry')
    pages=[]
    bmap=[]
    for page in range(2):
        extents=[]
        for index in range(page*4096//block_size,(page+1)*4096//block_size):
            output=helpers.debugfs(image,f'bmap {target} {index}')
            bmap.append(output)
            values=re.findall(r'^([0-9]+)\s*$',output,re.M)
            check(len(values)==1 and int(values[0])>0,'fault fixture must not contain sparse blocks')
            extents.append([int(values[0])*block_size//512,block_size//512])
        pages.append(extents)
    layout=dict(path=target,page_bytes=4096,sector_bytes=512,block_bytes=block_size,
                pages=pages,sha256=hashlib.sha256(data).hexdigest())
    (run/'fault-file-layout.json').write_text(json.dumps(layout,indent=2)+'\n')
    (run/'fault-file-bmap.txt').write_text('\n'.join(bmap))
    return layout


def reads(data):
    pending={}; result=[]
    for line in data.decode().splitlines():
        read=READ.search(line)
        completed=COMPLETE.search(line)
        if read:
            dev,req,sector,count=read.groups()
            check((dev,req) not in pending,'device request reused before completion')
            pending[dev,req]=dict(sector=int(sector),sectors=int(count),completed=False)
            check(int(count)>0,'empty device read')
        elif completed:
            dev,req,ret=completed.groups()
            value=pending.pop((dev,req),None)
            if value is not None:
                value.update(completed=True,result=int(ret));result.append(value)
        else:
            check('virtio_blk_' not in line,'malformed device trace')
    return result+list(pending.values())


def overlap(request, extents):
    return sum(max(0,min(request['sector']+request['sectors'],first+count)
                   -max(request['sector'],first)) for first,count in extents)


def verify_cases(records, boundaries, trace, layout):
    check(len(boundaries)==2*len(CASES),'missing/duplicate fault boundaries')
    report={}
    last_time=last_offset=0
    for index,kind in enumerate(CASES):
        begin,end=boundaries[2*index:2*index+2]
        check(begin['kind']==end['kind']==kind and begin['point']=='begin' and end['point']=='end',
              'fault boundary order mismatch')
        check(0<begin['address']==end['address'] and begin['pid']==end['pid']>0
              and begin['tid']==end['tid']>0,'fault boundary identity mismatch')
        check(last_time<=begin['time_ns']<end['time_ns']
              and last_offset<=begin['trace_offset']<=end['trace_offset']<=len(trace),
              'fault boundary time/trace cursor invalid')
        last_time,last_offset=end['time_ns'],end['trace_offset']
        target=[]
        for record in records:
            if record.event!=8:continue
            address,start,elapsed,access,origin,outcome,classification=struct.unpack('<QQQIIII',record.payload)
            if address==begin['address'] and (record.pid,record.tid)==(begin['pid'],begin['tid']) \
                    and begin['time_ns']<=start<=record.time<=end['time_ns']:
                check(origin==2 and outcome==1 and elapsed==record.time-start,'target resolver not successfully completed')
                check(access & (2 if kind=='cow' else 1),'target access direction missing')
                check(classification==(2 if kind in ('cold','cold_neighbor') else 1),'target classification differs from device oracle')
                target.append(record)
        check(len(target)==1,'expected exactly one completed target fault per case')
        device=reads(trace[begin['trace_offset']:end['trace_offset']])
        target_sectors=neighbor_sectors=0
        for request in device:
            target_part=overlap(request,layout['pages'][0])
            neighbor_part=overlap(request,layout['pages'][1])
            if target_part or neighbor_part:
                check(request['completed'] and request['result']==0,'fixture device read did not complete successfully')
            target_sectors+=target_part;neighbor_sectors+=neighbor_part
        check((target_sectors>=8 if kind=='cold' else target_sectors==0),
              'target device-read evidence differs from workload expectation')
        check((neighbor_sectors>=8 if kind=='cold_neighbor' else neighbor_sectors==0),
              'neighbor device-read evidence differs from workload expectation')
        report[kind]=dict(classification='major' if kind in ('cold','cold_neighbor') else 'minor',address=begin['address'],
                          pid=begin['pid'],tid=begin['tid'],target_faults=1,target_read_sectors=target_sectors,
                          neighbor_read_sectors=neighbor_sectors,device_requests=device)
    # A supposedly cold page must not have already been read during boot/setup.
    before_cold=reads(trace[:boundaries[2]['trace_offset']])
    check(not any(overlap(request,layout['pages'][0]) or overlap(request,layout['pages'][1])
                  for request in before_cold),'cold fixture was read before the cold phase')
    return dict(kind='fault_classification_evidence',oracle='qemu_virtio_completed_reads',cases=report)


def verify(run):
    run=Path(run)
    inputs=json.loads((run/'inputs.json').read_text())
    records,_=decode_raw((run/'records.pbraw').read_bytes(),'fault')
    normalized,_=decode_capture((run/'capture.pbcapture').read_bytes(),inputs['arch'])
    compare_records(records,normalized)
    text=(run/'guest.log').read_text().replace('\r','')
    check(text.splitlines().count('FAULT_CLASS COMPLETE cases=6')==1,'workload did not complete all classification cases')
    boundaries=json.loads((run/'fault-boundaries.json').read_text())
    markers=list(MARKER.finditer(text))
    check(len(markers)==len(boundaries),'host boundaries differ from actual guest markers')
    for marker,row in zip(markers,boundaries):
        kind,point,address,pid,tid,time=marker.groups()
        check((kind,point,int(address),int(pid),int(tid),int(time)) ==
              tuple(row[key] for key in ('kind','point','address','pid','tid','time_ns')),
              'host boundary metadata differs from guest output')
    report=verify_cases(records,boundaries,(run/'device-reads.log').read_bytes(),
                        json.loads((run/'fault-file-layout.json').read_text()))
    archive=json.loads((run/'archive.json').read_text())
    report['fault_report']=verify_faults(run,records,archive)
    summary=json.loads((run/'faults-report.json').read_text())['faults']
    counts=dict(resolved_minor=0,resolved_major=0,resolved_unknown=0,unsuccessful=0)
    for record in records:
        outcome,classification=struct.unpack_from('<II',record.payload,32)
        key={0:'resolved_unknown',1:'resolved_minor',2:'resolved_major'}[classification] if outcome==1 else 'unsuccessful'
        counts[key]+=1
    check(all(summary.get(key)==value for key,value in counts.items()),
          'host success/error totals differ from RAW records')
    report['classification_counts']=counts
    lifecycle=re.findall(r'MLC_KERNEL PASS (\w+)',text)
    features=inputs.get('kernel_build_provenance',{}).get('configuration',{}).get('values',{}).get('features','')
    if 'mapping-lifecycle-test' in features.split():
        check(set(lifecycle)==LIFECYCLE_CASES and len(lifecycle)==len(LIFECYCLE_CASES)
              and 'MLC_KERNEL RESULT FAIL' not in text,'kernel lifecycle checks missing/failed')
    report['kernel_lifecycle_cases']=lifecycle
    report['arch']=inputs['arch']
    (run/'fault-classification-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def verify_index(directory):
    directory=Path(directory)
    index=json.loads((directory/'index.json').read_text())
    check(index['format']=='pulse-fault-classification-evidence' and index['version']==1,
          'unsupported classification evidence index')
    reports={}
    for name,entry in index['runs'].items():
        bundle=directory/entry['bundle']
        check(bundle.parent==directory and hashlib.sha256(bundle.read_bytes()).hexdigest()==entry['bundle_sha256'],
              'bundle path/hash mismatch')
        with tempfile.TemporaryDirectory(prefix='fault-evidence-') as temporary:
            root=Path(temporary)
            found=set()
            with tarfile.open(bundle,'r:gz') as archive:
                for member in archive:
                    check(member.isfile() and '/' not in member.name and member.name not in ('.','..')
                          and member.name not in found and member.name in entry['members_sha256']
                          and member.size<=64*1024*1024,'unsafe/unindexed evidence member')
                    found.add(member.name)
                    stream=archive.extractfile(member)
                    check(stream is not None,'missing evidence member body')
                    data=stream.read()
                    check(hashlib.sha256(data).hexdigest()==entry['members_sha256'][member.name],
                          'evidence member SHA mismatch')
                    (root/member.name).write_bytes(data)
            check(found==set(entry['members_sha256']),'evidence archive omitted indexed members')
            inputs=json.loads((root/'inputs.json').read_text())
            check(hashlib.sha256((root/'kernel.elf').read_bytes()).hexdigest()==inputs['kernel_elf_sha256'],
                  'kernel ELF identity mismatch')
            check(hashlib.sha256((root/'payload.elf').read_bytes()).hexdigest()==inputs['payload_sha256'],
                  'guest payload identity mismatch')
            layout=json.loads((root/'fault-file-layout.json').read_text())
            check(hashlib.sha256((root/'fault-data').read_bytes()).hexdigest()==layout['sha256'],
                  'fixture data identity mismatch')
            if entry['kind']=='red_baseline':
                records,_=decode_raw((root/'records.pbraw').read_bytes(),'fault')
                normalized,_=decode_capture((root/'capture.pbcapture').read_bytes(),inputs['arch'])
                compare_records(records,normalized)
                check(all(struct.unpack_from('<I',record.payload,36)[0]==0 for record in records),
                      'red baseline is not the original Unknown-classification capture')
                result=json.loads((root/'result.json').read_text())
                check(result['passed'] is False and any('target classification differs from device oracle' in e
                      for e in result['errors']),'baseline original failure is missing')
                reports[name]=dict(kind='red_baseline',unknown_records=len(records),expected_failure=result['errors'])
            else:
                check(entry['kind']=='acceptance','unknown bundle kind')
                reports[name]=verify(root)
    return reports


if __name__=='__main__':
    import sys
    path=Path(sys.argv[1])
    print(json.dumps(verify_index(path) if (path/'index.json').exists() else verify(path),indent=2))
