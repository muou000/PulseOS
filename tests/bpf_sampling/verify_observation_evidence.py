#!/usr/bin/env python3
"""Independently check one run directory or a JSON run list (standard library only).

RAW/capture checksums, fields, payloads and semantic witnesses are decoded with
struct/zlib. No capture/analyzer/harness library is imported. This verifies
offline evidence consistency, NOT guest production or build provenance. Reports
must be full/unfiltered. Capture metadata content remains opaque to this oracle.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import zlib

LIMIT = 32 * 1024 * 1024
U64_MAX = (1 << 64) - 1
TRACE_BYTES = {1:72, 2:72, 3:72, 4:80, 5:56, 6:64, 7:64, 8:80}
TRACE_IDS = {'trace':{2}, 'block':{3}, 'wake':{4}, 'sched':set(range(1,7)), 'fault':{8}}
STATUS = {0:'Complete', 1:'IncompleteLoss', 2:'IncompleteTruncated', 3:'IncompleteError'}

class Rejected(ValueError): pass

def check(condition, message):
    if not condition: raise Rejected(message)

def uint(value):
    check(type(value) is int and 0 <= value <= U64_MAX, 'expected unsigned u64')
    return value

def read(path):
    with path.open('rb') as stream: value = stream.read(LIMIT + 1)
    check(len(value) <= LIMIT, f'{path.name} exceeds evidence size bound')
    return value

def unique_object(pairs):
    result = {}
    for key,value in pairs:
        check(key not in result, f'duplicate JSON field: {key}')
        result[key] = value
    return result

def load(path): return json.loads(read(path), object_pairs_hook=unique_object)

def unpack(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    check(0 <= offset <= len(data) and size <= len(data)-offset, 'truncated binary structure')
    return struct.unpack_from(fmt, data, offset)

@dataclass(frozen=True)
class Record:
    event: int
    version: int
    time: int
    cpu: int
    pid: int
    tid: int
    task: int
    payload: bytes

def decode_raw(data, mode):
    magic,start,stop,count,size,crc,dropped,reserved = unpack('<8sQQQQII16s', data)
    check(magic == b'PBRW0001' and reserved == bytes(16), 'unsupported RAW header')
    check(0 < start < stop and count > 0, 'empty RAW capture or bad time window')
    check(size == len(data)-64 and zlib.crc32(data[64:]) == crc, 'RAW stream size/CRC mismatch')
    check(mode in TRACE_IDS or mode in ('task','cpu'), 'unknown native mode')
    records,position,frames,lost = [],64,0,0
    while position < len(data):
        seq,cpu,length,crc,reserved = unpack('<QIIII', data, position); position += 24
        check(seq == frames and cpu < 8 and reserved == 0, 'RAW sequence/CPU/reserved mismatch')
        check(8 <= length <= 120 and length <= len(data)-position, 'RAW frame length invalid')
        frame = data[position:position+length]; position += length
        kind,_misc,declared = unpack('<IHH',frame)
        check(declared == length and length % 8 == 0 and zlib.crc32(frame) == crc, 'perf frame boundary/CRC mismatch')
        if kind == 2:
            check(length == 24, 'bad LOST frame')
            lost += unpack('<Q',frame,16)[0]
        else:
            check(kind == 9 and length >= 12, 'unknown perf record')
            n = unpack('<I',frame,8)[0]
            check(12+n <= length <= 19+n, 'RAW context size/padding mismatch')
            magic, version, source_kind, context_size, logical_id, reserved = unpack('<IHHIIQ', frame, 12)
            check(magic == 0x31524250 and version == 1 and logical_id > 0 and reserved == 0
                  and context_size + 24 == n, 'missing or invalid explicit logical source envelope')
            check(source_kind == (1 if mode in ('task', 'cpu') else 2), 'source kind mismatch')
            context = frame[36:12+n]
            n = context_size
            if mode in ('task','cpu'):
                check(n == 64, 'software v2 context must be 64 bytes')
                period,address,time,source_cpu,pid,tid,reserved,task,ip,privilege,version = unpack('<QQQIIIIQQII',context)
                check(version == 2 and privilege in (1,2) and reserved == 0 and period > 0 and ip > 0 and task > 0, 'invalid software v2 fields')
                check(privilege != 2 or (pid > 0 and tid > 0), 'user sample identity missing')
                # Address and IP occupy separate normalized payload fields.
                record = Record(0x1001,2,time,source_cpu,pid,tid,task,struct.pack('<QQQII',period,address,ip,privilege,0))
            else:
                event,version,time,source_cpu,pid,tid,reserved,task = unpack('<IIQIIIIQ',context)
                check(event in TRACE_IDS[mode] and n == TRACE_BYTES[event] and version == 1 and reserved == 0, 'trace context/ID/version mismatch')
                record = Record(event,version,time,source_cpu,pid,tid,task,context[40:])
            check(record.cpu == cpu and start <= record.time <= stop, 'sample source CPU/time mismatch')
            records.append(record)
        frames += 1
    check(frames == count and records, 'RAW count mismatch or no real samples')
    return records,dict(start_ns=start,stop_ns=stop,frames=frames,samples=len(records),transport_lost=lost,export_dropped=dropped)

def decode_capture(data, arch):
    magic,version,schema,header_size,target,meta_start,meta_len,record_start,count,record_len,tail_start,tail_len = unpack('<8sIIIIQQQQQQQ',data)
    check(magic == b'PBCAP001' and version == 6 and schema == 1, 'oracle requires capture format 6/schema 1')
    check(target == {'riscv64':1,'loongarch64':2}[arch], 'capture architecture mismatch')
    check(header_size == meta_start == 80 and meta_len > 0 and record_start == meta_start+meta_len, 'capture metadata ordering invalid')
    check(tail_start == record_start+record_len and tail_len == 40 and tail_start+40 == len(data), 'capture boundaries/trailer invalid')
    magic,tail_count,tail_bytes,crc,status,tail_size,reserved = unpack('<8sQQIIII',data,tail_start)
    check(magic == b'PBCAPTRL' and tail_size == 40 and reserved == 0 and status in STATUS, 'capture trailer shape invalid')
    check((tail_count,tail_bytes) == (count,record_len) and zlib.crc32(data[:tail_start]) == crc, 'capture count/IEEE CRC mismatch')
    check(count <= record_len//48, 'impossible normalized record count')
    records,position = [],record_start
    while position < tail_start:
        check(position+48 <= tail_start, 'truncated normalized header')
        event,schema,time,cpu,pid,tid,reserved,task,size,pad = unpack('<IIQIIIIQII',data,position); position += 48
        check(reserved == pad == 0 and size <= tail_start-position, 'normalized reserved/payload bound invalid')
        records.append(Record(event,schema,time,cpu,pid,tid,task,data[position:position+size])); position += size
    check(position == tail_start and len(records) == count, 'normalized count mismatch')
    return records,status

def compare_records(raw, normalized):
    check(len(raw) == len(normalized), 'RAW/normalized count mismatch')
    for index,(source,record) in enumerate(zip(raw,normalized)):
        check(source == record, f'RAW -> normalized record {index}: altered time/identity/schema/payload')

def full_report(wrapper, count):
    query = wrapper['query']
    for key in ('phase','mode','from_ns','to_ns','task_id','pid','tid','cpu','address_start','address_end'):
        check(query[key] is None, 'oracle requires an unfiltered full-run report')
    check(query['empty_window'] is False, 'semantic query is empty')
    check(uint(wrapper['selected_records_count']) == count and uint(wrapper['context_records_count']) == 0, 'semantic report omitted selected/context records')

def summary_numbers(summary, values, *, string_sum=False):
    check(uint(summary['count']) == len(values), 'summary count mismatch')
    for key,expected in [('min_ns',min(values) if values else None),('max_ns',max(values) if values else None)]:
        check(summary[key] is None if expected is None else uint(summary[key]) == expected, f'summary {key} mismatch')
    total = summary['sum_ns']
    if string_sum:
        check(type(total) is str and total.isdecimal(), 'scheduler sum is not an exact decimal string')
        total = int(total)
    check(type(total) is int and total == sum(values), 'summary sum mismatch')
    mean = summary['mean_ns']
    if values:
        check(type(mean) in (int,float) and math.isfinite(mean) and math.isclose(mean,sum(values)/len(values),rel_tol=1e-12), 'summary mean mismatch')
    else: check(mean is None, 'empty mean must remain unknown/null')

def scheduler_summary(summary, values):
    summary_numbers(summary,values,string_sum=True)
    ordered = sorted(values)
    for p in (50,95,99):
        expected = ordered[(len(ordered)*p+99)//100-1] if ordered else None
        check(summary[f'p{p}_ns'] == expected, f'scheduler p{p} mismatch')
    bounds = [1000,10000,100000,1000000,10000000,100000000,1000000000,None]
    check([row['upper_bound_ns'] for row in summary['histogram']] == bounds, 'scheduler histogram bounds mismatch')
    counts = [0]*len(bounds)
    for value in values: counts[next(i for i,bound in enumerate(bounds) if bound is None or value <= bound)] += 1
    check([uint(row['count']) for row in summary['histogram']] == counts, 'scheduler histogram count mismatch')

def verify_scheduler(run, records):
    wrapper = load(run/'scheduler-report.json'); full_report(wrapper,len(records))
    report = wrapper['scheduler']
    check(report['report'] == 'scheduler' and report['unit'] == 'nanoseconds', 'scheduler report kind/unit mismatch')
    check(report['complete_attribution'] is False, 'native partial evidence claimed complete scheduler attribution')
    blocks,wakes,switches,exits = defaultdict(list),defaultdict(list),[],[]
    for record in records:
        if record.event == 3:
            seq,reason,_pad,_resource,_detail = unpack('<QIIQQ',record.payload)
            blocks[(record.task,seq,record.time)].append((record,reason))
        elif record.event == 4:
            target,seq,waker,source,_pad,_source_id = unpack('<QQQIIQ',record.payload)
            check(record.task == waker, 'wake common task differs from recorded waker')
            wakes[(target,seq,record.time)].append((record,waker,source))
        elif record.event == 2:
            prev,next_task,state,_pp,_np,_pad = unpack('<QQIIII',record.payload)
            switches.append((record.time,record.cpu,prev,next_task,state))
        elif record.event == 5:
            task,_code,_pad = unpack('<QiI',record.payload); exits.append((record.time,task))
    samples = report['wake_latencies']
    check(len(samples) > 0, 'scheduler gate has no valid instances')
    used,delays,by_task = set(),[],defaultdict(list)
    for index,sample in enumerate(samples):
        label = f'scheduler instance {index}'
        task,seq,b,w,r = (uint(sample[key]) for key in ('task_id','block_sequence','block_ns','wake_ns','switch_ns'))
        check((task,seq) not in used and b < w < r, f'{label}: duplicate episode or invalid time ordering')
        used.add((task,seq))
        candidates = blocks[(task,seq,b)]
        check(candidates, f'{label}: missing raw TaskBlock')
        check(any(b < time < w and prev == task and state == 3 and cpu == block.cpu
                  for block,_reason in candidates for time,cpu,prev,_next,state in switches),
              f'{label}: no Blocked switch-out on block CPU between block and wake')
        check(any(wake.cpu == uint(sample['wake_cpu']) and waker == uint(sample['waker_task_id']) and source == uint(sample['wake_source'])
                  for wake,waker,source in wakes[(task,seq,w)]), f'{label}: missing matching TaskWake')
        check(any(time == r and cpu == uint(sample['run_cpu']) and next_task == task
                  for time,cpu,_prev,next_task,_state in switches), f'{label}: missing switch-in')
        check(not any(w < time < r and next_task == task for time,_cpu,_prev,next_task,_state in switches), f'{label}: unrelated later switch-in')
        check(not any(b <= time <= r and exited == task for time,exited in exits), f'{label}: task exited during episode')
        check(uint(sample['blocked_wait_ns']) == w-b and uint(sample['wake_to_switch_ns']) == r-w, f'{label}: duration differs from raw timestamps')
        delays.append(r-w); by_task[str(task)].append(r-w)
    scheduler_summary(report['summary'],delays)
    check(set(report['by_task']) == set(by_task), 'scheduler per-task summary coverage mismatch')
    for task,values in by_task.items(): scheduler_summary(report['by_task'][task],values)
    for index,wait in enumerate(report['blocked_waits']):
        task,seq,b,w = (uint(wait[key]) for key in ('task_id','block_sequence','block_ns','wake_ns'))
        check(b <= w and uint(wait['duration_ns']) == w-b, f'blocked interval {index}: time mismatch')
        check(any(reason == wait['wait_reason'] for _block,reason in blocks[(task,seq,b)]), f'blocked interval {index}: missing block')
        check(wakes[(task,seq,w)], f'blocked interval {index}: missing wake')
    return dict(valid_instances=len(samples),blocked_pairs=len(report['blocked_waits']),wake_to_switch_sum_ns=sum(delays))

def fault_duration(summary, values):
    summary_numbers(summary,values)
    expected = Counter(0 if value == 0 else min(1 << (value-1).bit_length(),U64_MAX) for value in values)
    actual = [(uint(row['upper_ns']),uint(row['count'])) for row in summary['histogram_ns']]
    check(actual == sorted(expected.items()), 'fault duration histogram mismatch')

def optional_uint(value): return None if value is None else uint(value)

def verify_faults(run, records, archive):
    wrapper = load(run/'faults-report.json'); full_report(wrapper,len(records))
    report = wrapper['faults']
    check(report['kind'] == 'fault_report' and report['duration_semantics'] == 'resolver_wall_time' and report['time_unit'] == 'ns', 'fault report kind/unit mismatch')
    check(report['is_complete'] is False and report['capture_complete'] is False, 'fault report upgraded partial evidence')
    check(report['invalid_window'] is False and report['query_censored'] == 0 and report['invalid_events'] == 0, 'full fault report omitted/censored observations')
    groups,values,faults = defaultdict(list),[],[]
    for record in records:
        check(record.event == 8 and record.version == 1 and len(record.payload) == 40, 'fault capture contains a different record kind')
        address,start,elapsed,access,origin,outcome,classification = unpack('<QQQIIII',record.payload)
        check(start <= record.time and elapsed == record.time-start, 'fault elapsed differs from actual end-start')
        # Access 0 is unknown (e.g. LA privilege faults), not a corrupt record
        # and not evidence for either workload read/write target.
        check(0 <= access <= 7 and origin in (1,2) and 1 <= outcome <= 4 and classification in (0,1,2)
              and (outcome == 1 or classification == 0), 'invalid native fault fields/classification')
        key = (record.task,record.pid or None,record.tid or None,address & ~4095,access,origin,outcome,classification)
        groups[key].append(elapsed); values.append(elapsed)
        faults.append((record,address,access,origin,outcome,classification))
    check(report['captured_events'] == report['valid_events'] == len(faults) > 0, 'fault report record count mismatch')
    check(report['unknown_classification'] == sum(row[5] == 0 for row in faults), 'unknown classification count mismatch')
    check(report['unknown_access'] == sum(row[2] == 0 for row in faults), 'unknown access count mismatch')
    check(report['unknown_identity'] == sum(row[0].pid == 0 or row[0].tid == 0 for row in faults), 'unknown identity count mismatch')
    check(report['address_bin_bytes'] == 4096, 'fault address bin geometry changed')
    fault_duration(report['duration'],values)
    found = set()
    for group in report['groups']:
        key = (uint(group['task_id']),optional_uint(group['pid']),optional_uint(group['tid']),uint(group['page_address']),
               uint(group['access_bits']),uint(group['origin_id']),uint(group['outcome_id']),uint(group['classification_id']))
        check(key in groups and key not in found, 'unsupported or duplicate fault report group'); found.add(key)
        check(group['classification'] == {0:'unknown',1:'minor',2:'major'}[key[7]] and group['record_count'] == len(groups[key]) and group['query_censored'] == 0, 'fault group count/classification mismatch')
        check(group['origin'] == {1:'kernel',2:'user'}[key[5]] and group['outcome'] == {1:'resolved',2:'not_handled',3:'no_memory',4:'resolver_error'}[key[6]], 'fault group origin/outcome labels mismatch')
        check(group['access'] == {0:'unknown',1:'read',2:'write',3:'read|write',4:'execute',5:'read|execute',6:'write|execute',7:'read|write|execute'}[key[4]], 'fault access label mismatch')
        fault_duration(group['duration'],groups[key])
    check(found == set(groups), 'fault report omitted a raw group')
    workload,targets = archive['fault_workload'],archive['fault_targets']
    check(workload['iterations'] == len(targets) == 128, 'missing fault iteration targets')
    pid,tid = uint(workload['pid']),uint(workload['tid'])
    check(pid > 0 and tid > 0, 'missing fault workload identity')
    reads,writes = set(),set()
    for index,target in enumerate(targets):
        read_address,write_address = uint(target['read']),uint(target['write'])
        check(uint(target['index']) == index and read_address > 0 and read_address % 4096 == 0 and write_address == read_address+8192, 'fault target order/guard geometry mismatch')
        reads.add(read_address); writes.add(write_address)
    read_hits = write_hits = 0
    for record,address,access,origin,outcome,_classification in faults:
        if (record.pid,record.tid,origin) == (pid,tid,2):
            is_read = address in reads and bool(access & 1)
            is_write = address in writes and bool(access & 2)
            check(not (is_read or is_write) or outcome == 1, 'first-touch resolver failed')
            read_hits += int(is_read); write_hits += int(is_write)
    check(read_hits == uint(workload['read_hits']) > 0 and write_hits == uint(workload['write_hits']) > 0, 'workload hits differ from raw records')
    return dict(valid_instances=len(faults),unknown_classification=report['unknown_classification'],unknown_access=report['unknown_access'],read_hits=read_hits,write_hits=write_hits,resolver_sum_ns=sum(values))

def verify_run(run, declaration=None):
    inputs,result,archive = (load(run/name) for name in ('inputs.json','result.json','archive.json'))
    check(result['passed'] is True and result['errors'] == [], 'run is not a successful guest gate')
    arch,mode = inputs['arch'],inputs['mode']
    check(arch == result['arch'] and mode == result['mode'] == archive['mode'], 'run identity mismatch')
    raw,raw_info = decode_raw(read(run/'records.pbraw'),mode)
    capture = read(run/'capture.pbcapture')
    normalized,status = decode_capture(capture,arch); compare_records(raw,normalized)
    for key,value in raw_info.items(): check(value == archive[key], f'archive metadata disagrees with decoded RAW {key}')
    check(raw_info['export_dropped'] == 0, 'oracle requires an untruncated exported stream for these final observations')
    digest = hashlib.sha256(capture).hexdigest()
    declared = result['capture']
    check(declared['sha256'] == digest and declared['records'] == len(raw), 'result capture hash/count mismatch')
    check(declared['status'] == STATUS[status] and declared['attribution_claim_allowed'] is False, 'result status/attribution mismatch')
    general = load(run/'analyzer.json')
    check(general['records_count'] == len(raw) and general['status'] == STATUS[status] and general['attribution_claim_allowed'] is False, 'analyzer count/status/attribution mismatch')
    check(general['is_complete'] is (status == 0), 'analyzer completeness differs from trailer')
    semantic = verify_scheduler(run,raw) if mode == 'sched' else verify_faults(run,raw,archive) if mode == 'fault' else None
    if semantic is not None: check(declared['semantic_report']['valid_instances'] == semantic['valid_instances'], 'result semantic count mismatch')
    if declaration is not None:
        check(declaration['run'] == run.name and declaration['arch'] == arch and declaration['mode'] == mode, 'run-list identity mismatch')
        check(declaration['records'] == len(raw) and declaration['capture']['sha256'] == digest, 'run-list count/hash mismatch')
        if semantic is not None: check(declaration['capture']['semantic_report']['valid_instances'] == semantic['valid_instances'], 'run-list semantic count mismatch')
    return dict(run=run.name,arch=arch,mode=mode,verified=True,raw_frames=raw_info['frames'],matched_records=len(raw),capture_sha256=digest,capture_status=STATUS[status],semantic=semantic)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence',type=Path,help='one run directory or a JSON run list')
    parser.add_argument('--runs-root',type=Path,default=Path(__file__).resolve().parent/'runs')
    args = parser.parse_args(argv)
    try:
        if args.evidence.is_dir(): inputs = [(args.evidence,None)]
        else:
            declarations = load(args.evidence)
            check(type(declarations) is list and declarations, 'empty/invalid run list')
            names = [row['run'] for row in declarations]
            check(all(type(name) is str and Path(name).name == name and name not in ('.','..') for name in names), 'unsafe run-list path')
            check(len(set(names)) == len(names), 'duplicate run-list directory')
            inputs = [(args.runs_root/row['run'],row) for row in declarations]
        verified = []
        for directory,declaration in inputs:
            try: verified.append(verify_run(directory,declaration))
            except (OSError,ValueError,KeyError,TypeError,struct.error) as error:
                raise Rejected(f'{directory.name}: {error}') from error
        print(json.dumps({'oracle':'independent offline record and semantic-witness checks; not guest production proof',
                          'verified':True,'run_count':len(verified),'matched_records':sum(row['matched_records'] for row in verified),'runs':verified},indent=2))
        return 0
    except (OSError,ValueError,KeyError,TypeError,struct.error) as error:
        print(json.dumps({'verified':False,'error':str(error)})); return 1

if __name__ == '__main__': sys.exit(main())
