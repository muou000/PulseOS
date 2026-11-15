"""Synthetic protocol tests for a mixed scheduler session, never runtime evidence."""
import struct
import unittest
import zlib
import archive
from test_archive import fixture, replace_snapshot

SIZES = {1:72, 2:72, 3:72, 4:80, 5:56, 6:64}


def fixture_sched():
    records = []
    for event, cpu, timestamp, task, words in [
        (3,0,200,99,[7,3,0,0]),
        (2,0,210,99,[99,100,3,0]),
        (4,1,250,100,[99,7,100,1,0]),
        (6,1,260,99,[99,(1<<32)|1,(2<<32)|1]),
        (2,1,280,101,[101,99,1,0]),
    ]:
        context=bytearray(SIZES[event])
        struct.pack_into('<IIQIIIIQ',context,0,event,1,timestamp,cpu,40,41,0,task)
        for i,value in enumerate(words):struct.pack_into('<Q',context,40+8*i,value)
        size=(12+len(context)+7)&~7
        records.append((event,cpu,struct.pack('<IHHI',9,0,size,len(context))+context+bytes(size-12-len(context))))
    rows=[]
    for point in ['before','after']:
        active=point=='after'
        lines=['PULSE_BPF_STATS version=1 pid=40 available=1',
               f'GLOBAL timer_enqueued=0 timer_dequeued=0 timer_full=0 timer_busy=0 trace_enqueued={5 if active else 0} trace_full=0 trace_recursive=0']
        for cpu in range(8):
            delivered=sum(c==cpu for _,c,_ in records) if active else 0
            lines.append(f'EVENT fd={5+cpu} id={5+cpu} clock=10 config=10 scope=cpu target={cpu} task_id=0 period=0 generation=1 enabled=1 inflight=0 observed=0 delivered={delivered} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=0')
        for event in SIZES:
            for cpu in range(8):
                fd=20+(event-1)*8+cpu
                delivered=sum(e==event and c==cpu for e,c,_ in records) if active else 0
                lines.append(f'EVENT fd={fd} id={fd+100} clock=2 config={event} scope=cpu target={cpu} task_id=0 period=0 generation=20 enabled=0 inflight=0 observed={delivered} delivered={delivered} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id={10+event}')
        for event in SIZES:
            delivered=sum(e==event for e,_,_ in records) if active else 0
            lines.append(f'PROGRAM id={10+event} runs={delivered} errors=0')
        lines.append('END events=56 programs=6')
        raw=('\n'.join(lines)+'\n').encode()
        rows.append(f'ARCHIVE STATS_BEGIN point={point} bytes={len(raw)} crc={zlib.crc32(raw)}')
        rows.extend(f'ARCHIVE STATS_DATA point={point} offset={n} hex={raw[n:n+256].hex()}' for n in range(0,len(raw),256))
        rows.append(f'ARCHIVE STATS_END point={point}')
    rows.append('ARCHIVE CONFIG program_id=11 output_map_id=2 scratch_map_id=3 buffer_pages=16 mode=sched')
    for event,size in SIZES.items():
        rows.append(f'ARCHIVE PROGRAM tracepoint={event} program_id={10+event} context_bytes={size}')
        for cpu in range(8):
            fd=20+(event-1)*8+cpu
            rows.append(f'ARCHIVE SOURCE fd={fd} link_id={fd+1000} enable_before=110 enable_after=120 disable_before=290 disable_after=295')
    rows.extend(line for line in fixture().splitlines() if line.startswith('ARCHIVE MEASURE '))
    raw=b''.join(struct.pack('<QIIII',i,cpu,len(frame),zlib.crc32(frame),0)+frame for i,(_,cpu,frame) in enumerate(records))
    rows.append(f'ARCHIVE BEGIN version=1 mode=sched start_ns=100 stop_ns=300 frames=5 bytes={len(raw)} crc={zlib.crc32(raw)} dropped=0 mapped_bytes=4194304')
    rows.extend(f'ARCHIVE DATA point=frames offset={n} hex={raw[n:n+256].hex()}' for n in range(0,len(raw),256))
    rows.append(f'ARCHIVE END frames=5 bytes={len(raw)} crc={zlib.crc32(raw)}')
    return '\n'.join(rows)+'\n'


class MixedSchedulerArchiveTests(unittest.TestCase):
    def test_mixed_records_keep_all_source_program_bindings(self):
        raw,metadata,_=archive.extract(fixture_sched(),'sched')
        self.assertEqual(metadata['samples'],5)
        self.assertEqual(len(metadata['sources']),48)
        self.assertEqual([p['tracepoint'] for p in metadata['program_bindings']],list(range(1,7)))
        self.assertEqual(raw[:8],b'PBRW0001')

    def test_missing_program_or_one_cpu_source_fails(self):
        for prefix in ['ARCHIVE PROGRAM tracepoint=4 ', 'ARCHIVE SOURCE fd=51 ']:
            bad='\n'.join(line for line in fixture_sched().splitlines() if not line.startswith(prefix))
            with self.assertRaises(ValueError):archive.extract(bad,'sched')

    def test_program_counter_swap_cannot_hide_behind_aggregate_total(self):
        bad=replace_snapshot(fixture_sched(),'after',lambda b:b.replace(b'PROGRAM id=12 runs=2',b'PROGRAM id=12 runs=1').replace(b'PROGRAM id=14 runs=1',b'PROGRAM id=14 runs=2'))
        with self.assertRaises(ValueError):archive.extract(bad,'sched')

if __name__=='__main__':unittest.main()
