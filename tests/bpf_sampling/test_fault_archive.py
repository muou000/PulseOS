"""Synthetic fault protocol fixtures; these are never real fault/guest evidence."""
import struct
import unittest
import zlib
import archive
from test_archive import fixture, replace_snapshot


def fixture_fault(*, change_context=None, unknown_access=False):
    records=[]
    cases=[(3,200,190,0x400000,1,1),(4,220,210,0x402000,2,1)]
    if unknown_access:cases.append((3,240,230,0xffff800000000000,0,2))
    for cpu,end,start,address,access,outcome in cases:
        context=bytearray(80)
        struct.pack_into('<IIQIIIIQ',context,0,8,1,end,cpu,40,41,0,99)
        struct.pack_into('<QQQIIII',context,40,address,start,end-start,access,2,outcome,0)
        if change_context:change_context(context)
        frame=struct.pack('<IHHI',9,0,96,80)+context+bytes(4)
        records.append((cpu,frame))
    rows=[]
    for point in ['before','after']:
        count=len(records) if point=='after' else 0
        lines=['PULSE_BPF_STATS version=1 pid=40 available=1',
               f'GLOBAL timer_enqueued=0 timer_dequeued=0 timer_full=0 timer_busy=0 trace_enqueued={count} trace_full=0 trace_recursive=0 fault_started={count} fault_completed={count} fault_clock_errors=0']
        for cpu in range(8):
            delivered=sum(c==cpu for c,_ in records) if point=='after' else 0
            lines.append(f'EVENT fd={5+cpu} id={5+cpu} clock=10 config=10 scope=cpu target={cpu} task_id=0 period=0 generation=1 enabled=1 inflight=0 observed=0 delivered={delivered} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=0')
            lines.append(f'EVENT fd={20+cpu} id={120+cpu} clock=2 config=8 scope=cpu target={cpu} task_id=0 period=0 generation=20 enabled=0 inflight=0 observed={delivered} delivered={delivered} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=5')
        lines += [f'PROGRAM id=5 runs={count} errors=0','END events=16 programs=1']
        raw=('\n'.join(lines)+'\n').encode()
        rows.append(f'ARCHIVE STATS_BEGIN point={point} bytes={len(raw)} crc={zlib.crc32(raw)}')
        rows.extend(f'ARCHIVE STATS_DATA point={point} offset={n} hex={raw[n:n+256].hex()}' for n in range(0,len(raw),256))
        rows.append(f'ARCHIVE STATS_END point={point}')
    rows.append('ARCHIVE CONFIG program_id=5 output_map_id=2 scratch_map_id=3 buffer_pages=16 mode=fault')
    rows.extend(f'ARCHIVE SOURCE fd={20+cpu} link_id={1000+cpu} enable_before=110 enable_after=120 disable_before=290 disable_after=295' for cpu in range(8))
    rows.extend(line for line in fixture().splitlines() if line.startswith('ARCHIVE MEASURE '))
    # Reuse of the same virtual addresses in distinct iterations is allowed.
    rows.append('ARCHIVE FAULT_WORKLOAD pid=40 tid=41 iterations=128 read_hits=1 write_hits=1')
    rows.extend(f'ARCHIVE FAULT_TARGET index={i} read=4194304 write=4202496' for i in range(128))
    raw=b''.join(struct.pack('<QIIII',i,cpu,len(frame),zlib.crc32(frame),0)+frame for i,(cpu,frame) in enumerate(records))
    rows.append(f'ARCHIVE BEGIN version=1 mode=fault start_ns=100 stop_ns=300 frames={len(records)} bytes={len(raw)} crc={zlib.crc32(raw)} dropped=0 mapped_bytes=4194304')
    rows.extend(f'ARCHIVE DATA point=frames offset={n} hex={raw[n:n+256].hex()}' for n in range(0,len(raw),256))
    rows.append(f'ARCHIVE END frames={len(records)} bytes={len(raw)} crc={zlib.crc32(raw)}')
    return '\n'.join(rows)+'\n'


class FaultArchiveTests(unittest.TestCase):
    def test_known_success_classification_survives_raw_archive(self):
        for classification in (1, 2):
            def classify(context):
                struct.pack_into('<I', context, 76, classification)
            _, metadata, _ = archive.extract(fixture_fault(change_context=classify), 'fault')
            self.assertEqual(metadata['samples'], 2)

    def test_failure_cannot_carry_a_success_classification(self):
        def failed(context):
            struct.pack_into('<II', context, 72, 2, 1)
        with self.assertRaises(ValueError):
            archive.extract(fixture_fault(change_context=failed), 'fault')

    def test_unknown_access_outside_known_targets_is_not_corrupt(self):
        _,metadata,_=archive.extract(fixture_fault(unknown_access=True),'fault')
        self.assertEqual(metadata['samples'],3)
        self.assertEqual(metadata['fault_workload']['read_hits'],1)
        self.assertEqual(metadata['fault_workload']['write_hits'],1)

    def test_actual_records_support_both_reported_fault_hits(self):
        raw,metadata,_=archive.extract(fixture_fault(),'fault')
        self.assertEqual(metadata['samples'],2)
        self.assertEqual(len(metadata['sources']),8)
        self.assertEqual(len(metadata['fault_targets']),128)
        self.assertEqual(metadata['fault_workload'],dict(pid=40,tid=41,iterations=128,read_hits=1,write_hits=1))
        self.assertEqual(raw[:8],b'PBRW0001')

    def test_missing_global_fault_counters_are_not_assumed_zero(self):
        for name in ['fault_started','fault_completed','fault_clock_errors']:
            bad=replace_snapshot(fixture_fault(),'after',lambda b:b.replace(f' {name}={2 if name!="fault_clock_errors" else 0}'.encode(),b''))
            with self.assertRaises(ValueError):archive.extract(bad,'fault')

    def test_missing_targets_zero_hits_and_mismatched_identity_fail(self):
        for old,new in [('index=127 read=','index=126 read='),('read_hits=1','read_hits=0'),('write_hits=1','write_hits=2'),('pid=40 tid=41 iterations=128','pid=40 tid=42 iterations=128')]:
            with self.assertRaises(ValueError):archive.extract(fixture_fault().replace(old,new),'fault')

    def test_adjacent_targets_cannot_claim_isolated_read_and_write_vmas(self):
        with self.assertRaises(ValueError):
            archive.extract(fixture_fault().replace('write=4202496','write=4198400'),'fault')

    def test_bad_time_shape_and_wrong_event_are_rejected(self):
        for offset,value in [(0,7),(4,2),(56,11),(64,8),(68,0),(72,0),(76,3)]:
            def alter(context):struct.pack_into('<I',context,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):archive.extract(fixture_fault(change_context=alter),'fault')

if __name__=='__main__':unittest.main()
