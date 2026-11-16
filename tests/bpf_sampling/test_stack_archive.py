"""Synthetic stack wire fixtures; these never replace the QEMU/ELF gate."""
import struct
import unittest
import zlib
import archive
import run
from test_archive import fixture, sample_frame, source_declaration, replace_snapshot
from test_runner import VALID, CPU_VALID, TOKEN


def stack_fixture(change=None):
    log = fixture()
    lines = log.splitlines()
    raw = archive.chunks(lines, 'ARCHIVE DATA ', 'frames')
    context = bytearray(640)
    context[:64] = raw[24 + 36:24 + 36 + 64]
    struct.pack_into('<QQQQQHHHHIIQ', context,64,13,0x10000,0x10010,0,5,3,32,3,4,32,512,0)
    struct.pack_into('<QQQ',context,128,0x400110,0x400100,0x400080)
    if change:
        change(context)
    frame = sample_frame(1, 3, context)
    raw = struct.pack('<QIIII',0,3,len(frame),zlib.crc32(frame),0) + frame
    lines = [line for line in lines if not line.startswith(('ARCHIVE BEGIN ', 'ARCHIVE DATA ', 'ARCHIVE END ', 'ARCHIVE CONTEXT '))]
    lines = [line.replace("kind=1 schema_event_id=4097 schema_version=2", "kind=3 schema_event_id=4098 schema_version=3") for line in lines]
    lines += [
        'SAMPLING START version=2 mode=task cpus=8 pid=40 tid=41',
        'ARCHIVE CONTEXT format=software-stack-v3',
        f'ARCHIVE BEGIN version=1 mode=task start_ns=100 stop_ns=300 frames=1 bytes={len(raw)} crc={zlib.crc32(raw)} dropped=0 mapped_bytes=4194304',
        *(f'ARCHIVE DATA point=frames offset={offset} hex={raw[offset:offset+256].hex()}' for offset in range(0,len(raw),256)),
        f'ARCHIVE END frames=1 bytes={len(raw)} crc={zlib.crc32(raw)}',
    ]
    return '\n'.join(lines) + '\n'


def cpu_stack_fixture_same_period():
    """Two separately stamped sources per CPU, all requesting the same period."""
    log = stack_fixture()
    prototype = archive.chunks(log.splitlines(), 'ARCHIVE DATA ', 'frames')[60:700]
    for point in ('before', 'after'):
        delivered = 2 if point == 'after' else 0
        def snapshot(_raw):
            rows = ['PULSE_BPF_STATS version=1 pid=40 available=1',
                    f'GLOBAL timer_enqueued={delivered} timer_dequeued={delivered} timer_full=0 timer_busy=0 trace_enqueued=0 trace_full=0 trace_recursive=0']
            for cpu in range(8):
                count = delivered if cpu == 0 else 0
                rows.append(f'EVENT fd={5+cpu} id={5+cpu} clock=10 config=10 scope=cpu target={cpu} task_id=0 period=0 generation=1 enabled=1 inflight=0 observed=0 delivered={count} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=0')
            for index in range(16):
                count = int(point == 'after' and index < 2)
                rows.append(f'EVENT fd={100+index} id={100+index} clock=0 config=0 scope=cpu target={index//2} task_id=0 period=10 generation=20 enabled=0 inflight=0 observed={count} delivered={count} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=5')
            rows += [f'PROGRAM id=5 runs={delivered} errors=0', 'END events=24 programs=1']
            return ('\n'.join(rows)+'\n').encode()
        log = replace_snapshot(log, point, snapshot)
    lines = [line.replace('mode=task', 'mode=cpu') for line in log.splitlines()
             if not line.startswith(('ARCHIVE SOURCE ', 'ARCHIVE BEGIN ', 'ARCHIVE DATA ', 'ARCHIVE END '))]
    lines += [source_declaration(fd=100+index, logical_id=index+1, event_id=100+index,
                                kind=3, schema_event_id=0x1002, target=index//2,
                                period=10, link_id=200+index) for index in range(16)]
    raw = bytearray()
    for index in range(2):
        context = bytearray(prototype)
        struct.pack_into('<I', context, 24, 0)
        struct.pack_into('<Q', context, 64, 100+index)
        frame = sample_frame(index+1, 3, context)
        raw.extend(struct.pack('<QIIII', index, 0, len(frame), zlib.crc32(frame), 0)+frame)
    lines += [f'ARCHIVE BEGIN version=1 mode=cpu start_ns=100 stop_ns=300 frames=2 bytes={len(raw)} crc={zlib.crc32(raw)} dropped=0 mapped_bytes=4194304',
              *(f'ARCHIVE DATA point=frames offset={offset} hex={raw[offset:offset+256].hex()}' for offset in range(0,len(raw),256)),
              f'ARCHIVE END frames=2 bytes={len(raw)} crc={zlib.crc32(raw)}']
    return '\n'.join(lines)+'\n'


class StackArchiveTests(unittest.TestCase):
    def test_distinct_same_cpu_sources_do_not_require_distinct_periods(self):
        _, metadata, _ = archive.extract(cpu_stack_fixture_same_period(), 'cpu')
        self.assertEqual(metadata['stack_source_counts'], {100: 1, 101: 1})
        self.assertEqual([source['logical_id'] for source in metadata['sources'][:2]], [1, 2])
        self.assertEqual([source['period'] for source in metadata['sources'][:2]], [10, 10])

    def test_cpu_source_coverage_rejects_out_of_matrix_targets(self):
        log = cpu_stack_fixture_same_period()
        for point in ('before', 'after'):
            log = replace_snapshot(log, point, lambda raw: raw.replace(b'target=7 ', b'target=8 '))
        log = log.replace('scope=1 target=7 ', 'scope=1 target=8 ')
        with self.assertRaisesRegex(ValueError, 'same-CPU software source instances'):
            archive.extract(log, 'cpu')

    def test_preserves_required_format_and_source_record_count(self):
        binary, metadata, _ = archive.extract(stack_fixture(),'task')
        self.assertEqual(metadata['context_format'],'software-stack-v3')
        self.assertEqual(metadata['stack_source_counts'],{13:1})
        self.assertEqual(struct.unpack_from('<Q',binary,64+24+36+64)[0],13)

    def test_empty_unavailable_chain_preserves_observed_ip(self):
        def empty(context, status=9, read_bytes=0):
            struct.pack_into('<HHI',context,108,0,status,read_bytes)
            context[128:] = bytes(512)
        for status in (9,13):
            binary,metadata,_=archive.extract(stack_fixture(lambda c:empty(c,status)),'task')
            self.assertEqual(metadata['samples'],1)
            self.assertEqual(struct.unpack_from('<Q',binary,64+24+36+48)[0],0x400110)
            self.assertEqual(struct.unpack_from('<H',binary,64+24+36+108)[0],0)
        for status,read_bytes in [(4,0),(9,16),(13,16)]:
            with self.subTest(status=status,read_bytes=read_bytes), self.assertRaises(ValueError):
                archive.extract(stack_fixture(lambda c:empty(c,status,read_bytes)),'task')
        def nonzero_tail(context):
            empty(context)
            struct.pack_into('<Q',context,128,0x400110)
        with self.assertRaises(ValueError):
            archive.extract(stack_fixture(nonzero_tail),'task')

    def test_unknown_format_never_falls_back_to_v2(self):
        with self.assertRaises(ValueError):
            archive.extract(stack_fixture().replace('software-stack-v3','software-stack-v4'),'task')
        with self.assertRaises(ValueError):
            archive.extract(stack_fixture().replace('ARCHIVE CONTEXT format=software-stack-v3\n',''),'task')

    def test_invalid_required_extensions_rejected(self):
        changes = [lambda c:struct.pack_into('<H',c,104,4),
                   lambda c:struct.pack_into('<H',c,108,65),
                   lambda c:struct.pack_into('<H',c,110,99),
                   lambda c:struct.pack_into('<Q',c,120,1),
                   lambda c:struct.pack_into('<Q',c,160,1),
                   lambda c:struct.pack_into('<I',c,112,513),
                   lambda c:struct.pack_into('<Q',c,128,0)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                archive.extract(stack_fixture(change),'task')

    def test_stable_source_and_period_are_authoritative(self):
        for offset,value in [(64,999),(0,11),(40,111)]:
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                archive.extract(stack_fixture(lambda c:struct.pack_into('<Q',c,offset,value)),'task')

    def test_stack_gate_requires_user_kernel_and_negative_evidence(self):
        markers = ('SAMPLING STACKS user_a=3 user_b=4 kernel=5 partial=8 sources=1 context=software-stack-v3\n'
                   'SAMPLING STACK_PROBES no_fp=1 read_fault=1 cycle=1 bad_ra=1 misaligned=1 depth_limit=1\n')
        self.assertEqual(run.validate_log(VALID+markers,TOKEN,'task',True),[])
        self.assertTrue(run.validate_log(VALID,TOKEN,'task',True))
        for old,new in [('kernel=5','kernel=0'),('read_fault=1','read_fault=0'),('sources=1','sources=2')]:
            self.assertTrue(run.validate_log(VALID+markers.replace(old,new),TOKEN,'task',True))
        self.assertEqual(run.validate_log(CPU_VALID+markers.replace('sources=1','sources=16'),TOKEN,'cpu',True),[])
