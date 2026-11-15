"""Synthetic stack wire fixtures; these never replace the QEMU/ELF gate."""
import struct
import unittest
import zlib
import archive
import run
from test_archive import fixture
from test_runner import VALID, CPU_VALID, TOKEN


def stack_fixture(change=None):
    log = fixture()
    lines = log.splitlines()
    raw = archive.chunks(lines, 'ARCHIVE DATA ', 'frames')
    context = bytearray(640)
    context[:64] = raw[24 + 12:24 + 12 + 64]
    struct.pack_into('<QQQQQHHHHIIQ', context,64,13,0x10000,0x10010,0,5,3,32,3,4,32,512,0)
    struct.pack_into('<QQQ',context,128,0x400110,0x400100,0x400080)
    if change:
        change(context)
    frame = struct.pack('<IHHI',9,0,656,640) + context + bytes(4)
    raw = struct.pack('<QIIII',0,3,len(frame),zlib.crc32(frame),0) + frame
    lines = [line for line in lines if not line.startswith(('ARCHIVE BEGIN ', 'ARCHIVE DATA ', 'ARCHIVE END '))]
    lines += [
        'SAMPLING START version=2 mode=task cpus=8 pid=40 tid=41',
        'ARCHIVE CONTEXT format=software-stack-v3',
        f'ARCHIVE BEGIN version=1 mode=task start_ns=100 stop_ns=300 frames=1 bytes={len(raw)} crc={zlib.crc32(raw)} dropped=0 mapped_bytes=4194304',
        *(f'ARCHIVE DATA point=frames offset={offset} hex={raw[offset:offset+256].hex()}' for offset in range(0,len(raw),256)),
        f'ARCHIVE END frames=1 bytes={len(raw)} crc={zlib.crc32(raw)}',
    ]
    return '\n'.join(lines) + '\n'


class StackArchiveTests(unittest.TestCase):
    def test_preserves_required_format_and_source_record_count(self):
        binary, metadata, _ = archive.extract(stack_fixture(),'task')
        self.assertEqual(metadata['context_format'],'software-stack-v3')
        self.assertEqual(metadata['stack_source_counts'],{13:1})
        self.assertEqual(struct.unpack_from('<Q',binary,64+24+12+64)[0],13)

    def test_empty_unavailable_chain_preserves_observed_ip(self):
        def empty(context, status=9, read_bytes=0):
            struct.pack_into('<HHI',context,108,0,status,read_bytes)
            context[128:] = bytes(512)
        for status in (9,13):
            binary,metadata,_=archive.extract(stack_fixture(lambda c:empty(c,status)),'task')
            self.assertEqual(metadata['samples'],1)
            self.assertEqual(struct.unpack_from('<Q',binary,64+24+12+48)[0],0x400110)
            self.assertEqual(struct.unpack_from('<H',binary,64+24+12+108)[0],0)
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
