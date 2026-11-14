import struct
import unittest
import zlib
import archive


def fixture(sample_count=1):
    """Synthetic format test data; never a guest or performance measurement."""
    raw = bytearray()
    for sequence in range(sample_count):
        context = bytearray(64)
        struct.pack_into('<QQQIIIIQQII', context, 0, 10, 0, 200+sequence, 3, 40, 41, 0, 99, 0x400110+sequence*4, 2, 2)
        frame = struct.pack('<IHHI', 9, 0, 80, 64) + context + bytes(4)
        raw.extend(struct.pack('<QIIII', sequence, 3, len(frame), zlib.crc32(frame), 0) + frame)
    rows = []
    for point, delivered in [('before', 0), ('after', sample_count)]:
        stats = f'''PULSE_BPF_STATS version=1 pid=40 available=1
GLOBAL timer_enqueued={delivered} timer_dequeued={delivered} timer_full=0 timer_busy=0 trace_enqueued=0 trace_full=0 trace_recursive=0
EVENT fd=14 id=13 clock=1 config=1 scope=task target=41 task_id=99 period=10 generation=20 enabled=0 inflight=0 observed={delivered} delivered={delivered} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=5
PROGRAM id=5 runs={delivered} errors=0
END events=1 programs=1
'''
        sinks = ''.join(
            f'EVENT fd={5+cpu} id={5+cpu} clock=10 config=10 scope=cpu target={cpu} task_id=0 period=0 generation=1 enabled=1 inflight=0 observed=0 delivered={delivered if cpu == 3 else 0} skipped=0 cancelled=0 invalid=0 reentry=0 helper=0 budget=0 transport_lost=0 consumer_corrupt=0 consumer_bounds=0 program_id=0\n'
            for cpu in range(8))
        stats = stats.replace('PROGRAM id=5', sinks + 'PROGRAM id=5').replace('END events=1 programs=1', 'END events=9 programs=1').encode()
        rows.append(f'ARCHIVE STATS_BEGIN point={point} bytes={len(stats)} crc={zlib.crc32(stats)}')
        for offset in range(0,len(stats),256):
            rows.append(f'ARCHIVE STATS_DATA point={point} offset={offset} hex={stats[offset:offset+256].hex()}')
        rows.append(f'ARCHIVE STATS_END point={point}')
    rows += [
        'ARCHIVE CONFIG program_id=5 output_map_id=2 scratch_map_id=3 buffer_pages=16 mode=task',
        'ARCHIVE SOURCE fd=14 link_id=7 enable_before=110 enable_after=120 disable_before=280 disable_after=290',
        'ARCHIVE MEASURE phase=baseline start_ns=10 stop_ns=20 wall_ns=10 iterations=128 extra_mapped_bytes=0 memory_scope=sampler_mappings',
        'ARCHIVE MEASURE phase=loaded_detached start_ns=30 stop_ns=40 wall_ns=10 iterations=128 extra_mapped_bytes=557056 memory_scope=sampler_mappings',
        'ARCHIVE MEASURE phase=attached_capture start_ns=125 stop_ns=275 wall_ns=150 iterations=128 extra_mapped_bytes=4751360 memory_scope=sampler_mappings',
        f'ARCHIVE BEGIN version=1 mode=task start_ns=100 stop_ns=300 frames={sample_count} bytes={len(raw)} crc={zlib.crc32(raw)} dropped=0 mapped_bytes=4194304',
        *(f'ARCHIVE DATA point=frames offset={offset} hex={raw[offset:offset+256].hex()}' for offset in range(0,len(raw),256)),
        f'ARCHIVE END frames={sample_count} bytes={len(raw)} crc={zlib.crc32(raw)}',
    ]
    return '\n'.join(rows) + '\n'


def replace_snapshot(log, point, transform):
    """Alter a synthetic snapshot and reframe it, so validation reaches counters."""
    lines = log.splitlines()
    raw = transform(archive.chunks(lines, 'ARCHIVE STATS_DATA ', point))
    begin = next(i for i, line in enumerate(lines) if line.startswith(f'ARCHIVE STATS_BEGIN point={point} '))
    end = next(i for i, line in enumerate(lines) if line == f'ARCHIVE STATS_END point={point}')
    rows = [f'ARCHIVE STATS_BEGIN point={point} bytes={len(raw)} crc={zlib.crc32(raw)}']
    rows.extend(f'ARCHIVE STATS_DATA point={point} offset={offset} hex={raw[offset:offset+256].hex()}'
                for offset in range(0, len(raw), 256))
    rows.append(f'ARCHIVE STATS_END point={point}')
    return '\n'.join(lines[:begin] + rows + lines[end+1:]) + '\n'


class RawArchiveTests(unittest.TestCase):
    def test_ring_wrap_evidence_matches_the_actual_frame_boundaries(self):
        log = fixture(60).replace('buffer_pages=16 mode=task', 'buffer_pages=1 mode=task ring_diagnostics=1')
        log += 'ARCHIVE QUIESCENT polls=1 waited_ns=0\n'
        for cpu in range(8):
            head = 4800 if cpu == 3 else 0
            log += f'ARCHIVE RING cpu={cpu} head={head} tail={head} wraps={1 if cpu == 3 else 0}\n'
        _, metadata, _ = archive.extract(log, 'task')
        self.assertEqual(metadata['rings'][3]['wraps'], 1)
        for bad in [log.replace('wraps=1', 'wraps=0'), log.replace('tail=4800', 'tail=0'),
                    log.replace('ARCHIVE QUIESCENT', 'MISSING QUIESCENT')]:
            with self.assertRaises(ValueError): archive.extract(bad, 'task')

    def test_preserves_real_frame_and_counter_snapshots(self):
        binary, metadata, stats = archive.extract(fixture(), 'task')
        self.assertEqual(binary[:8], b'PBRW0001')
        self.assertEqual(metadata['samples'],1)
        self.assertEqual(metadata['snapshots']['after']['events'][14]['delivered'],1)
        self.assertEqual(metadata['sources'][0]['event_id'],13)
        self.assertIn(b'PROGRAM id=5 runs=1', stats['after'])
        self.assertEqual(struct.unpack_from('<Q',binary,64+24+12+48)[0],0x400110)

    def test_missing_reordered_or_corrupted_chunks_fail(self):
        log = fixture()
        data = next(line for line in log.splitlines() if line.startswith('ARCHIVE DATA '))
        for bad in [log.replace(data+'\n',''), log.replace('point=frames offset=0','point=frames offset=1'), log.replace(data, data[:-2]+'ff'), log+data+'\n']:
            with self.assertRaises(ValueError): archive.extract(bad, 'task')

    def test_no_eof_or_zero_records_do_not_make_an_archive(self):
        for bad in [fixture().replace('ARCHIVE END ', 'BROKEN END '), fixture().replace('frames=1','frames=0')]:
            with self.assertRaises(ValueError): archive.extract(bad, 'task')

    def test_missing_stats_measurement_or_source_cannot_be_assumed_zero(self):
        for prefix in ['ARCHIVE STATS_END point=after', 'ARCHIVE SOURCE ', 'ARCHIVE MEASURE phase=baseline']:
            bad = '\n'.join(line for line in fixture().splitlines() if not line.startswith(prefix))
            with self.assertRaises(ValueError): archive.extract(bad, 'task')

    def test_snapshot_missing_counter_is_not_an_all_zero_snapshot(self):
        _,_,stats = archive.extract(fixture(),'task')
        with self.assertRaises(ValueError):
            archive.parse_stats(stats['after'].replace(b' helper=0',b''))
        with self.assertRaises(ValueError):
            archive.parse_stats(stats['after'].replace(b'available=1',b'available=0'))

    def test_zero_program_runs_cannot_explain_delivered_samples(self):
        log = replace_snapshot(fixture(), 'after', lambda raw: raw.replace(b'PROGRAM id=5 runs=1', b'PROGRAM id=5 runs=0'))
        with self.assertRaisesRegex(ValueError, 'program'):
            archive.extract(log, 'task')

    def test_consumer_errors_make_quality_partial(self):
        for field in (b'consumer_corrupt', b'consumer_bounds'):
            with self.subTest(field=field):
                log = replace_snapshot(fixture(), 'after', lambda raw: raw.replace(field+b'=0', field+b'=1', 1))
                _, metadata, _ = archive.extract(log, 'task')
                self.assertEqual(metadata['quality'], 'partial')
                self.assertTrue(any(issue['counter'] == field.decode() and issue['delta'] == 1
                                    for issue in metadata['observed_issues']))

    def test_successful_and_failed_program_runs_are_not_added_as_loss(self):
        log = replace_snapshot(fixture(), 'after', lambda raw: raw.replace(
            b'PROGRAM id=5 runs=1 errors=0', b'PROGRAM id=5 runs=2 errors=1').replace(
            b'observed=1 delivered=1', b'observed=2 delivered=1', 1).replace(b'helper=0', b'helper=1', 1))
        _, metadata, _ = archive.extract(log, 'task')
        self.assertEqual(metadata['samples'], 1)
        self.assertEqual(metadata['quality'], 'partial')
        self.assertIn({'scope':'program', 'id':5, 'counter':'errors', 'delta':1}, metadata['observed_issues'])

if __name__ == '__main__': unittest.main()
