import unittest
import zlib
import copy
import json
from pathlib import Path
import tempfile

import mapping_evidence


SHA = 'ab' * 32


def journal():
    return (
        'PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=100 dropped=0 records=3\n'
        f'OBJECT seq=1 ts=1 object=7 sha256={SHA} path_hex=2f78\n'
        'SPACE seq=2 ts=3 begin_ns=2 space=11 revision=1 count=1\n'
        'MAP start=8192 len=4096 pgoff=4096 perms=5 object=7\nENDSPACE\n'
        'TASK seq=3 ts=5 task=9 pid=2 tid=2 space=11 exec=1 kind=bind parent=0 class=user begin_ns=4 comm_hex=78\n'
        'END records=3 dropped=0 snapshot_ns=100\n'
    ).encode()


class MappingEvidenceTests(unittest.TestCase):
    def test_exec_console_reset_preserves_real_workload_marker(self):
        self.assertEqual(mapping_evidence.normalized_lines('\x1b[mMAPPING WORK phase=exec pid=3\r\n'),
                         ['MAPPING WORK phase=exec pid=3'])

    def test_original_stream_framing_detects_missing_sequence_and_torn_snapshot(self):
        header, rows = mapping_evidence.parse_journal(journal())
        self.assertEqual(len(rows), 3)
        for broken in (journal().replace(b'seq=2', b'seq=4'),
                       journal().replace(b'ENDSPACE\n', b''),
                       journal().replace(b'dropped=0', b'dropped=1')):
            with self.assertRaises(ValueError):
                mapping_evidence.parse_journal(broken)

    def test_resolution_uses_time_and_tlb_completion(self):
        _, rows = mapping_evidence.parse_journal(journal())
        resolved = mapping_evidence.resolve_sample(rows, 10, 9, 8200)
        self.assertEqual(resolved['file_offset'], 4104)
        self.assertEqual(resolved['sha256'], SHA)
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 4, 9, 8200))
        rows += [dict(record='TLB', space='11', token='1', complete='0', ts='20'),
                 dict(record='TLB', space='11', token='1', complete='1', ts='30')]
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 25, 9, 8200))
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 30, 9, 8200))
        self.assertIsNotNone(mapping_evidence.resolve_sample(rows, 31, 9, 8200))

    def test_exec_does_not_inherit_old_space_and_unmap_removes_mapping(self):
        _, rows = mapping_evidence.parse_journal(journal())
        rows += [dict(record='TASK', task='9', pid='2', space='12', exec='2',
                      kind='exec', ts='20', begin_ns='15', **{'class': 'user'})]
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 18, 9, 8200))
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 25, 9, 8200))
        _, rows = mapping_evidence.parse_journal(journal())
        rows += [dict(record='SPACE', space='11', ts='25', begin_ns='20', maps=[])]
        self.assertIsNotNone(mapping_evidence.resolve_sample(rows, 19, 9, 8200))
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 21, 9, 8200))
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 30, 9, 8200))

    def test_snapshot_cut_inside_open_write_lease_is_unknown(self):
        _, rows = mapping_evidence.parse_journal(journal())
        rows += [dict(record='MUTATION', target='space', id='11', token='3', complete='0', ts='20')]
        self.assertIsNotNone(mapping_evidence.resolve_sample(rows, 19, 9, 8200))
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 25, 9, 8200))
        rows += [dict(record='MUTATION', target='space', id='11', token='3', complete='1', ts='30')]
        self.assertIsNone(mapping_evidence.resolve_sample(rows, 25, 9, 8200))
        self.assertIsNotNone(mapping_evidence.resolve_sample(rows, 31, 9, 8200))

    def test_guest_serial_checksum_and_missing_snapshot_fail(self):
        raw = journal()
        text = ''
        for point in ('before', 'after'):
            text += f'ARCHIVE MAPPINGS_BEGIN point={point} bytes={len(raw)} crc={zlib.crc32(raw)}\n'
            for offset in range(0, len(raw), 256):
                text += f'ARCHIVE MAPPINGS_DATA point={point} offset={offset} hex={raw[offset:offset + 256].hex()}\n'
            text += f'ARCHIVE MAPPINGS_END point={point}\n'
        self.assertEqual(mapping_evidence.extract_snapshots(text), {'before': raw, 'after': raw})
        with self.assertRaises(ValueError):
            mapping_evidence.extract_snapshots(text.replace('offset=0', 'offset=1', 1))
        with self.assertRaises(ValueError):
            mapping_evidence.extract_snapshots(text.replace('ARCHIVE MAPPINGS_END point=after\n', ''))

    def test_standalone_report_must_match_raw_generation_object_and_symbol(self):
        expected = dict(timestamp_ns=10, cpu=1, task_id=9, pid=2, tid=2, ip=8200,
                        space=11, exec=1, object=7, sha256=SHA, pgoff=4096, file_offset=4104)
        sample = dict(timestamp_ns=10, cpu=1, task=9, pid=2, tid=2, ip=8200,
                      mapping=dict(space=11, exec=1, object=7, sha256=SHA, byte_pgoff=4096, file_offset=4104),
                      elf=dict(sha256=SHA, name='mapped_busy_loop', elf_address=0x401008), unknown_reason=None)
        report = dict(mapping_metadata=True, journal_dropped=0, busy_time_ns=None, idle_time_ns=None,
                      mapped_user_samples=1, verified_elf_samples=1, samples=[sample])
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / 'mapping-evidence.json').write_text(json.dumps({'examples': {'fork': expected}}))
            mapping_evidence.check_report(run, report)
            for group, key, value in [('mapping', 'exec', 2), ('mapping', 'object', 8),
                                       ('elf', 'sha256', 'cd' * 32), ('elf', 'elf_address', 4104)]:
                broken = copy.deepcopy(report)
                broken['samples'][0][group][key] = value
                with self.assertRaises(ValueError):
                    mapping_evidence.check_report(run, broken)

    def test_same_irq_samples_are_distinguished_by_source_instance(self):
        expected = dict(timestamp_ns=10, cpu=1, task_id=9, pid=2, tid=2, ip=8200,
                        source_id=21, space=11, exec=1, object=7, sha256=SHA, pgoff=4096, file_offset=4104)
        sample = dict(timestamp_ns=10, cpu=1, task=9, pid=2, tid=2, ip=8200, source_id=21,
                      mapping=dict(space=11, exec=1, object=7, sha256=SHA, byte_pgoff=4096, file_offset=4104),
                      elf=dict(sha256=SHA, name='mapped_busy_loop', elf_address=0x401008), unknown_reason=None)
        second = {**sample, 'source_id': 22}
        report = dict(mapping_metadata=True, journal_dropped=0, busy_time_ns=None, idle_time_ns=None,
                      mapped_user_samples=2, verified_elf_samples=2, samples=[sample, second])
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / 'mapping-evidence.json').write_text(json.dumps({'examples': {'fork': expected}}))
            mapping_evidence.check_report(run, report)
            report['samples'] = [second]
            with self.assertRaises(ValueError):
                mapping_evidence.check_report(run, report)


if __name__ == '__main__':
    unittest.main()
