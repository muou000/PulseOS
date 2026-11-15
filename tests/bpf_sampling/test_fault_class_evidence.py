"""Adversarial fixtures for the device-read/RAW classification oracle."""
import struct
import unittest
import io
from pathlib import Path
import tempfile
from verify_observation_evidence import Record
import fault_class_evidence as evidence


def fixture():
    markers=[]; records=[]; trace=bytearray()
    for index,kind in enumerate(evidence.CASES):
        address=0x100000+index*4096
        start=100+index*100
        markers.append(dict(kind=kind,point='begin',address=address,pid=2,tid=3,
                            time_ns=start,trace_offset=len(trace)))
        sector = 80 if kind=='cold' else 88 if kind=='cold_neighbor' else None
        if sector is not None:
            trace.extend(f'virtio_blk_handle_read vdev 0x1 req 0x2 sector {sector} nsectors 8\n'.encode())
            trace.extend(b'virtio_blk_rw_complete vdev 0x1 req 0x2 ret 0\n')
        markers.append(dict(kind=kind,point='end',address=address,pid=2,tid=3,
                            time_ns=start+90,trace_offset=len(trace)))
        records.append(Record(8,1,start+50,0,2,3,7,
            struct.pack('<QQQIIII',address,start+1,49,2 if kind=='cow' else 1,2,1,2 if kind in ('cold','cold_neighbor') else 1)))
    return records,markers,bytes(trace),{'pages':[[[80,8]],[[88,8]]]}


class FaultClassEvidenceTests(unittest.TestCase):
    def test_boundary_waits_for_full_serial_line_before_acknowledging(self):
        with tempfile.TemporaryDirectory() as temporary:
            run=Path(temporary)
            (run/'device-reads.log').write_bytes(b'')
            boundaries=evidence.Boundaries(run)
            stdin=io.BytesIO()
            prefix='FAULT_CLASS kind=anonymous point=begin address=4096 pid=2 tid=3 time_ns=364'
            boundaries(prefix,stdin)
            self.assertEqual(boundaries.rows,[])
            self.assertEqual(stdin.getvalue(),b'')
            boundaries(prefix+'4279560\n',stdin)
            self.assertEqual(boundaries.rows[0]['time_ns'],3644279560)
            self.assertEqual(stdin.getvalue(),b'g\n')

    def test_completed_device_reads_agree_with_target_classes(self):
        report=evidence.verify_cases(*fixture())
        self.assertEqual(report['cases']['cold']['classification'],'major')
        self.assertEqual(report['cases']['cached_target_cold_neighbor']['classification'],'minor')
        self.assertEqual(report['cases']['cold_neighbor']['neighbor_read_sectors'],8)

    def test_unknown_cold_is_not_a_completed_classification(self):
        records,*args=fixture()
        record=records[1]
        records[1]=Record(*list(record.__dict__.values())[:-1],record.payload[:-4]+bytes(4))
        with self.assertRaises(ValueError):evidence.verify_cases(records,*args)

    def test_cached_target_must_not_absorb_neighbor_io(self):
        records,*args=fixture()
        record=records[-2]
        records[-2]=Record(*list(record.__dict__.values())[:-1],record.payload[:-4]+struct.pack('<I',2))
        with self.assertRaises(ValueError):evidence.verify_cases(records,*args)

    def test_missing_or_failed_device_read_is_not_cold_evidence(self):
        records,markers,trace,layout=fixture()
        for corrupt in (trace.replace(b'sector 80',b'sector 96'),trace.replace(b'ret 0',b'ret 1')):
            with self.subTest(trace=corrupt),self.assertRaises(ValueError):
                evidence.verify_cases(records,markers,corrupt,layout)

    def test_duplicate_and_out_of_order_boundaries_fail(self):
        records,markers,trace,layout=fixture()
        for bad in (markers+markers[:1],list(reversed(markers))):
            with self.assertRaises(ValueError):evidence.verify_cases(records,bad,trace,layout)

    def test_raw_fault_outside_target_interval_is_not_evidence(self):
        records,markers,trace,layout=fixture()
        records.pop()
        with self.assertRaises(ValueError):evidence.verify_cases(records,markers,trace,layout)


if __name__=='__main__':unittest.main()
