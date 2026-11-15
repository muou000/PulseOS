"""Serial transport checks; fixture bytes are not sampling evidence."""
import unittest
import zlib

from capture import extract


def transcript(data=b"the actual guest file\x00\xff"):
    return (
        "RECORD_FILE BEGIN name=cpu\n"
        f"RECORD_FILE DATA name=cpu offset=0 hex={data.hex()}\n"
        f"RECORD_FILE END name=cpu bytes={len(data)} crc={zlib.crc32(data)}\n"
    )


class CaptureTransportTests(unittest.TestCase):
    def test_guest_file_is_preserved_byte_for_byte(self):
        self.assertEqual(extract(transcript(), "cpu"), b"the actual guest file\x00\xff")

    def test_kernel_console_color_reset_does_not_hide_the_file_start(self):
        self.assertEqual(extract("\x1b[m" + transcript(), "cpu"), b"the actual guest file\x00\xff")

    def test_missing_end_or_duplicate_chunk_is_not_a_complete_file(self):
        text = transcript()
        line = text.splitlines()[1] + "\n"
        for corrupt in (text.replace("RECORD_FILE END", "MISSING END"),
                        text.replace(line, line + line),
                        text.replace("offset=0", "offset=1"),
                        text.replace("offset=0", "offset=-1")):
            with self.subTest(corrupt=corrupt), self.assertRaises(ValueError):
                extract(corrupt, "cpu")

    def test_bad_crc_or_wrong_session_is_rejected(self):
        for corrupt in (transcript().replace("hex=74", "hex=75"),
                        transcript().replace("name=cpu", "name=fault")):
            with self.assertRaises(ValueError):
                extract(corrupt, "cpu")


if __name__ == "__main__":
    unittest.main()
