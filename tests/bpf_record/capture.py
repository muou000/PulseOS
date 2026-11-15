"""Recover a guest file, never reconstruct or manufacture its capture records."""
import re
import zlib


def clean_console(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text.replace("\r", ""))


def extract(text: str, name: str, limit: int = 32 * 1024 * 1024) -> bytes:
    rows = clean_console(text).splitlines()
    begin = f"RECORD_FILE BEGIN name={name}"
    if rows.count(begin) != 1:
        raise ValueError(f"missing/duplicate file start: {name}")
    started = ended = False
    output = bytearray()
    for row in rows:
        if row == begin:
            started = True
        elif row.startswith(f"RECORD_FILE DATA name={name} "):
            if not started or ended:
                raise ValueError("file chunk outside its transfer")
            match = re.fullmatch(r"RECORD_FILE DATA name=\S+ offset=(\d+) hex=([0-9a-f]+)", row)
            if not match or int(match[1]) != len(output) or len(match[2]) % 2:
                raise ValueError("invalid file chunk/offset")
            if len(output) + len(match[2]) // 2 > limit:
                raise ValueError("file transfer exceeds bound")
            output.extend(bytes.fromhex(match[2]))
        elif row.startswith(f"RECORD_FILE END name={name} "):
            match = re.fullmatch(r"RECORD_FILE END name=\S+ bytes=(\d+) crc=(\d+)", row)
            if not started or ended or not match:
                raise ValueError("invalid file transfer end")
            if int(match[1]) != len(output) or int(match[2]) != zlib.crc32(output):
                raise ValueError("file length/checksum mismatch")
            ended = True
    if not ended or not output:
        raise ValueError("missing file end or empty output")
    return bytes(output)
