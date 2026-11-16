"""Independent comparison of native perf decoding to original guest RAW bytes."""
from collections import Counter
import re
import struct
import zlib
import archive

SUMMARY = re.compile(r"^(\d+) (\d+) 0x[0-9a-f]+ \[0x[0-9a-f]+\]: PERF_RECORD_SAMPLE\(IP, (0x[0-9a-f]+)\): (\d+)/(\d+): (0x[0-9a-f]+) period: (\d+) addr: \d+$", re.M)


def native_samples(dump: str) -> list[tuple]:
    samples = []
    blocks = re.split(r"(?=^0x[0-9a-f]+@.*\]: event: \d+$)", dump, flags=re.M)
    for block in blocks:
        if not re.match(r"0x[0-9a-f]+@.*\]: event: 9\n", block):
            continue
        raw = bytearray()
        for offset, columns in re.findall(r"^\.  ([0-9a-f]+):  (.*)$", block, re.M):
            if int(offset, 16) != len(raw):
                raise ValueError("native perf raw dump offset discontinuity")
            # perf renders exactly sixteen three-column byte cells. Never
            # consume its following ASCII column as if it were hex bytes.
            raw.extend(bytes.fromhex(columns[:47].rstrip()))
        if len(raw) < 64 or struct.unpack_from('<I', raw)[0] != 9 or struct.unpack_from('<H', raw, 6)[0] != len(raw):
            raise ValueError("native perf sample dump length/header mismatch")
        mode = struct.unpack_from('<H', raw, 4)[0] & 7
        source, ip, pid, tid, timestamp, cpu, reserved, period, count = struct.unpack_from('<QQIIQIIQQ', raw, 8)
        if reserved or len(raw) != 64 + 8 * count:
            raise ValueError("native sample wire payload differs from declared subset")
        chain = struct.unpack_from(f'<{count}Q', raw, 64)
        parsed = SUMMARY.findall(block)
        expected = (cpu, timestamp, mode, pid, tid, ip, period)
        if len(parsed) != 1 or tuple(int(value, 16 if index in (2, 5) else 10) for index, value in enumerate(parsed[0])) != expected:
            raise ValueError("native perf decoded summary differs from its raw event")
        lengths = re.findall(r'^\.\.\. FP chain: nr:(\d+)$', block, re.M)
        frames = re.findall(r'^\.\.\.\.\.\s+(\d+): ([0-9a-f]+)$', block, re.M)
        if lengths != [str(count)] or [int(index) for index, _ in frames] != list(range(count)) or tuple(int(value, 16) for _, value in frames) != chain:
            raise ValueError("native perf decoded context/callchain differs from raw event")
        samples.append((source, ip, pid, tid, timestamp, cpu, period, mode, chain))
    return samples


def raw_samples(raw: bytes, query: dict) -> list[tuple]:
    """Decode native 640-byte contexts and apply explicit public Query fields."""
    if raw[:8] != b'PBRW0001' or len(raw) < 64:
        raise ValueError("missing real RAW archive")
    frames, length, checksum = struct.unpack_from('<QQI', raw, 24)
    if length != len(raw) - 64 or zlib.crc32(raw[64:]) != checksum:
        raise ValueError("RAW archive checksum/length mismatch")
    samples, offset, sequence = [], 64, 0
    for _ in range(frames):
        seq, ring_cpu, size, crc, reserved = struct.unpack_from('<QIIII', raw, offset)
        offset += 24
        frame = raw[offset:offset + size]
        offset += size
        if seq != sequence or reserved or len(frame) != size or zlib.crc32(frame) != crc:
            raise ValueError("RAW frame identity/checksum mismatch")
        sequence += 1
        kind, _, record_size = struct.unpack_from('<IHH', frame)
        if record_size != size:
            raise ValueError("RAW record length differs from envelope")
        if kind != 9:
            continue
        logical_id, source_kind, context = archive.source_context(frame)
        if source_kind != 3 or len(context) != 640:
            raise ValueError("real perf evidence requires native stack-v3 contexts")
        period, _, timestamp, cpu, pid, tid, _, task, ip, mode = struct.unpack_from('<QQQIIIIQQI', context)
        source = logical_id
        count, = struct.unpack_from('<H', context, 108)
        if count > 64 or cpu != ring_cpu:
            raise ValueError("RAW stack count or CPU invalid")
        values = {'pid': pid, 'tid': tid, 'task': task, 'cpu': cpu, 'mode': 'user' if mode == 2 else 'kernel' if mode == 1 else 'unknown'}
        if any(key in query and values[key] != query[key] for key in values):
            continue
        if timestamp < query.get('from_ns', 0) or timestamp >= query.get('to_ns', 1 << 64):
            continue
        ips = struct.unpack_from(f'<{count}Q', context, 128)
        marker = (1 << 64) - (512 if mode == 2 else 128)
        samples.append((source, ip, pid, tid, timestamp, cpu, period, mode, (marker, *ips)))
    if offset != len(raw):
        raise ValueError("RAW archive trailing bytes")
    return samples


def verify_named_chain(script: str, calltree: str, leaf_first: list[str]) -> None:
    """Require the known real functions in one chain, not unrelated rows."""
    if len(leaf_first) < 3:
        raise ValueError("multilevel function oracle requires at least three functions")
    chains = []
    for block in re.split(r'\n\s*\n', script):
        chains.append([symbol.strip() for symbol in re.findall(r'^\s+[0-9a-f]+\s+(.+?)\s+\(.*\)\s*$', block, re.M)])
    if not any(chain[:len(leaf_first)] == leaf_first for chain in chains):
        raise ValueError("native perf script lacks known leaf-to-root function chain")
    root_first = list(reversed(leaf_first))
    for block in re.split(r'\n\s*\n', calltree):
        graph = [re.sub(r'^[ |`\-0-9.%]+', '', line).strip() for line in block.splitlines() if '[' not in line]
        graph = [line for line in graph if line]
        if any(graph[index:index + len(root_first)] == root_first for index in range(len(graph))):
            return
    raise ValueError("native perf calltree lacks known root-to-leaf function chain")


def verify_function_weights(samples: list[tuple], rows: list[dict], ranges: dict) -> dict:
    """Compare per-function native report weights with original IP ranges."""
    result = {}
    for symbol, (start, end) in ranges.items():
        selected = [sample for sample in samples if start <= sample[1] < end]
        expected = {'samples': len(selected), 'period_ns': sum(sample[6] for sample in selected)}
        actual = {'samples': sum(row['samples'] for row in rows if row['symbol'] == symbol),
                  'period_ns': sum(row['period_ns'] for row in rows if row['symbol'] == symbol)}
        if expected != actual:
            raise ValueError(f'native perf function weight differs from original RAW IP range: {symbol}')
        result[symbol] = expected
    return result


def verify(raw: bytes, dump: str, query: dict, report: str) -> dict:
    expected = raw_samples(raw, query)
    actual = native_samples(dump)
    if not expected or Counter(expected) != Counter(actual):
        raise ValueError("native perf samples differ from selected original RAW identities, PCs, periods or chains")
    periods = sum(sample[6] for sample in expected)
    reported_periods = [int(value) for value in re.findall(r'^# Event count \(approx\.\): (\d+)$', report, re.M)]
    if not reported_periods or sum(reported_periods) != periods:
        raise ValueError("native perf report period differs from selected original RAW")
    # Rows under --show-nr-samples --show-total-period are exact, unlike the
    # human-friendly '# Samples: 5K' heading for large observations.
    rows = re.findall(r'^\s*\d+(?:\.\d+)?%\s+(\d+)\s+(\d+)\s+.*?\s+\[[k.u]\]\s+(.+)$', report, re.M)
    if sum(int(row[0]) for row in rows) != len(expected) or sum(int(row[1]) for row in rows) != periods:
        raise ValueError("native perf function rows do not account for every selected sample and period")
    return {'sample_count': len(expected), 'total_period_ns': periods,
            'sources': sorted({sample[0] for sample in expected}),
            'raw_fields_verified': ['source_id', 'ip', 'pid', 'tid', 'timestamp_ns', 'cpu', 'period_ns', 'mode', 'context_markers', 'callchain'],
            'query': query, 'function_rows': [{'samples': int(n), 'period_ns': int(p), 'symbol': symbol} for n, p, symbol in rows]}
