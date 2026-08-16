import struct
from dataclasses import dataclass

SYNC = 0xA55A
SYNC_BYTES = struct.pack("<H", SYNC)

HEADER_FMT = "<HBBIHH"
HEADER_LEN = struct.calcsize(HEADER_FMT)
MAX_PAYLOAD_LEN = 512

BITS_PER_BYTE = 8
BYTE_MASK = (1 << BITS_PER_BYTE) - 1            # 0xFF

# CRC-16/IBM-3740. All of poly, init, xorout, reflection, and width are ICD
# terms -- firmware must match every one of them, not just the polynomial.
# Reflection is not implemented because this variant does not use it: bits are
# processed MSB-first.
CRC_WIDTH_BITS = 16
CRC_FMT = "<H"                                  # wire encoding; must match CRC_WIDTH_BITS
CRC_LEN = struct.calcsize(CRC_FMT)              # bytes on the wire
CRC_POLY = 0x1021                               # x^16 + x^12 + x^5 + 1
CRC_INIT = 0xFFFF                               # seed; see note below re CRC_MASK
CRC_XOROUT = 0x0000                             # IBM-3740 applies no final XOR
CRC_MASK = (1 << CRC_WIDTH_BITS) - 1            # 0xFFFF, keeps the register 16-bit
CRC_MSB = 1 << (CRC_WIDTH_BITS - 1)             # 0x8000, top bit of the register
CRC_TABLE_SIZE = 1 << BITS_PER_BYTE             # 256, one entry per byte value
CRC_BYTE_SHIFT = CRC_WIDTH_BITS - BITS_PER_BYTE # aligns a byte with the register top

def _build_crc_table() -> tuple[int, ...]:
    """
    Precompute each byte value's CRC contribution so the runtime loop is a single lookup per byte.
    """
    table = []
    for byte in range(CRC_TABLE_SIZE):
        crc = byte << CRC_BYTE_SHIFT
        for _ in range(BITS_PER_BYTE):
            if crc & CRC_MSB:
                crc = ((crc << 1) ^ CRC_POLY) & CRC_MASK
            else:
                crc = (crc << 1) & CRC_MASK
        table.append(crc)
    return tuple(table)

_CRC_TABLE = _build_crc_table()

def crc16(data: bytes) -> int:
    """
    CRC-16/IBM-3740 over `data`.
    """
    crc = CRC_INIT
    for byte in data:
        table_idx = ((crc >> CRC_BYTE_SHIFT) ^ byte) & BYTE_MASK
        crc = ((crc << BITS_PER_BYTE) & CRC_MASK) ^ _CRC_TABLE[table_idx]
    return crc ^ CRC_XOROUT

@dataclass(frozen=True)
class Frame:
    schema_ver: int
    frame_type: int
    t_raw: int
    seq: int
    payload: bytes

@dataclass
class ParserStats:
    ok_frames: int = 0
    crc_errors: int = 0
    bad_length: int = 0
    bytes_discarded: int = 0
    schema_mismatch: int = 0

class FrameParser:
    def __init__(self) -> None:
        self._buf = bytearray()
        self.stats = ParserStats()

    def _skip_sync(self) -> None:
        self.stats.bytes_discarded += len(SYNC_BYTES)
        del self._buf[:len(SYNC_BYTES)]

    def feed(self, chunk: bytes) -> list[Frame]:
        self._buf.extend(chunk)
        frames: list[Frame] = []

        while True:
            frame_start_idx = self._buf.find(SYNC_BYTES)

            if frame_start_idx < 0:
                # Sync byte not found
                keep_bytes = min(len(SYNC_BYTES) - 1, len(self._buf)) # handles fragmented sync word and empty buffer cases
                drop_bytes = len(self._buf) - keep_bytes
                if drop_bytes > 0:
                    self.stats.bytes_discarded += drop_bytes
                    del self._buf[:drop_bytes]
                break

            if frame_start_idx > 0:
                self.stats.bytes_discarded += frame_start_idx
                del self._buf[:frame_start_idx]

            if len(self._buf) < HEADER_LEN:
                # header is incomplete
                break

            _sync, schema_ver, frame_type, t_raw, seq, payload_len = struct.unpack_from(HEADER_FMT, self._buf, 0)

            if payload_len > MAX_PAYLOAD_LEN:
                # False sync candidate led to false length. Attempt a new scan
                self.stats.bad_length += 1
                self._skip_sync()
                continue

            packet_len = HEADER_LEN + payload_len + CRC_LEN
            if len(self._buf) < packet_len:
                break  # frame still incomplete, wait for more

            packet_body = bytes(self._buf[:HEADER_LEN + payload_len])
            (rx_crc,) = struct.unpack_from(CRC_FMT, self._buf, HEADER_LEN + payload_len)

            if crc16(packet_body) != rx_crc:
                self.stats.crc_errors += 1
                self._skip_sync()
                continue

            if schema_ver != self._expected_schema:
                # Refuse to decode a layout we don't have a config for.
                self.stats.schema_mismatch += 1
                del self._buf[:packet_len]
                continue

            frames.append(Frame(
                schema_ver = schema_ver,
                frame_type = frame_type,
                t_raw = t_raw,
                seq = seq,
                payload = packet_body[HEADER_LEN:],
            ))
            self.stats.frames_ok += 1
            del self._buf[:packet_len]

        return frames