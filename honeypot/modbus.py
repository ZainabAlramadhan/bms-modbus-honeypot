"""Minimal Modbus TCP protocol helpers (framing, parsing, building).

Implemented from the Modbus Application Protocol specification with the
Python standard library only, so every byte an attacker sends can be logged.
"""

import struct

MBAP_HEADER = struct.Struct(">HHHB")  # transaction id, protocol id, length, unit id
MAX_PDU = 253

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    8: "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}

READ_FUNCTIONS = {1, 2, 3, 4}
WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}
RECON_FUNCTIONS = {17, 43}

# Exception codes
ILLEGAL_FUNCTION = 0x01
ILLEGAL_DATA_ADDRESS = 0x02
ILLEGAL_DATA_VALUE = 0x03
EXCEPTION_NAMES = {
    ILLEGAL_FUNCTION: "Illegal Function",
    ILLEGAL_DATA_ADDRESS: "Illegal Data Address",
    ILLEGAL_DATA_VALUE: "Illegal Data Value",
}


class FrameError(ValueError):
    """Raised when bytes on the wire are not a valid Modbus TCP frame."""


def function_name(code):
    return FUNCTION_NAMES.get(code, f"Unknown ({code})")


def split_frames(buffer):
    """Split a byte buffer into complete frames.

    Returns (frames, remaining_bytes). Each frame is (transaction_id, unit_id, pdu).
    Raises FrameError for data that cannot be Modbus TCP (wrong protocol id or length).
    """
    frames = []
    while len(buffer) >= MBAP_HEADER.size:
        tid, pid, length, unit = MBAP_HEADER.unpack_from(buffer)
        if pid != 0:
            raise FrameError(f"protocol id {pid} is not Modbus")
        if length < 2 or length > MAX_PDU + 1:
            raise FrameError(f"invalid length field {length}")
        total = MBAP_HEADER.size - 1 + length  # length counts the unit id byte
        if len(buffer) < total:
            break
        pdu = bytes(buffer[MBAP_HEADER.size:total])
        frames.append((tid, unit, pdu))
        buffer = buffer[total:]
    return frames, buffer


def build_frame(transaction_id, unit_id, pdu):
    return MBAP_HEADER.pack(transaction_id, 0, len(pdu) + 1, unit_id) + pdu


def exception_pdu(function_code, exception_code):
    return bytes([(function_code | 0x80) & 0xFF, exception_code])


def pack_bits(bits):
    """Pack a list of booleans into Modbus bit bytes (LSB first)."""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def unpack_bits(data, count):
    return [bool(data[i // 8] >> (i % 8) & 1) for i in range(count)]


# ---------------------------------------------------------------------------
# Client-side request builders (used by the attack simulator and tests)
# ---------------------------------------------------------------------------

def read_request(function_code, address, count):
    return struct.pack(">BHH", function_code, address, count)


def write_single_register_request(address, value):
    return struct.pack(">BHH", 6, address, value & 0xFFFF)


def write_single_coil_request(address, on):
    return struct.pack(">BHH", 5, address, 0xFF00 if on else 0x0000)


def write_multiple_registers_request(address, values):
    body = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    return struct.pack(">BHHB", 16, address, len(values), len(body)) + body


def device_identification_request():
    return bytes([43, 0x0E, 0x01, 0x00])


def report_server_id_request():
    return bytes([17])
