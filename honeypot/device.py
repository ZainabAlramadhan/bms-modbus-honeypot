"""Simulated BMS building controller that answers Modbus requests.

The device keeps realistic state: live sensor readings drift over time and
writes from an attacker really change the values they read back afterwards,
so the honeypot behaves like a real controller instead of a static responder.
"""

import json
import random
import struct

from . import modbus


class Point:
    def __init__(self, spec):
        self.address = spec["address"]
        self.name = spec["name"]
        self.unit = spec.get("unit", "")
        self.scale = spec.get("scale", 1)
        self.base = spec["value"]
        self.value = spec["value"]
        self.jitter = spec.get("jitter", 0)
        self.safe_min = spec.get("safe_min")
        self.safe_max = spec.get("safe_max")
        self.safety = spec.get("safety", False)

    def describe(self, raw):
        """Human readable value, e.g. 45.0 C."""
        if isinstance(raw, bool):
            return "ON" if raw else "OFF"
        shown = raw / self.scale if self.scale != 1 else raw
        return f"{shown:g} {self.unit}".strip()


class BMSDevice:
    def __init__(self, profile, rng=None):
        self.profile = profile
        self.identity = profile["identity"]
        self.rng = rng or random.Random()
        self.tables = {
            "holding": {p["address"]: Point(p) for p in profile["holding_registers"]},
            "input": {p["address"]: Point(p) for p in profile["input_registers"]},
            "coil": {p["address"]: Point(p) for p in profile["coils"]},
            "discrete": {p["address"]: Point(p) for p in profile["discrete_inputs"]},
        }

    @classmethod
    def from_file(cls, path, rng=None):
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh), rng=rng)

    def point(self, table, address):
        return self.tables[table].get(address)

    # ------------------------------------------------------------------
    def _drift(self):
        """Let sensor readings move a little, like a real building."""
        for p in self.tables["input"].values():
            if p.jitter:
                p.value = p.base + self.rng.randint(-p.jitter, p.jitter)

    def _read_block(self, table, address, count):
        points = self.tables[table]
        if count < 1 or count > 125:
            return None, modbus.ILLEGAL_DATA_VALUE
        values = []
        for a in range(address, address + count):
            if a not in points:
                return None, modbus.ILLEGAL_DATA_ADDRESS
            values.append(points[a].value)
        return values, None

    # ------------------------------------------------------------------
    def handle(self, pdu):
        """Process one request PDU.

        Returns (response_pdu, details) where details describes the request
        for logging: function, address, count, written values, exception.
        """
        if not pdu:
            return modbus.exception_pdu(0, modbus.ILLEGAL_FUNCTION), {"function": 0, "exception": modbus.ILLEGAL_FUNCTION}

        fc = pdu[0]
        details = {"function": fc, "function_name": modbus.function_name(fc)}
        self._drift()

        try:
            if fc in (1, 2, 3, 4):
                address, count = struct.unpack_from(">HH", pdu, 1)
                details.update(address=address, count=count)
                table = {1: "coil", 2: "discrete", 3: "holding", 4: "input"}[fc]
                values, err = self._read_block(table, address, count)
                if err:
                    return self._exception(fc, err, details)
                if fc in (1, 2):
                    body = modbus.pack_bits(values)
                else:
                    body = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
                return bytes([fc, len(body)]) + body, details

            if fc == 5:
                address, raw = struct.unpack_from(">HH", pdu, 1)
                details.update(address=address, count=1)
                if raw not in (0x0000, 0xFF00):
                    return self._exception(fc, modbus.ILLEGAL_DATA_VALUE, details)
                p = self.point("coil", address)
                if p is None:
                    return self._exception(fc, modbus.ILLEGAL_DATA_ADDRESS, details)
                details["writes"] = [self._record_write("coil", p, raw == 0xFF00)]
                return pdu[:5], details

            if fc == 6:
                address, value = struct.unpack_from(">HH", pdu, 1)
                details.update(address=address, count=1)
                p = self.point("holding", address)
                if p is None:
                    return self._exception(fc, modbus.ILLEGAL_DATA_ADDRESS, details)
                details["writes"] = [self._record_write("holding", p, value)]
                return pdu[:5], details

            if fc == 16:
                address, count, nbytes = struct.unpack_from(">HHB", pdu, 1)
                details.update(address=address, count=count)
                if count < 1 or count > 123 or nbytes != count * 2 or len(pdu) < 6 + nbytes:
                    return self._exception(fc, modbus.ILLEGAL_DATA_VALUE, details)
                values = struct.unpack_from(f">{count}H", pdu, 6)
                points = [self.point("holding", address + i) for i in range(count)]
                if any(p is None for p in points):
                    return self._exception(fc, modbus.ILLEGAL_DATA_ADDRESS, details)
                details["writes"] = [self._record_write("holding", p, v) for p, v in zip(points, values)]
                return struct.pack(">BHH", fc, address, count), details

            if fc == 15:
                address, count, nbytes = struct.unpack_from(">HHB", pdu, 1)
                details.update(address=address, count=count)
                if count < 1 or count > 1968 or nbytes != (count + 7) // 8:
                    return self._exception(fc, modbus.ILLEGAL_DATA_VALUE, details)
                bits = modbus.unpack_bits(pdu[6:6 + nbytes], count)
                points = [self.point("coil", address + i) for i in range(count)]
                if any(p is None for p in points):
                    return self._exception(fc, modbus.ILLEGAL_DATA_ADDRESS, details)
                details["writes"] = [self._record_write("coil", p, b) for p, b in zip(points, bits)]
                return struct.pack(">BHH", fc, address, count), details

            if fc == 43 and len(pdu) >= 2 and pdu[1] == 0x0E:
                return self._device_identification(), details

            if fc == 17:
                info = f"{self.identity['model']} {self.identity['revision']}".encode()
                body = bytes([self.profile.get("unit_id", 1), 0xFF]) + info
                return bytes([fc, len(body)]) + body, details

        except struct.error:
            return self._exception(fc, modbus.ILLEGAL_DATA_VALUE, details)

        return self._exception(fc, modbus.ILLEGAL_FUNCTION, details)

    # ------------------------------------------------------------------
    def _exception(self, fc, code, details):
        details["exception"] = code
        details["exception_name"] = modbus.EXCEPTION_NAMES.get(code, str(code))
        return modbus.exception_pdu(fc, code), details

    def _record_write(self, table, point, new_value):
        old = point.value
        point.value = new_value
        if table == "holding":
            point.base = new_value
        return {
            "table": table,
            "address": point.address,
            "name": point.name,
            "old": old,
            "new": new_value,
            "old_text": point.describe(old),
            "new_text": point.describe(new_value),
            "safe_min": point.safe_min,
            "safe_max": point.safe_max,
            "safety": point.safety,
        }

    def _device_identification(self):
        objects = [
            (0x00, self.identity["vendor"]),
            (0x01, self.identity["product_code"]),
            (0x02, self.identity["revision"]),
        ]
        body = bytearray([43, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)])
        for oid, text in objects:
            data = text.encode()
            body += bytes([oid, len(data)]) + data
        return bytes(body)
