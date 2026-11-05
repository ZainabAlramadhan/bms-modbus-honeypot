import asyncio
import json
import os
import random
import struct
import tempfile
import unittest

from honeypot import modbus
from honeypot.detector import Detector
from honeypot.device import BMSDevice
from honeypot.server import EventLog, Honeypot

PROFILE = os.path.join(os.path.dirname(__file__), "..", "config", "device_profile.json")


def device():
    return BMSDevice.from_file(PROFILE, rng=random.Random(1))


class ModbusFramingTests(unittest.TestCase):
    def test_round_trip_frame(self):
        frame = modbus.build_frame(7, 1, modbus.read_request(3, 0, 2))
        frames, rest = modbus.split_frames(frame)
        self.assertEqual(rest, b"")
        self.assertEqual(frames, [(7, 1, bytes([3, 0, 0, 0, 2]))])

    def test_partial_frame_waits_for_more_bytes(self):
        frame = modbus.build_frame(1, 1, modbus.read_request(3, 0, 2))
        frames, rest = modbus.split_frames(frame[:-2])
        self.assertEqual(frames, [])
        self.assertEqual(rest, frame[:-2])

    def test_non_modbus_traffic_is_rejected(self):
        with self.assertRaises(modbus.FrameError):
            modbus.split_frames(b"GET / HTTP/1.1\r\n\r\n")

    def test_bit_packing(self):
        bits = [True, False, True, True, False, False, False, False, True]
        self.assertEqual(modbus.unpack_bits(modbus.pack_bits(bits), len(bits)), bits)


class DeviceTests(unittest.TestCase):
    def test_read_holding_registers(self):
        resp, details = device().handle(modbus.read_request(3, 0, 3))
        self.assertEqual(resp[:2], bytes([3, 6]))
        self.assertEqual(struct.unpack(">3H", resp[2:]), (220, 225, 140))
        self.assertNotIn("exception", details)

    def test_illegal_address_returns_exception(self):
        resp, details = device().handle(modbus.read_request(3, 500, 1))
        self.assertEqual(resp, bytes([0x83, modbus.ILLEGAL_DATA_ADDRESS]))
        self.assertEqual(details["exception"], modbus.ILLEGAL_DATA_ADDRESS)

    def test_unknown_function_returns_illegal_function(self):
        resp, _ = device().handle(bytes([90, 0, 0]))
        self.assertEqual(resp, bytes([90 | 0x80, modbus.ILLEGAL_FUNCTION]))

    def test_write_changes_state(self):
        d = device()
        d.handle(modbus.write_single_register_request(0, 350))
        resp, _ = d.handle(modbus.read_request(3, 0, 1))
        self.assertEqual(struct.unpack(">H", resp[2:4])[0], 350)

    def test_device_identification_reveals_vendor(self):
        resp, _ = device().handle(modbus.device_identification_request())
        self.assertIn(b"Falcon Building Systems", resp)


class DetectorTests(unittest.TestCase):
    def rules(self, alerts):
        return {a["rule"] for a in alerts} - {"DECOY_CONTACT"}

    def test_first_contact_is_flagged_once(self):
        det, d = Detector(), device()
        first = det.inspect("10.0.0.3", d.handle(modbus.read_request(4, 0, 1))[1])
        second = det.inspect("10.0.0.3", d.handle(modbus.read_request(4, 0, 1))[1])
        self.assertEqual([a["rule"] for a in first], ["DECOY_CONTACT"])
        self.assertEqual(second, [])

    def test_unsafe_setpoint_is_critical(self):
        _, details = device().handle(modbus.write_single_register_request(0, 350))
        alerts = Detector().inspect("10.0.0.5", details)
        self.assertEqual(self.rules(alerts), {"UNSAFE_SETPOINT"})
        self.assertIn("critical", [a["severity"] for a in alerts if a["rule"] == "UNSAFE_SETPOINT"])

    def test_safe_write_is_still_unauthorized(self):
        _, details = device().handle(modbus.write_single_register_request(3, 80))
        self.assertEqual(self.rules(Detector().inspect("10.0.0.5", details)), {"UNAUTHORIZED_WRITE"})

    def test_safety_coil_tampering(self):
        _, details = device().handle(modbus.write_single_coil_request(5, True))
        self.assertEqual(self.rules(Detector().inspect("10.0.0.5", details)), {"SAFETY_SYSTEM_TAMPERING"})

    def test_fingerprinting(self):
        _, details = device().handle(modbus.device_identification_request())
        self.assertEqual(self.rules(Detector().inspect("10.0.0.5", details)), {"DEVICE_FINGERPRINT"})

    def test_address_scan_fires_once_after_threshold(self):
        det, d, fired = Detector(scan_threshold=5), device(), []
        for addr in range(100, 110):
            _, details = d.handle(modbus.read_request(3, addr, 1))
            fired += [a["rule"] for a in det.inspect("10.0.0.9", details)]
        self.assertEqual(fired.count("ADDRESS_SCAN"), 1)

    def test_high_request_rate(self):
        clock = iter(range(1000))
        det, d, fired = Detector(rate_threshold=10, clock=lambda: next(clock) * 0.1), device(), []
        for _ in range(15):
            _, details = d.handle(modbus.read_request(4, 0, 2))
            fired += [a["rule"] for a in det.inspect("10.0.0.7", details)]
        self.assertEqual(fired.count("HIGH_REQUEST_RATE"), 1)


class ServerIntegrationTest(unittest.TestCase):
    def test_end_to_end_logging(self):
        async def scenario(log_path):
            hp = Honeypot(device(), EventLog(log_path), Detector())
            server = await asyncio.start_server(hp.handle_client, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(modbus.build_frame(1, 1, modbus.write_single_coil_request(4, True)))
            await writer.drain()
            header = await reader.readexactly(7)
            _, _, length, _ = modbus.MBAP_HEADER.unpack(header)
            body = await reader.readexactly(length - 1)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.1)
            server.close()
            await server.wait_closed()
            return body

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            body = asyncio.run(scenario(path))
            self.assertEqual(body[0], 5)
            with open(path) as fh:
                events = [json.loads(line) for line in fh]
            self.assertEqual([e["event"] for e in events], ["connect", "request", "disconnect"])
            self.assertIn("SAFETY_SYSTEM_TAMPERING", [a["rule"] for a in events[1]["alerts"]])
            self.assertEqual(events[1]["max_severity"], "critical")


if __name__ == "__main__":
    unittest.main()
