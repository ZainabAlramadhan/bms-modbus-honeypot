"""Asyncio Modbus TCP honeypot server with structured JSON logging."""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from . import modbus
from .detector import SEVERITY_ORDER, Detector
from .device import BMSDevice

log = logging.getLogger("honeypot")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EventLog:
    """Append-only JSON Lines log, one event per line."""

    def __init__(self, path):
        self.path = path

    def write(self, event):
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")


class Honeypot:
    def __init__(self, device: BMSDevice, event_log: EventLog, detector: Detector = None,
                 idle_timeout=60):
        self.device = device
        self.events = event_log
        self.detector = detector or Detector()
        self.idle_timeout = idle_timeout

    def _emit(self, event):
        self.events.write(event)
        for alert in event.get("alerts", []):
            log.warning("[%s] %s from %s - %s",
                        alert["severity"].upper(), alert["title"], event["src_ip"], alert["detail"])

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        src_ip, src_port = peer[0], peer[1]
        session = uuid.uuid4().hex[:8]
        requests = 0
        log.info("connection from %s:%s (session %s)", src_ip, src_port, session)
        self._emit({"ts": utc_now(), "event": "connect", "session": session,
                    "src_ip": src_ip, "src_port": src_port})
        buffer = b""
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=self.idle_timeout)
                if not data:
                    break
                buffer += data
                try:
                    frames, buffer = modbus.split_frames(buffer)
                except modbus.FrameError as err:
                    self._emit({"ts": utc_now(), "event": "malformed", "session": session,
                                "src_ip": src_ip, "src_port": src_port,
                                "error": str(err), "raw_hex": buffer[:64].hex()})
                    break
                for tid, unit, pdu in frames:
                    requests += 1
                    response, details = self.device.handle(pdu)
                    alerts = self.detector.inspect(src_ip, details)
                    event = {"ts": utc_now(), "event": "request", "session": session,
                             "src_ip": src_ip, "src_port": src_port, "unit_id": unit,
                             "transaction_id": tid, "raw_hex": pdu[:64].hex(), **details,
                             "alerts": alerts}
                    if alerts:
                        event["max_severity"] = max((a["severity"] for a in alerts),
                                                    key=SEVERITY_ORDER.get)
                    self._emit(event)
                    writer.write(modbus.build_frame(tid, unit, response))
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            self._emit({"ts": utc_now(), "event": "disconnect", "session": session,
                        "src_ip": src_ip, "src_port": src_port, "requests": requests})
            log.info("session %s closed after %d requests", session, requests)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def serve(self, host, port):
        server = await asyncio.start_server(self.handle_client, host, port)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        log.info("BMS honeypot listening on %s", addrs)
        async with server:
            await server.serve_forever()
