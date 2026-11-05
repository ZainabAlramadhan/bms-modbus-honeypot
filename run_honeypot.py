#!/usr/bin/env python3
"""Start the BMS Modbus honeypot.

Example:
    python run_honeypot.py --port 5020 --log logs/events.jsonl
"""

import argparse
import asyncio
import logging
import os

from honeypot.detector import Detector
from honeypot.device import BMSDevice
from honeypot.server import EventLog, Honeypot


def main():
    parser = argparse.ArgumentParser(description="BMS Modbus TCP honeypot")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5020,
                        help="TCP port (default 5020; the standard Modbus port 502 needs admin rights)")
    parser.add_argument("--profile", default="config/device_profile.json", help="device profile JSON")
    parser.add_argument("--log", default="logs/events.jsonl", help="JSON Lines event log")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    os.makedirs(os.path.dirname(args.log) or ".", exist_ok=True)

    honeypot = Honeypot(BMSDevice.from_file(args.profile), EventLog(args.log), Detector())
    try:
        asyncio.run(honeypot.serve(args.host, args.port))
    except KeyboardInterrupt:
        logging.info("stopped")


if __name__ == "__main__":
    main()
