"""Rule-based detection of attacker behavior against the simulated BMS.

Each rule maps to a technique in the MITRE ATT&CK for ICS matrix so alerts
can be explained in the language defenders already use.
"""

import time
from collections import defaultdict, deque

from . import modbus

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

RULES = {
    "DECOY_CONTACT": {
        "severity": "low",
        "title": "New source contacted the decoy",
        "attack": "T0846 Remote System Discovery",
    },
    "DEVICE_FINGERPRINT": {
        "severity": "medium",
        "title": "Device fingerprinting",
        "attack": "T0888 Remote System Information Discovery",
    },
    "ADDRESS_SCAN": {
        "severity": "medium",
        "title": "Register address scanning",
        "attack": "T0861 Point & Tag Identification",
    },
    "HIGH_REQUEST_RATE": {
        "severity": "medium",
        "title": "High request rate from one source",
        "attack": "T0846 Remote System Discovery",
    },
    "INVALID_FUNCTION": {
        "severity": "medium",
        "title": "Unsupported function code (possible fuzzing)",
        "attack": "T0814 Denial of Service",
    },
    "UNAUTHORIZED_WRITE": {
        "severity": "high",
        "title": "Unauthorized write to controller",
        "attack": "T0836 Modify Parameter",
    },
    "UNSAFE_SETPOINT": {
        "severity": "critical",
        "title": "Setpoint written outside safe range",
        "attack": "T0836 Modify Parameter / T0879 Damage to Property",
    },
    "SAFETY_SYSTEM_TAMPERING": {
        "severity": "critical",
        "title": "Life-safety point changed",
        "attack": "T0880 Loss of Safety",
    },
}


class Detector:
    def __init__(self, rate_window=10, rate_threshold=30, scan_threshold=5, clock=time.time):
        self.rate_window = rate_window
        self.rate_threshold = rate_threshold
        self.scan_threshold = scan_threshold
        self.clock = clock
        self._requests = defaultdict(deque)       # src_ip -> timestamps
        self._address_errors = defaultdict(int)   # src_ip -> illegal address count
        self._fired_once = defaultdict(set)       # src_ip -> rules that fire once per source

    def _alert(self, rule, detail):
        meta = RULES[rule]
        return {"rule": rule, "severity": meta["severity"], "title": meta["title"],
                "attack": meta["attack"], "detail": detail}

    def _once(self, src, rule):
        if rule in self._fired_once[src]:
            return False
        self._fired_once[src].add(rule)
        return True

    def inspect(self, src, details):
        """Return a list of alerts for one request from `src`."""
        alerts = []
        fc = details.get("function")
        now = self.clock()

        # A decoy has no legitimate users, so the first request from any source is suspicious
        if self._once(src, "DECOY_CONTACT"):
            alerts.append(self._alert("DECOY_CONTACT",
                          "no legitimate system should talk to this device"))

        # Rate of requests from this source
        window = self._requests[src]
        window.append(now)
        while window and now - window[0] > self.rate_window:
            window.popleft()
        if len(window) >= self.rate_threshold and self._once(src, "HIGH_REQUEST_RATE"):
            alerts.append(self._alert("HIGH_REQUEST_RATE",
                          f"{len(window)} requests in {self.rate_window}s"))

        if fc in modbus.RECON_FUNCTIONS:
            alerts.append(self._alert("DEVICE_FINGERPRINT",
                          f"{modbus.function_name(fc)} request reveals vendor and firmware"))

        exc = details.get("exception")
        if exc == modbus.ILLEGAL_FUNCTION and fc not in modbus.RECON_FUNCTIONS:
            alerts.append(self._alert("INVALID_FUNCTION",
                          f"function code {fc} is not used by this controller"))

        if exc == modbus.ILLEGAL_DATA_ADDRESS:
            self._address_errors[src] += 1
            if self._address_errors[src] >= self.scan_threshold and self._once(src, "ADDRESS_SCAN"):
                alerts.append(self._alert("ADDRESS_SCAN",
                              f"{self._address_errors[src]} requests to addresses that do not exist"))

        for w in details.get("writes", []):
            change = f"{w['name']}: {w['old_text']} -> {w['new_text']}"
            if w.get("safety"):
                alerts.append(self._alert("SAFETY_SYSTEM_TAMPERING", change))
            elif (w.get("safe_min") is not None and not w["safe_min"] <= w["new"] <= w["safe_max"]):
                alerts.append(self._alert("UNSAFE_SETPOINT", change))
            else:
                alerts.append(self._alert("UNAUTHORIZED_WRITE", change))

        return alerts
