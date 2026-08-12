#!/usr/bin/env python3
"""Internal battery energy-storage device API for the SCADA testbed."""

import argparse
import json
import math
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


STARTED_AT = time.time()
REQUIRED_CONTROL_BIT = "1"
REQUEST_WINDOW = deque()
REQUEST_LOCK = threading.Lock()
CONFIG = {
    "capacity_per_second": 20,
    "overload_mode": "delay",
    "overload_delay_seconds": 3.0,
}
CONTROL_STATE = {
    "mode": "standby",
    "last_command": "none",
    "accepted_commands": 0,
    "rejected_commands": 0,
    "last_reject_reason": "",
}
AVAILABILITY = {
    "accepted_requests": 0,
    "overload_events": 0,
    "overload_rejections": 0,
    "overload_delays": 0,
    "current_request_rate": 0,
    "available": True,
}


def check_capacity():
    now = time.time()
    with REQUEST_LOCK:
        while REQUEST_WINDOW and now - REQUEST_WINDOW[0] > 1.0:
            REQUEST_WINDOW.popleft()
        current_rate = len(REQUEST_WINDOW)
        AVAILABILITY["current_request_rate"] = current_rate
        if current_rate >= CONFIG["capacity_per_second"]:
            AVAILABILITY["available"] = False
            AVAILABILITY["overload_events"] += 1
            return False
        REQUEST_WINDOW.append(now)
        AVAILABILITY["accepted_requests"] += 1
        AVAILABILITY["current_request_rate"] = len(REQUEST_WINDOW)
        AVAILABILITY["available"] = True
        return True


def battery_status():
    elapsed = time.time() - STARTED_AT
    return {
        "asset": "battery-energy-storage-system",
        "ip_role": "internal_scada_battery",
        "status": "online" if AVAILABILITY["available"] else "overloaded",
        "state_of_charge_percent": round(67.5 + 3.5 * math.sin(elapsed / 40.0), 1),
        "power_kw": round(28.0 + 9.0 * math.sin(elapsed / 15.0), 1),
        "dc_bus_voltage_v": round(782.0 + 4.0 * math.sin(elapsed / 18.0), 1),
        "temperature_c": round(31.0 + 1.5 * math.sin(elapsed / 22.0), 1),
        "control": dict(CONTROL_STATE),
        "availability": {**AVAILABILITY, **CONFIG},
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def json_response(handler, status_code, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def handle_over_capacity(self):
        if check_capacity():
            return False
        print(
            f"battery_overloaded source={self.client_address[0]} rate={AVAILABILITY['current_request_rate']} capacity={CONFIG['capacity_per_second']} mode={CONFIG['overload_mode']}",
            flush=True,
        )
        if CONFIG["overload_mode"] == "reject":
            AVAILABILITY["overload_rejections"] += 1
            json_response(self, 503, {"available": False, "reason": "battery_request_capacity_exceeded", "availability": {**AVAILABILITY, **CONFIG}})
            return True
        AVAILABILITY["overload_delays"] += 1
        time.sleep(CONFIG["overload_delay_seconds"])
        return False

    def do_GET(self):
        if self.handle_over_capacity():
            return
        path = urlparse(self.path).path
        if path in ("/", "/api/status"):
            json_response(self, 200, battery_status())
            return
        json_response(self, 404, {"error": "not found"})

    def do_POST(self):
        if self.handle_over_capacity():
            return
        path = urlparse(self.path).path
        if path != "/api/control":
            json_response(self, 404, {"error": "not found"})
            return

        control_bit = self.headers.get("X-SCADA-Control-Bit", "")
        if control_bit != REQUIRED_CONTROL_BIT:
            CONTROL_STATE["rejected_commands"] += 1
            CONTROL_STATE["last_reject_reason"] = "bad_control_bit"
            print(
                f"battery_control rejected source={self.client_address[0]} reason=bad_control_bit bit={control_bit!r}",
                flush=True,
            )
            json_response(self, 403, {"accepted": False, "reason": "bad_control_bit"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            CONTROL_STATE["rejected_commands"] += 1
            CONTROL_STATE["last_reject_reason"] = "bad_json"
            json_response(self, 400, {"accepted": False, "reason": "bad_json"})
            return

        command = str(payload.get("command", "maintain"))
        if command not in {"maintain", "charge", "discharge", "standby"}:
            CONTROL_STATE["rejected_commands"] += 1
            CONTROL_STATE["last_reject_reason"] = "unknown_command"
            json_response(self, 400, {"accepted": False, "reason": "unknown_command"})
            return

        CONTROL_STATE["accepted_commands"] += 1
        CONTROL_STATE["last_command"] = command
        CONTROL_STATE["mode"] = command
        CONTROL_STATE["last_reject_reason"] = ""
        print(f"battery_control accepted source={self.client_address[0]} command={command}", flush=True)
        json_response(self, 200, {"accepted": True, "command": command, "control": dict(CONTROL_STATE)})

    def log_message(self, fmt, *args):
        print(f"battery: {self.address_string()} - {fmt % args}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Serve internal battery device status/control")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--capacity", type=int, default=20)
    parser.add_argument("--overload-mode", choices=["delay", "reject"], default="delay")
    parser.add_argument("--overload-delay", type=float, default=3.0)
    args = parser.parse_args()
    CONFIG["capacity_per_second"] = max(1, args.capacity)
    CONFIG["overload_mode"] = args.overload_mode
    CONFIG["overload_delay_seconds"] = max(0.0, args.overload_delay)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"battery API listening on http://{args.host}:{args.port}/api/status", flush=True)
    print(f"battery capacity limit: {CONFIG['capacity_per_second']} requests/sec", flush=True)
    print(f"battery overload mode: {CONFIG['overload_mode']} delay={CONFIG['overload_delay_seconds']}s", flush=True)
    print("battery control endpoint requires X-SCADA-Control-Bit: 1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
