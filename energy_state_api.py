#!/usr/bin/env python3
"""External energy-state API for the energy-infrastructure scenario."""

import argparse
import json
import math
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


STARTED_AT = time.time()


def current_state():
    elapsed = time.time() - STARTED_AT
    daylight = max(0.0, math.sin((elapsed / 120.0) * math.pi))
    solar_kw = 180.0 + daylight * 65.0
    site_load_kw = 210.0 + 18.0 * math.sin(elapsed / 18.0)
    battery_soc = 68.0 + 4.0 * math.sin(elapsed / 35.0)
    battery_kw = site_load_kw - solar_kw

    return {
        "site": "microgrid-alpha",
        "asset_type": "energy_infrastructure_state",
        "solar": {
            "status": "online",
            "generation_kw": round(solar_kw, 1),
            "inverter_temp_c": round(39.0 + 2.0 * math.sin(elapsed / 20.0), 1),
        },
        "battery": {
            "status": "online",
            "state_of_charge_percent": round(battery_soc, 1),
            "power_kw": round(battery_kw, 1),
        },
        "grid": {
            "frequency_hz": round(60.0 + 0.02 * math.sin(elapsed / 12.0), 3),
            "breaker_closed": True,
        },
        "control_panel": {
            "mode": "automatic",
            "operator_command": "maintain_load",
        },
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/api/state"):
            payload = json.dumps(current_state()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"not found\n")

    def log_message(self, fmt, *args):
        print(f"energy api: {self.address_string()} - {fmt % args}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Serve dummy energy infrastructure state")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"energy api listening on http://{args.host}:{args.port}/api/state", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

