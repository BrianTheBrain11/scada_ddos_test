#!/usr/bin/env python3
"""Internal battery energy-storage device API for the SCADA testbed."""

import argparse
import json
import math
import os
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


STARTED_AT = time.time()
REQUIRED_CONTROL_BIT = "1"
CONFIG = {
    "capacity_per_second": 20,
    "worker_slots": 4,
    "normal_service_time_seconds": 0.05,
    "malformed_service_time_seconds": 0.2,
    "queue_timeout_seconds": 0.2,
    "fair_queue_enabled": False,
    "policy_file": "/tmp/battery_policy.json",
}
WORKER_SEMAPHORE = None
STATE_LOCK = threading.RLock()
CAPACITY_CONDITION = threading.Condition(STATE_LOCK)
REQUEST_WINDOW = deque()
CAPACITY_WAITERS = deque()
SOURCE_WINDOWS = defaultdict(deque)
MALFORMED_WINDOWS = defaultdict(deque)
POLICY = {
    "connection_limiting_enabled": False,
    "rate_limiting_enabled": False,
    "conn_threshold": 8,
    "frame_rate_limit": 8,
    "allowlist": {"10.0.1.20"},
    "policy_mtime": 0.0,
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
    "queued_timeouts": 0,
    "current_request_rate": 0,
    "current_inflight": 0,
    "normal_processed": 0,
    "malformed_processed": 0,
    "connections_blocked": 0,
    "frames_blocked_rate": 0,
    "frames_blocked_malformed": 0,
    "available": True,
}


def parse_allowlist(value):
    if isinstance(value, str):
        return {item.strip() for item in value.split(",") if item.strip()}
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def refresh_policy():
    policy_file = CONFIG["policy_file"]
    try:
        mtime = os.path.getmtime(policy_file)
    except OSError:
        return
    with STATE_LOCK:
        if mtime <= POLICY["policy_mtime"]:
            return
    try:
        with open(policy_file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return
    with STATE_LOCK:
        POLICY["connection_limiting_enabled"] = bool(payload.get("connection_limiting_enabled", False))
        POLICY["rate_limiting_enabled"] = bool(payload.get("rate_limiting_enabled", False))
        POLICY["conn_threshold"] = max(0, int(payload.get("conn_threshold", 8)))
        POLICY["frame_rate_limit"] = max(0, int(payload.get("frame_rate_limit", 8)))
        POLICY["allowlist"] = parse_allowlist(payload.get("allowlist", "10.0.1.20"))
        POLICY["policy_mtime"] = mtime


def prune_window(window, now):
    while window and now - window[0] >= 1.0:
        window.popleft()


def enforce_policy(source, malformed):
    refresh_policy()
    now = time.monotonic()
    with STATE_LOCK:
        allowlisted = source in POLICY["allowlist"]
        if POLICY["connection_limiting_enabled"] and not allowlisted:
            window = SOURCE_WINDOWS[source]
            prune_window(window, now)
            if POLICY["conn_threshold"] <= 0 or len(window) >= POLICY["conn_threshold"]:
                AVAILABILITY["connections_blocked"] += 1
                return False, "connection_limit"
            window.append(now)

        if POLICY["rate_limiting_enabled"] and malformed and not allowlisted:
            window = MALFORMED_WINDOWS[source]
            prune_window(window, now)
            if POLICY["frame_rate_limit"] <= 0 or len(window) >= POLICY["frame_rate_limit"]:
                AVAILABILITY["frames_blocked_rate"] += 1
                AVAILABILITY["frames_blocked_malformed"] += 1
                return False, "rate_limit"
            window.append(now)

    return True, ""


def purge_request_window(now):
    while REQUEST_WINDOW and now - REQUEST_WINDOW[0] >= 1.0:
        REQUEST_WINDOW.popleft()
    AVAILABILITY["current_request_rate"] = len(REQUEST_WINDOW)


def acquire_capacity(deadline):
    """Wait briefly for a slot in the shared rolling requests/second window."""
    waiter = object()
    with CAPACITY_CONDITION:
        if CONFIG["fair_queue_enabled"]:
            CAPACITY_WAITERS.append(waiter)
        while True:
            now = time.monotonic()
            purge_request_window(now)
            at_front = not CONFIG["fair_queue_enabled"] or CAPACITY_WAITERS[0] is waiter
            if at_front and len(REQUEST_WINDOW) < CONFIG["capacity_per_second"]:
                if CONFIG["fair_queue_enabled"]:
                    CAPACITY_WAITERS.popleft()
                REQUEST_WINDOW.append(now)
                AVAILABILITY["accepted_requests"] += 1
                AVAILABILITY["current_request_rate"] = len(REQUEST_WINDOW)
                AVAILABILITY["available"] = True
                CAPACITY_CONDITION.notify_all()
                return True

            remaining = deadline - now
            if remaining <= 0:
                if CONFIG["fair_queue_enabled"]:
                    try:
                        CAPACITY_WAITERS.remove(waiter)
                    except ValueError:
                        pass
                AVAILABILITY["queued_timeouts"] += 1
                AVAILABILITY["available"] = False
                CAPACITY_CONDITION.notify_all()
                return False

            if REQUEST_WINDOW:
                next_slot_in = max(0.001, REQUEST_WINDOW[0] + 1.0 - now)
                wait_for = min(remaining, next_slot_in)
            else:
                wait_for = remaining
            CAPACITY_CONDITION.wait(timeout=wait_for)


def acquire_worker(deadline):
    remaining = max(0.0, deadline - time.monotonic())
    acquired = WORKER_SEMAPHORE.acquire(timeout=remaining)
    with STATE_LOCK:
        if not acquired:
            AVAILABILITY["queued_timeouts"] += 1
            AVAILABILITY["available"] = False
            return False
        AVAILABILITY["current_inflight"] += 1
        return True


def release_worker():
    with STATE_LOCK:
        AVAILABILITY["current_inflight"] = max(0, AVAILABILITY["current_inflight"] - 1)
    WORKER_SEMAPHORE.release()


def battery_status():
    elapsed = time.time() - STARTED_AT
    with STATE_LOCK:
        purge_request_window(time.monotonic())
        availability = {**AVAILABILITY, **CONFIG}
        availability["policy"] = {
            "connection_limiting_enabled": POLICY["connection_limiting_enabled"],
            "rate_limiting_enabled": POLICY["rate_limiting_enabled"],
            "conn_threshold": POLICY["conn_threshold"],
            "frame_rate_limit": POLICY["frame_rate_limit"],
            "allowlist": sorted(POLICY["allowlist"]),
        }
        control = dict(CONTROL_STATE)
    return {
        "asset": "battery-energy-storage-system",
        "ip_role": "internal_scada_battery",
        "status": "online" if availability["available"] else "overloaded",
        "state_of_charge_percent": round(67.5 + 3.5 * math.sin(elapsed / 40.0), 1),
        "power_kw": round(28.0 + 9.0 * math.sin(elapsed / 15.0), 1),
        "dc_bus_voltage_v": round(782.0 + 4.0 * math.sin(elapsed / 18.0), 1),
        "temperature_c": round(31.0 + 1.5 * math.sin(elapsed / 22.0), 1),
        "control": control,
        "availability": availability,
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


class BatteryHTTPServer(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def begin_request(self, malformed=False):
        source = self.client_address[0]
        allowed, reason = enforce_policy(source, malformed)
        if not allowed:
            print(f"battery_blocked source={source} reason={reason}", flush=True)
            json_response(self, 429, {"accepted": False, "reason": reason})
            return False

        deadline = time.monotonic() + CONFIG["queue_timeout_seconds"]
        if acquire_capacity(deadline) and acquire_worker(deadline):
            return True
        print(
            f"battery_timeout source={source} "
            f"rate={AVAILABILITY['current_request_rate']} capacity={CONFIG['capacity_per_second']} "
            f"inflight={AVAILABILITY['current_inflight']} slots={CONFIG['worker_slots']}",
            flush=True,
        )
        # Keep the connection unanswered long enough for the one-second clients to
        # observe an actual timeout/drop instead of a synthetic HTTP rejection.
        time.sleep(max(1.1, CONFIG["queue_timeout_seconds"] + 0.1))
        return False

    def do_GET(self):
        if not self.begin_request():
            return
        try:
            time.sleep(CONFIG["normal_service_time_seconds"])
            with STATE_LOCK:
                AVAILABILITY["normal_processed"] += 1
            path = urlparse(self.path).path
            if path in ("/", "/api/status"):
                json_response(self, 200, battery_status())
                return
            json_response(self, 404, {"error": "not found"})
        finally:
            release_worker()

    def do_POST(self):
        path = urlparse(self.path).path
        control_bit = self.headers.get("X-SCADA-Control-Bit", "")
        malformed = path == "/api/control" and control_bit != REQUIRED_CONTROL_BIT
        if not self.begin_request(malformed=malformed):
            return
        try:
            if path != "/api/control":
                json_response(self, 404, {"error": "not found"})
                return

            if control_bit != REQUIRED_CONTROL_BIT:
                time.sleep(CONFIG["malformed_service_time_seconds"])
                with STATE_LOCK:
                    AVAILABILITY["malformed_processed"] += 1
                    CONTROL_STATE["rejected_commands"] += 1
                    CONTROL_STATE["last_reject_reason"] = "bad_control_bit"
                print(
                    f"battery_control rejected source={self.client_address[0]} reason=bad_control_bit bit={control_bit!r}",
                    flush=True,
                )
                json_response(self, 403, {"accepted": False, "reason": "bad_control_bit"})
                return

            time.sleep(CONFIG["normal_service_time_seconds"])
            with STATE_LOCK:
                AVAILABILITY["normal_processed"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except json.JSONDecodeError:
                with STATE_LOCK:
                    CONTROL_STATE["rejected_commands"] += 1
                    CONTROL_STATE["last_reject_reason"] = "bad_json"
                json_response(self, 400, {"accepted": False, "reason": "bad_json"})
                return

            command = str(payload.get("command", "maintain"))
            if command not in {"maintain", "charge", "discharge", "standby"}:
                with STATE_LOCK:
                    CONTROL_STATE["rejected_commands"] += 1
                    CONTROL_STATE["last_reject_reason"] = "unknown_command"
                json_response(self, 400, {"accepted": False, "reason": "unknown_command"})
                return

            with STATE_LOCK:
                CONTROL_STATE["accepted_commands"] += 1
                CONTROL_STATE["last_command"] = command
                CONTROL_STATE["mode"] = command
                CONTROL_STATE["last_reject_reason"] = ""
                control = dict(CONTROL_STATE)
            print(f"battery_control accepted source={self.client_address[0]} command={command}", flush=True)
            json_response(self, 200, {"accepted": True, "command": command, "control": control})
        finally:
            release_worker()

    def log_message(self, fmt, *args):
        print(f"battery: {self.address_string()} - {fmt % args}", flush=True)


def main():
    global WORKER_SEMAPHORE
    parser = argparse.ArgumentParser(description="Serve internal battery device status/control")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--capacity", type=int, default=20)
    parser.add_argument("--worker-slots", type=int, default=4)
    parser.add_argument("--queue-timeout", type=float, default=0.2)
    parser.add_argument("--normal-service-time", type=float, default=0.05)
    parser.add_argument("--malformed-service-time", type=float, default=0.2)
    parser.add_argument("--fair-queue", action="store_true", help="serve capacity waiters FIFO instead of contention-based admission")
    parser.add_argument("--policy-file", default="/tmp/battery_policy.json")
    args = parser.parse_args()
    CONFIG["capacity_per_second"] = max(1, args.capacity)
    CONFIG["worker_slots"] = max(1, args.worker_slots)
    CONFIG["queue_timeout_seconds"] = max(0.1, args.queue_timeout)
    CONFIG["normal_service_time_seconds"] = max(0.0, args.normal_service_time)
    CONFIG["malformed_service_time_seconds"] = max(0.0, args.malformed_service_time)
    CONFIG["fair_queue_enabled"] = bool(args.fair_queue)
    CONFIG["policy_file"] = args.policy_file
    WORKER_SEMAPHORE = threading.BoundedSemaphore(CONFIG["worker_slots"])
    server = BatteryHTTPServer((args.host, args.port), Handler)
    print(f"battery soft capacity: {CONFIG['capacity_per_second']} requests/sec", flush=True)
    print(f"battery API listening on http://{args.host}:{args.port}/api/status", flush=True)
    print(f"battery worker slots: {CONFIG['worker_slots']}", flush=True)
    print(f"battery queue timeout: {CONFIG['queue_timeout_seconds']}s", flush=True)
    print(f"battery fair queue: {CONFIG['fair_queue_enabled']}", flush=True)
    print(f"battery policy file: {CONFIG['policy_file']}", flush=True)
    print("battery control endpoint requires X-SCADA-Control-Bit: 1", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()