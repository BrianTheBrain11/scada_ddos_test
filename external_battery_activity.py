#!/usr/bin/env python3
"""Generate normal external API polling into the internal battery device."""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
import json
import time
import urllib.error
import urllib.request


CONTROL_BIT_HEADER = "X-SCADA-Control-Bit"
VALID_CONTROL_BIT = "1"


def fetch_json(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def post_control(url, command, control_bit, timeout):
    body = json.dumps({"command": command}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            CONTROL_BIT_HEADER: control_bit,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def error_result(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return f"http_{exc.code}"
    reason = getattr(exc, "reason", exc)
    return f"error:{str(reason).replace(' ', '_')}"


def run_activity(sequence, battery_url, control_url, control_every, timeout):
    battery_soc = "unavailable"
    battery_kw = "unavailable"
    battery_status = "unavailable"
    status_result = "none"
    control_result = "none"
    request_result = "ok"
    request_type = "status"

    try:
        if control_every > 0 and (sequence + 1) % control_every == 0:
            request_type = "control"
            result = post_control(control_url, "maintain", VALID_CONTROL_BIT, timeout)
            control_result = "accepted" if result.get("accepted") else "rejected"
            if control_result != "accepted":
                request_result = "rejected"
        else:
            status = fetch_json(battery_url, timeout)
            status_result = "ok"
            battery_soc = status["state_of_charge_percent"]
            battery_kw = status["power_kw"]
            battery_status = status["status"]
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError, OSError) as exc:
        request_result = error_result(exc)
        if request_type == "status":
            status_result = request_result
        else:
            control_result = request_result

    print(
        "external_battery_activity: "
        f"target={battery_url} "
        f"request_type={request_type} "
        f"request_result={request_result} "
        f"status_result={status_result} "
        f"battery_soc={battery_soc} "
        f"battery_kw={battery_kw} "
        f"battery_status={battery_status} "
        f"control={control_result}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description="Poll internal battery status from an external API host")
    parser.add_argument("--battery-url", default="http://10.0.2.50:8081/api/status")
    parser.add_argument("--control-url", default="http://10.0.2.50:8081/api/control")
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--count", type=int, default=0, help="0 means run until stopped")
    parser.add_argument("--control-every", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--concurrency", type=int, default=16)
    args = parser.parse_args()

    interval = max(0.001, args.interval)
    polls = 0
    next_request = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        while args.count == 0 or polls < args.count:
            executor.submit(
                run_activity,
                polls,
                args.battery_url,
                args.control_url,
                args.control_every,
                args.timeout,
            )
            polls += 1
            next_request += interval
            sleep_for = next_request - time.monotonic()
            if sleep_for > 0:
                time.sleep(sleep_for)


if __name__ == "__main__":
    main()
