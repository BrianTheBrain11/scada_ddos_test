#!/usr/bin/env python3
"""Generate normal external API polling into the internal battery device."""

import argparse
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


def main():
    parser = argparse.ArgumentParser(description="Poll internal battery status from an external API host")
    parser.add_argument("--battery-url", default="http://10.0.2.50:8081/api/status")
    parser.add_argument("--control-url", default="http://10.0.2.50:8081/api/control")
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--count", type=int, default=0, help="0 means run until stopped")
    parser.add_argument("--control-every", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    polls = 0
    while args.count == 0 or polls < args.count:
        battery_soc = "unavailable"
        battery_kw = "unavailable"
        battery_status = "unavailable"
        status_result = "ok"
        try:
            status = fetch_json(args.battery_url, args.timeout)
            battery_soc = status["state_of_charge_percent"]
            battery_kw = status["power_kw"]
            battery_status = status["status"]
        except urllib.error.HTTPError as exc:
            status_result = f"http_{exc.code}"
        except urllib.error.URLError as exc:
            status_result = f"error:{exc.reason}"

        control_result = "none"
        if args.control_every > 0 and polls % args.control_every == 0:
            try:
                result = post_control(args.control_url, "maintain", VALID_CONTROL_BIT, args.timeout)
                control_result = "accepted" if result.get("accepted") else "rejected"
            except urllib.error.HTTPError as exc:
                control_result = f"http_{exc.code}"
            except urllib.error.URLError as exc:
                control_result = f"error:{exc.reason}"

        print(
            "external_battery_activity: "
            f"target={args.battery_url} "
            f"status_result={status_result} "
            f"battery_soc={battery_soc} "
            f"battery_kw={battery_kw} "
            f"battery_status={battery_status} "
            f"control={control_result}",
            flush=True,
        )
        polls += 1
        time.sleep(args.interval)


if __name__ == "__main__":
    main()


