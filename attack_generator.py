#!/usr/bin/env python3
"""Controlled local DDoS-style traffic generator for the SCADA testbed.

Use only inside the isolated Mininet topology. The initial profile sends bad
battery-control packets with the wrong control bit to exercise gateway/battery
protection and metrics.
"""

import argparse
import json
import socket
import time
import urllib.error
import urllib.request


def bad_battery_control(target, rate, duration, wait, bad_bit):
    url = f"http://{target}/api/control"
    deadline = time.time() + duration
    sent = 0
    rejected = 0
    errors = 0
    interval = 1.0 / max(1, rate)

    while time.time() < deadline:
        started = time.time()
        body = json.dumps({"command": "discharge"}).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-SCADA-Control-Bit": bad_bit,
            },
        )
        try:
            urllib.request.urlopen(request, timeout=1.0).read()
            sent += 1
        except urllib.error.HTTPError as exc:
            sent += 1
            if exc.code == 403:
                rejected += 1
            else:
                errors += 1
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            errors += 1

        print(
            "attack_activity: "
            f"profile=bad_battery_control target={target} sent={sent} rejected={rejected} errors={errors}",
            flush=True,
        )
        sleep_for = interval - (time.time() - started)
        if sleep_for > 0:
            time.sleep(sleep_for)

    if wait > 0:
        time.sleep(wait)


def main():
    parser = argparse.ArgumentParser(description="Generate controlled local SCADA DDoS traffic")
    parser.add_argument("--profile", default="bad_battery_control", choices=["bad_battery_control"])
    parser.add_argument("--target", default="10.0.2.50:8081")
    parser.add_argument("--rate", type=int, default=100)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--wait", type=int, default=0)
    parser.add_argument("--bad-bit", default="0")
    args = parser.parse_args()

    if args.profile == "bad_battery_control":
        bad_battery_control(args.target, args.rate, args.duration, args.wait, args.bad_bit)


if __name__ == "__main__":
    main()
