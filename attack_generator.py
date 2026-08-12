#!/usr/bin/env python3
"""Controlled local DDoS-style traffic generator for the SCADA testbed.

Use only inside the isolated Mininet topology. The initial profile sends bad
battery-control packets with the wrong control bit to exercise gateway/battery
protection and metrics.
"""

import argparse
import http.client
import json
import queue
import socket
import threading
import time
import urllib.error
import urllib.request


class Counters:
    def __init__(self):
        self.sent = 0
        self.rejected = 0
        self.blocked = 0
        self.errors = 0
        self.lock = threading.Lock()

    def add(self, sent=0, rejected=0, blocked=0, errors=0):
        with self.lock:
            self.sent += sent
            self.rejected += rejected
            self.blocked += blocked
            self.errors += errors
            return self.sent, self.rejected, self.blocked, self.errors

    def snapshot(self):
        with self.lock:
            return self.sent, self.rejected, self.blocked, self.errors


def send_bad_control(url, bad_bit, timeout):
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
        urllib.request.urlopen(request, timeout=timeout).read()
        return "sent"
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return "rejected"
        if exc.code == 429:
            return "blocked"
        return "error"
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, socket.timeout, ConnectionError, OSError):
        return "error"


def worker(work_queue, url, bad_bit, timeout, counters):
    while True:
        try:
            work_queue.get(timeout=0.2)
        except queue.Empty:
            return
        try:
            result = send_bad_control(url, bad_bit, timeout)
            if result == "rejected":
                counters.add(sent=1, rejected=1)
            elif result == "blocked":
                counters.add(blocked=1)
            elif result == "sent":
                counters.add(sent=1)
            else:
                counters.add(errors=1)
        finally:
            work_queue.task_done()


def bad_battery_control(target, rate, duration, wait, bad_bit, concurrency, timeout):
    url = f"http://{target}/api/control"
    work_queue = queue.Queue(maxsize=max(1, min(concurrency, max(1, rate // 2))))
    counters = Counters()
    stop_at = time.time() + duration
    interval = 1.0 / max(1, rate)

    workers = [
        threading.Thread(target=worker, args=(work_queue, url, bad_bit, timeout, counters), daemon=True)
        for _ in range(max(1, concurrency))
    ]
    for thread in workers:
        thread.start()

    next_send = time.time()
    while time.time() < stop_at:
        try:
            work_queue.put_nowait(1)
        except queue.Full:
            counters.add(errors=1)
        next_send += interval
        sleep_for = next_send - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)

        sent, rejected, blocked, errors = counters.snapshot()
        print(
            "attack_activity: "
            f"profile=bad_battery_control target={target} sent={sent} rejected={rejected} blocked={blocked} errors={errors}",
            flush=True,
        )

    while True:
        try:
            work_queue.get_nowait()
            counters.add(errors=1)
            work_queue.task_done()
        except queue.Empty:
            break
    work_queue.join()
    sent, rejected, blocked, errors = counters.snapshot()
    print(
        "attack_activity: "
        f"profile=bad_battery_control target={target} sent={sent} rejected={rejected} blocked={blocked} errors={errors}",
        flush=True,
    )
    if wait > 0:
        time.sleep(wait)


def main():
    parser = argparse.ArgumentParser(description="Generate controlled local SCADA DDoS traffic")
    parser.add_argument("--profile", default="bad_battery_control", choices=["bad_battery_control"])
    parser.add_argument("--target", default="10.0.2.50:8081")
    parser.add_argument("--rate", type=int, default=25)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--wait", type=int, default=0)
    parser.add_argument("--bad-bit", default="0")
    parser.add_argument("--concurrency", type=int, default=80)
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()

    if args.profile == "bad_battery_control":
        bad_battery_control(
            args.target,
            args.rate,
            args.duration,
            args.wait,
            args.bad_bit,
            args.concurrency,
            args.timeout,
        )


if __name__ == "__main__":
    main()