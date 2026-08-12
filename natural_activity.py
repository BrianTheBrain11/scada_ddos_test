#!/usr/bin/env python3
"""Generate normal HMI/PLC and external state polling traffic."""

import argparse
import json
import time
import urllib.request

from hmi_client import ModbusClient


ENERGY_REGISTER_NAMES = [
    "grid_frequency_hz_x100",
    "bus_voltage_kv_x10",
    "main_breaker_closed",
    "site_load_percent",
]


def poll_external_state(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Run normal energy SCADA background activity")
    parser.add_argument("--plc", default="10.0.2.30")
    parser.add_argument("--plc-port", type=int, default=502)
    parser.add_argument("--state-api-url", default="http://10.0.1.20:8080/api/state")
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--count", type=int, default=0, help="0 means run until stopped")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    client = ModbusClient(args.plc, args.plc_port, timeout=args.timeout)
    polls = 0

    while args.count == 0 or polls < args.count:
        registers = client.read_holding_registers(0, 4)
        state = poll_external_state(args.state_api_url, args.timeout)
        register_text = ", ".join(
            f"{name}={value}" for name, value in zip(ENERGY_REGISTER_NAMES, registers)
        )
        print(
            "natural_activity: "
            f"plc=[{register_text}] "
            f"solar_kw={state['solar']['generation_kw']} "
            f"battery_soc={state['battery']['state_of_charge_percent']} "
            f"mode={state['control_panel']['mode']}",
            flush=True,
        )
        polls += 1
        time.sleep(args.interval)


if __name__ == "__main__":
    main()


