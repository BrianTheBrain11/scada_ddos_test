#!/usr/bin/env python3
"""Poll the simulated PLC over Modbus/TCP like a tiny HMI."""

import argparse
import socket
import struct
import time


REGISTER_NAMES = {
    0: "frequency_hz_x100",
    1: "voltage_kv_x10",
    2: "breaker_closed",
    3: "load_percent",
}


class ModbusClient:
    def __init__(self, host, port, unit_id=1, timeout=2.0):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self.transaction_id = 0

    def read_holding_registers(self, start, quantity):
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        pdu = struct.pack(">BHH", 3, start, quantity)
        response = self._request(pdu)

        function_code = response[0]
        if function_code & 0x80:
            raise RuntimeError(f"PLC exception response: function={function_code:#x}, code={response[1]}")
        if function_code != 3:
            raise RuntimeError(f"Unexpected function code: {function_code}")

        byte_count = response[1]
        payload = response[2:]
        if byte_count != len(payload):
            raise RuntimeError("Malformed Modbus response byte count")

        return list(struct.unpack(f">{quantity}H", payload))

    def write_single_register(self, address, value):
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        pdu = struct.pack(">BHH", 6, address, value)
        response = self._request(pdu)

        if response[0] & 0x80:
            raise RuntimeError(f"PLC exception response: function={response[0]:#x}, code={response[1]}")
        if response != pdu:
            raise RuntimeError("Unexpected write acknowledgement")

    def _request(self, pdu):
        header = struct.pack(
            ">HHHB",
            self.transaction_id,
            0,
            len(pdu) + 1,
            self.unit_id,
        )

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(header + pdu)
            response_header = recv_exact(sock, 7)
            transaction_id, protocol_id, length, _unit_id = struct.unpack(">HHHB", response_header)
            if transaction_id != self.transaction_id or protocol_id != 0:
                raise RuntimeError("Unexpected Modbus/TCP response header")
            return recv_exact(sock, length - 1)


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("Connection closed while reading response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def format_registers(values):
    parts = []
    for offset, value in enumerate(values):
        name = REGISTER_NAMES.get(offset, f"register_{offset}")
        parts.append(f"{name}={value}")
    return ", ".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Poll a simulated PLC over Modbus/TCP")
    parser.add_argument("--target", default="10.0.2.30")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--count", type=int, default=0, help="0 means poll until stopped")
    args = parser.parse_args()

    client = ModbusClient(args.target, args.port)
    polls = 0

    while args.count == 0 or polls < args.count:
        started = time.time()
        values = client.read_holding_registers(0, 4)
        elapsed_ms = (time.time() - started) * 1000
        print(f"HMI: {format_registers(values)} latency_ms={elapsed_ms:.2f}", flush=True)
        polls += 1
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

