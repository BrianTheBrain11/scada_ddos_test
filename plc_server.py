#!/usr/bin/env python3
"""Small simulated PLC speaking a minimal subset of Modbus/TCP.

Supported functions:
- 0x03: read holding registers
- 0x06: write single holding register
"""

import argparse
import socket
import struct
import threading
import time


DEFAULT_REGISTERS = {
    0: 6000,  # grid frequency, scaled by 100: 60.00 Hz
    1: 1247,  # bus voltage, scaled by 10: 124.7 kV
    2: 1,  # breaker state: 1 = closed, 0 = open
    3: 42,  # simulated load percentage
}


class RegisterBank:
    def __init__(self):
        self._registers = dict(DEFAULT_REGISTERS)
        self._lock = threading.Lock()
        self._tick = 0

    def update_process_values(self):
        while True:
            with self._lock:
                self._tick += 1
                self._registers[0] = 6000 + (self._tick % 5) - 2
                self._registers[1] = 1245 + (self._tick % 7)
                self._registers[3] = 40 + (self._tick % 20)
            time.sleep(1)

    def read(self, start, quantity):
        with self._lock:
            return [self._registers.get(addr, 0) for addr in range(start, start + quantity)]

    def write_one(self, address, value):
        with self._lock:
            self._registers[address] = value & 0xFFFF


def exception_response(function_code, exception_code):
    return bytes([function_code | 0x80, exception_code])


def handle_pdu(registers, pdu):
    if not pdu:
        return exception_response(0, 3)

    function_code = pdu[0]

    if function_code == 3:
        if len(pdu) != 5:
            return exception_response(function_code, 3)
        start, quantity = struct.unpack(">HH", pdu[1:5])
        if quantity < 1 or quantity > 125:
            return exception_response(function_code, 3)
        values = registers.read(start, quantity)
        payload = bytes([function_code, quantity * 2])
        payload += b"".join(struct.pack(">H", value) for value in values)
        return payload

    if function_code == 6:
        if len(pdu) != 5:
            return exception_response(function_code, 3)
        address, value = struct.unpack(">HH", pdu[1:5])
        registers.write_one(address, value)
        return pdu

    return exception_response(function_code, 1)


def handle_client(conn, peer, registers):
    print(f"PLC: connection from {peer[0]}:{peer[1]}", flush=True)
    with conn:
        while True:
            header = recv_exact(conn, 7)
            if not header:
                return

            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", header)
            if protocol_id != 0 or length < 2:
                return

            pdu = recv_exact(conn, length - 1)
            if not pdu:
                return

            response_pdu = handle_pdu(registers, pdu)
            response_header = struct.pack(
                ">HHHB",
                transaction_id,
                0,
                len(response_pdu) + 1,
                unit_id,
            )
            conn.sendall(response_header + response_pdu)


def recv_exact(conn, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            return b""
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve(host, port):
    registers = RegisterBank()
    threading.Thread(target=registers.update_process_values, daemon=True).start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        print(f"PLC: listening on {host}:{port}", flush=True)

        while True:
            conn, peer = server.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, peer, registers),
                daemon=True,
            ).start()


def main():
    parser = argparse.ArgumentParser(description="Simulated SCADA PLC Modbus/TCP server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=502)
    args = parser.parse_args()

    serve(args.host, args.port)


if __name__ == "__main__":
    main()
