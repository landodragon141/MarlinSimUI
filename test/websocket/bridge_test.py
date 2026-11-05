#!/usr/bin/env python3
"""Live tests for the WebSocket serial bridge against echo_marlin.

Usage: python3 bridge_test.py ./echo_marlin
Needs: pip install websockets
"""
import asyncio
import socket
import subprocess
import sys
import time

import websockets
from websockets.exceptions import InvalidStatus

PORT = 18100
URL = f"ws://127.0.0.1:{PORT}/"
failures = 0


def check(cond, what):
    global failures
    if cond:
        print(f"  ok   {what}")
    else:
        failures += 1
        print(f"  FAIL {what}")


async def read_until(ws, marker, timeout=2.0):
    """Collect bytes until marker appears. Returns the text read."""
    text = ""
    end = time.monotonic() + timeout
    while marker not in text:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        try:
            msg = await asyncio.wait_for(ws.recv(), remaining)
        except asyncio.TimeoutError:
            break
        text += msg.decode() if isinstance(msg, bytes) else msg
    return text


async def status_of(origin=None):
    try:
        async with websockets.connect(URL, origin=origin, open_timeout=2):
            return 101
    except InvalidStatus as e:
        return e.response.status_code


async def main():
    print("command and reply")
    async with websockets.connect(URL, origin="http://localhost:5173") as ws:
        await ws.send("M105\n")
        reply = await read_until(ws, "ok\n")
        check(reply == "echo:M105\nok\n", f"line in, echo+ok out ({reply!r})")

        msg = await read_until(ws, "never", timeout=0.1)
        check(msg == "", "nothing extra arrives")

        print("binary input, split lines, batching")
        await ws.send(b"G28 X")          # half a line
        await ws.send(b"\nM400\nM114\n")  # rest of it plus two more
        reply = await read_until(ws, "echo:M114\nok\n")
        check(reply == "echo:G28 X\nok\necho:M400\nok\necho:M114\nok\n", "lines reassembled across messages")

        print("server output arrives as binary messages")
        await ws.send("M115\n")
        raw = await asyncio.wait_for(ws.recv(), 2)
        check(isinstance(raw, bytes), "binary frame type")

        print("ping/pong")
        pong = await ws.ping(b"hb")
        latency = await asyncio.wait_for(pong, 2)
        check(latency is not None, "pong received")

        print("big burst")
        lines = "".join(f"G1 X{i}\n" for i in range(500))
        await ws.send(lines)
        reply = await read_until(ws, "echo:G1 X499\nok\n", timeout=5)
        check(reply.count("ok\n") >= 500, f"500 lines answered ({reply.count('ok')} oks)")

        print("second client refused while first is connected")
        check(await status_of("http://localhost:5173") == 409, "409 Conflict")

        print("first client still works after the refusal")
        await ws.send("M105\n")
        check((await read_until(ws, "ok\n")).endswith("ok\n"), "still answered")

    await asyncio.sleep(0.1)

    print("origin policy")
    check(await status_of("https://evil.example") == 403, "foreign page refused (403)")
    check(await status_of("http://localhost.evil.example") == 403, "lookalike host refused")
    check(await status_of("https://allowed.example") == 101, "--ws-allow-origin page accepted")
    check(await status_of(None) == 101, "no Origin (script) accepted")

    print("reconnect gets a clean stream")
    async with websockets.connect(URL) as ws:
        await ws.send("M105\n")
        # disconnect before reading the reply
    await asyncio.sleep(0.2)
    async with websockets.connect(URL) as ws:
        stale = await read_until(ws, "never", timeout=0.3)
        check(stale == "", f"no stale output from the previous session ({stale!r})")
        await ws.send("M105\n")
        check(await read_until(ws, "ok\n") == "echo:M105\nok\n", "fresh session answers")

    print("bad requests")
    with socket.create_connection(("127.0.0.1", PORT), timeout=2) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        check(s.recv(100).startswith(b"HTTP/1.1 400"), "plain HTTP GET gets 400")
    with socket.create_connection(("127.0.0.1", PORT), timeout=2) as s:
        s.sendall(b"GET / HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 9000 + b"\r\n")
        check(s.recv(100).startswith(b"HTTP/1.1 431"), "oversized head gets 431")
    # Unmasked frame after a valid handshake -> close 1002
    async with websockets.connect(URL) as ws:
        ws.transport.write(b"\x81\x02ok")
        try:
            await asyncio.wait_for(ws.recv(), 2)
            check(False, "unmasked frame closes the connection")
        except websockets.ConnectionClosed as e:
            check(e.rcvd is not None and e.rcvd.code == 1002, f"unmasked frame -> close 1002 ({e.rcvd})")

    print("server still healthy after errors")
    async with websockets.connect(URL) as ws:
        await ws.send("M105\n")
        check(await read_until(ws, "ok\n") == "echo:M105\nok\n", "answers")


if __name__ == "__main__":
    server = subprocess.Popen([sys.argv[1], str(PORT), "https://allowed.example"])
    try:
        time.sleep(0.3)
        asyncio.run(main())
    finally:
        server.terminate()
        server.wait(timeout=5)
    print(f"\n{'all bridge tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
