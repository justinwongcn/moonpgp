#!/usr/bin/env python3
"""Minimal TLS SMTP sink for e2e (plan tls-transport M2/M3): python
stdlib only. Accepts ONE connection, speaks the same mini-ESMTP subset
as the plaintext sink in e2e.sh, and stores the DATA payload as
msg-0.eml. Two modes:
  implicit: TLS handshake immediately after accept (port 465 style)
  starttls: plaintext until the STARTTLS command, then upgrade (587)
Usage: tls_sink.py PORT OUTDIR CERT KEY MODE"""
import os
import socket
import ssl
import sys

port, outdir, cert, key, mode = (
    int(sys.argv[1]),
    sys.argv[2],
    sys.argv[3],
    sys.argv[4],
    sys.argv[5],
)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(1)
print("SINK READY", flush=True)
conn, _ = server.accept()

tls = None
buf = b""
if mode == "starttls":
    conn.sendall(b"220 mini-sink ESMTP\r\n")
if mode == "implicit":
    conn = ctx.wrap_socket(conn, server_side=True)
    tls = conn
    conn.sendall(b"220 mini-sink TLS ESMTP\r\n")


def recv_line():
    global buf
    while b"\n" not in buf:
        chunk = conn.recv(1)
        if not chunk:
            raise SystemExit(0)
        buf += chunk
    line, rest = buf.split(b"\n", 1)
    buf = rest
    return line


in_data = False
payload = b""
while True:
    line = recv_line()
    if in_data:
        if line == b".\r":
            in_data = False
            with open(os.path.join(outdir, "msg-0.eml"), "wb") as f:
                f.write(payload)
            conn.sendall(b"250 stored\r\n")
        elif line.startswith(b".."):
            payload += line[1:] + b"\n"  # dot-unstuffing (receiver's job)
        else:
            payload += line + b"\n"
    else:
        cmd = line.decode(errors="replace").strip().upper()
        if cmd.startswith("EHLO"):
            if mode == "starttls" and tls is None:
                conn.sendall(b"250-mini-sink\r\n250-STARTTLS\r\n250 OK\r\n")
            else:
                conn.sendall(b"250-mini-sink\r\n250 OK\r\n")
        elif cmd == "STARTTLS" and mode == "starttls" and tls is None:
            conn.sendall(b"220 go ahead\r\n")
            conn = ctx.wrap_socket(conn, server_side=True)
            tls = conn
            buf = b""
        elif cmd == "DATA":
            in_data = True
            conn.sendall(b"354 end with .\r\n")
        elif cmd == "QUIT":
            conn.sendall(b"221 bye\r\n")
            break
        else:
            conn.sendall(b"250 OK\r\n")

conn.close()
print("SINK DONE", flush=True)
