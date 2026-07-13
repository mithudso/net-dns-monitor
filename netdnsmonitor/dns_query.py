"""Query a specific public DNS resolver directly, bypassing the system
resolver configuration. This is the ladder's "resolve against a known-good
public resolver" check: it isolates "your configured resolver is broken"
from "DNS is broken everywhere" (e.g. a captive portal intercepting all
DNS), which `socket.getaddrinfo` can't do since it always goes through
whatever resolver the OS is currently configured to use.
"""

import random
import socket
import struct
from typing import Callable, Optional

SendRecvFn = Callable[[bytes, str, int, float], bytes]


def _default_send_recv(packet: bytes, server: str, port: int, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        response, _ = sock.recvfrom(512)
        return response
    finally:
        sock.close()


def _encode_query(domain: str, transaction_id: int) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.strip(".").split("."):
        question += struct.pack("B", len(label)) + label.encode("ascii")
    question += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def query_public_dns(
    domain: str,
    server: str = "1.1.1.1",
    port: int = 53,
    timeout: float = 2.0,
    send_recv_fn: Optional[SendRecvFn] = None,
) -> bool:
    send_recv_fn = send_recv_fn or _default_send_recv
    packet = _encode_query(domain, random.randint(0, 65535))
    try:
        response = send_recv_fn(packet, server, port, timeout)
    except OSError:
        return False
    if len(response) < 4:
        return False
    rcode = response[3] & 0x0F
    return rcode == 0
