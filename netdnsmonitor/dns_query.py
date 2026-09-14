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
) -> Optional[bool]:
    """True if the resolver answered with RCODE 0, False for any other answer.

    None if no reply arrived (timeout, no route, UDP port 53 blocked): the
    name was never tested, and reporting that as False would present an
    unknown as a failed lookup.
    """
    send_recv_fn = send_recv_fn or _default_send_recv
    transaction_id = random.randint(0, 65535)
    try:
        # _encode_query is guarded because it can raise on input it cannot
        # represent: a non-ASCII domain gives UnicodeEncodeError, and a label
        # over 255 bytes gives struct.error. `domain` is a caller default
        # (repair_executor.make_repair_executor), not a constant, so those are
        # one config change from reachable. Such a name has no DNS wire form,
        # so False stays the answer for it.
        packet = _encode_query(domain, transaction_id)
    except (UnicodeError, struct.error):
        return False
    try:
        response = send_recv_fn(packet, server, port, timeout)
    except OSError:
        return None

    # Validate the datagram is actually a reply to the query we just sent.
    # Without this, any stray or spoofed packet -- including an all-zero
    # 12-byte header, which has RCODE 0 -- reads as "the public resolver
    # answered fine", destroying the exact resolver-vs-everywhere distinction
    # this module exists to draw. A full header is 12 bytes; the old 4-byte
    # floor accepted runts.
    if len(response) < 12:
        return False
    if ((response[0] << 8) | response[1]) != transaction_id:
        return False
    if not response[2] & 0x80:  # QR bit clear: this is a query, not a response
        return False

    rcode = response[3] & 0x0F
    return rcode == 0
