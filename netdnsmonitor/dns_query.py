"""Query a specific public DNS resolver directly, bypassing the system
resolver configuration. This is the ladder's "resolve against a known-good
public resolver" check: it isolates "your configured resolver is broken"
from "DNS is broken everywhere" (e.g. a captive portal intercepting all
DNS), which `socket.getaddrinfo` can't do since it always goes through
whatever resolver the OS is currently configured to use.
"""

import secrets
import socket
import struct
from typing import Callable, Optional

SendRecvFn = Callable[[bytes, str, int, float], bytes]


def _default_send_recv(packet: bytes, server: str, port: int, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # connect() makes the kernel drop datagrams from any other source. An
        # unconnected recvfrom accepts the first packet to arrive from anyone,
        # and a stray one fails the transaction-id check below, which reads as
        # "the public resolver did not answer" -- the wrong half of the one
        # distinction this module exists to draw.
        sock.connect((server, port))
        sock.send(packet)
        return sock.recv(512)
    finally:
        sock.close()


def _encode_query(domain: str, transaction_id: int) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.strip(".").split("."):
        encoded = label.encode("ascii")
        # A label is at most 63 bytes on the wire: length bytes of 192 and
        # above are compression pointers, so a 200-byte label would encode as
        # a pointer into the packet and be answered as some other name. (255
        # is the limit on the whole name, a different bound.)
        if not 1 <= len(encoded) <= 63:
            raise ValueError(f"DNS label must be 1-63 bytes, got {len(encoded)}")
        question += struct.pack("B", len(encoded)) + encoded
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
    # The transaction id is the only thing standing between this check and a
    # spoofed answer, so it must not come from a predictable generator.
    transaction_id = secrets.randbelow(65536)
    try:
        # _encode_query is inside the guard because it can raise on input it
        # cannot represent: a non-ASCII domain gives UnicodeEncodeError, and a
        # label outside 1-63 bytes gives ValueError. `domain` is a caller
        # default (repair_executor.make_repair_executor), not a constant, so
        # those are one config change from reachable.
        packet = _encode_query(domain, transaction_id)
        response = send_recv_fn(packet, server, port, timeout)
    except (OSError, UnicodeError, ValueError, struct.error):
        return False

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
