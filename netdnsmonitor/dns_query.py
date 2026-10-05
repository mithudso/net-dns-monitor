"""Query a specific public DNS resolver directly, bypassing the system
resolver configuration. The ladder compares a public DNS-server answer with
native resolution. Different results are evidence of different resolver paths,
not proof of where a fault lies: split DNS, VPNs and filtering can differ.
"""

import secrets
import socket
import struct
import time
from typing import Callable, Optional

SendRecvFn = Callable[[bytes, str, int, float], bytes]


# Tried in order by query_public_dns_any: Cloudflare over IPv6, then over IPv4.
# Native IPv6 first, then IPv4. NAT64-only test networks do not necessarily
# route a native IPv6 literal; retain the other family as a separate attempt.
PUBLIC_RESOLVERS = ("2606:4700:4700::1111", "1.1.1.1")


def _default_send_recv(packet: bytes, server: str, port: int, timeout: float) -> bytes:
    # The family comes from getaddrinfo rather than being fixed: an IPv6
    # literal needs AF_INET6. This can also use a synthesized candidate if the
    # resolver supplies one; flags=0 is not a guarantee of NAT64 synthesis.
    family, socktype, proto, _canon, address = socket.getaddrinfo(
        server, port, 0, socket.SOCK_DGRAM
    )[0]
    sock = socket.socket(family, socktype, proto)
    try:
        # connect() makes the kernel drop datagrams from any other source, but a
        # datagram from the resolver's own address with a different transaction
        # id can still arrive (a late reply to an earlier query on a reused
        # port, or an off-path guess). Taking the first datagram would end the
        # wait on it and read as "the public resolver did not answer" -- the
        # wrong half of the one distinction this module exists to draw. So keep
        # reading until the deadline and drop what does not carry our id.
        sock.connect(address)
        sock.send(packet)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no reply with a matching transaction id")
            sock.settimeout(remaining)
            data = sock.recv(512)
            if data[:2] == packet[:2]:
                return data
    finally:
        sock.close()


def _encode_query(domain: str, transaction_id: int) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.strip(".").split("."):
        # IDNA, not ASCII: a Unicode name has a wire form (xn-- labels), and a
        # name that is merely unusual is not a name that failed to resolve.
        encoded = label.encode("idna")
        # A label is at most 63 bytes on the wire: length bytes of 192 and
        # above are compression pointers, so a 200-byte label would encode as
        # a pointer into the packet and be answered as some other name. (255
        # is the limit on the whole name, a different bound.)
        if not 1 <= len(encoded) <= 63:
            raise ValueError(f"DNS label must be 1-63 bytes, got {len(encoded)}")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    if len(question) - 4 > 255:
        raise ValueError("DNS name exceeds 255 wire bytes")
    return header + question


def _decode_name(packet: bytes, offset: int) -> tuple[tuple[bytes, ...], int]:
    """Read a bounded DNS name, including compression, without trusting offsets."""
    labels = []
    end = None
    seen = set()
    wire_length = 1
    while True:
        if offset >= len(packet) or offset in seen:
            raise ValueError("invalid DNS name offset")
        seen.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("incomplete DNS pointer")
            target = ((length & 0x3F) << 8) | packet[offset + 1]
            # RFC 1035 compression points to a prior occurrence. This also
            # refuses pointer loops without recursive parsing.
            if target >= offset:
                raise ValueError("invalid DNS pointer")
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label")
        offset += 1
        if length == 0:
            return tuple(labels), offset if end is None else end
        if offset + length > len(packet):
            raise ValueError("incomplete DNS label")
        wire_length += length + 1
        if wire_length > 255:
            raise ValueError("DNS name exceeds 255 wire bytes")
        labels.append(packet[offset : offset + length].lower())
        offset += length


def _answer_result(response: bytes, packet: bytes) -> Optional[bool]:
    """True requires an A answer for this question or its bounded CNAME chain.

    A valid negative answer is False. An incomplete, mismatched or malformed
    message provides no trustworthy name-resolution result and stays unknown.
    """
    try:
        transaction, flags, questions, answers, authority, additional = struct.unpack(
            ">HHHHHH", response[:12]
        )
        if transaction != int.from_bytes(packet[:2], "big"):
            return None
        if not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or questions != 1:
            return None
        expected_name, _ = _decode_name(packet, 12)
        question_name, offset = _decode_name(response, 12)
        qtype, qclass = struct.unpack_from(">HH", response, offset)
        if question_name != expected_name or (qtype, qclass) != (1, 1):
            return None
        offset += 4
        aliases = {}
        addresses = set()
        for index in range(answers + authority + additional):
            owner, offset = _decode_name(response, offset)
            kind, record_class, _ttl, size = struct.unpack_from(">HHIH", response, offset)
            offset += 10
            end = offset + size
            if end > len(response):
                return None
            if kind == 1 and record_class == 1:
                if size != 4:
                    return None
                if index < answers:
                    addresses.add(owner)
            elif kind == 5 and record_class == 1:
                alias, alias_end = _decode_name(response, offset)
                if alias_end != end:
                    return None
                if index < answers:
                    if owner in aliases and aliases[owner] != alias:
                        return None
                    aliases[owner] = alias
            offset = end
        if offset != len(response):
            return None
        if flags & 0x000F:
            return False
        name = expected_name
        visited = set()
        # At most one traversal per answer record. CNAME loops or conflicting
        # CNAME/address data are not evidence that the name resolved.
        while name not in visited:
            visited.add(name)
            if name in addresses:
                return None if name in aliases else True
            if name not in aliases:
                return False
            name = aliases[name]
        return None
    except (IndexError, TypeError, ValueError, struct.error):
        return None


def query_public_dns(
    domain: str,
    server: str = "1.1.1.1",
    port: int = 53,
    timeout: float = 2.0,
    send_recv_fn: Optional[SendRecvFn] = None,
) -> Optional[bool]:
    """True for a usable A answer, False for a valid reply without one.

    None for transport failures and untrustworthy or truncated replies. An
    unknown reply must not be presented as a tested, failed name.
    """
    send_recv_fn = send_recv_fn or _default_send_recv
    # The transaction id is the only thing standing between this check and a
    # spoofed answer, so it must not come from a predictable generator.
    transaction_id = secrets.randbelow(65536)
    try:
        # _encode_query is guarded because it can raise on a name that has no
        # wire form even after IDNA encoding (an empty or over-long label, a
        # name over 255 bytes). `domain` is a caller default
        # (repair_executor.make_repair_executor), not a constant, so that is
        # one config change from reachable. Nothing was sent, so nothing was
        # learned about the name: None (not probed), never False (CLAUDE.md #2).
        packet = _encode_query(domain, transaction_id)
    except (UnicodeError, ValueError):
        return None
    try:
        response = send_recv_fn(packet, server, port, timeout)
    except OSError:
        return None

    return _answer_result(response, packet)


def query_public_dns_any(
    domain: str,
    servers: tuple = PUBLIC_RESOLVERS,
    timeout: float = 2.0,
    send_recv_fn: Optional[SendRecvFn] = None,
) -> Optional[bool]:
    """The first answer from `servers`, tried in order.

    A server that does not reply (None) moves on to the next; an answer, True
    or False, ends the search. None only if no server replied at all, so an
    IPv4-only network still gets a real answer from the IPv4 resolver.
    """
    for server in servers:
        answered = query_public_dns(
            domain, server=server, timeout=timeout, send_recv_fn=send_recv_fn
        )
        if answered is not None:
            return answered
    return None
