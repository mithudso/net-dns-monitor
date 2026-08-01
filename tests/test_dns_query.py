import struct

from netdnsmonitor.dns_query import query_public_dns


def _response(packet: bytes, rcode: int) -> bytes:
    """Build a reply the way a real resolver would.

    The previous version of this helper returned a 12-byte header with the
    transaction ID left at 0 and the QR response bit clear -- a datagram no
    resolver ever sends. Because every test used it, the parser could accept
    literally any stray packet and the suite stayed green. A fake that models
    an impossible state hides exactly the bug it should catch.
    """
    header = bytearray(12)
    header[0] = packet[0]  # echo the query's transaction ID
    header[1] = packet[1]
    header[2] = 0x80  # QR=1: this is a response
    header[3] = rcode & 0x0F
    return bytes(header)


def test_returns_true_when_rcode_is_zero():
    send_recv_fn = lambda packet, server, port, timeout: _response(packet, 0)
    assert query_public_dns("example.com", send_recv_fn=send_recv_fn) is True


def test_returns_false_when_rcode_is_nonzero():
    send_recv_fn = lambda packet, server, port, timeout: _response(packet, 3)  # NXDOMAIN
    assert query_public_dns("example.com", send_recv_fn=send_recv_fn) is False


def test_returns_false_on_transport_error():
    def raising(packet, server, port, timeout):
        raise OSError("network unreachable")

    assert query_public_dns("example.com", send_recv_fn=raising) is False


def test_query_packet_encodes_domain_labels():
    captured = {}

    def capture(packet, server, port, timeout):
        captured["packet"] = packet
        return _response(packet, 0)

    query_public_dns("example.com", send_recv_fn=capture)
    packet = captured["packet"]
    assert b"\x07example\x03com\x00" in packet


def test_query_packet_header_asks_one_question_with_recursion_desired():
    """The question section is pinned above but the header was not. QDCOUNT
    must be 1 and RD must be set, or a real resolver returns nothing usable and
    the ladder reports "did NOT resolve via public resolver" on every run -- a
    permanent false "DNS is broken everywhere", which inverts the one
    distinction this module exists to make.
    """
    captured = {}

    def capture(packet, server, port, timeout):
        captured["packet"] = packet
        return _response(packet, 0)

    assert query_public_dns("example.com", send_recv_fn=capture) is True
    flags, qdcount = struct.unpack(">HH", captured["packet"][2:6])
    assert qdcount == 1
    assert flags & 0x0100  # RD, recursion desired


def test_reply_for_a_different_query_is_rejected():
    """A resolver echoes the transaction ID. Accepting a reply that does not
    match means any stray or off-path datagram that happens to arrive first
    counts as "public DNS works".
    """

    def wrong_id(packet, server, port, timeout):
        reply = bytearray(_response(packet, 0))
        reply[0] ^= 0xFF  # some other query's ID
        return bytes(reply)

    assert query_public_dns("example.com", send_recv_fn=wrong_id) is False


def test_datagram_without_the_response_bit_is_rejected():
    def query_not_response(packet, server, port, timeout):
        reply = bytearray(_response(packet, 0))
        reply[2] = 0x00  # QR clear: this is a query
        return bytes(reply)

    assert query_public_dns("example.com", send_recv_fn=query_not_response) is False


def test_runt_datagram_shorter_than_a_dns_header_is_rejected():
    """An all-zero 5-byte runt has RCODE 0 in the low nibble of byte 3, so the
    old `len(response) < 4` floor read it as a successful answer.
    """
    assert query_public_dns("example.com", send_recv_fn=lambda *a: b"\x00" * 5) is False


def test_undecodable_domain_returns_false_instead_of_raising():
    """`domain` is a constructor default in repair_executor, not a constant, so
    an unencodable name is one config change away. `_encode_query` raises
    UnicodeEncodeError on non-ASCII and struct.error on an over-long label;
    neither is an OSError, so both used to escape the guard entirely.
    """
    sends = []

    def capture(packet, server, port, timeout):
        sends.append(packet)
        return _response(packet, 0)

    assert query_public_dns("münchen.de", send_recv_fn=capture) is False
    assert query_public_dns("a" * 256 + ".com", send_recv_fn=capture) is False
    assert sends == []  # never reached the wire
