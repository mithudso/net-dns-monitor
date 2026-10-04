import struct

import pytest

from netdnsmonitor.dns_query import PUBLIC_RESOLVERS, query_public_dns, query_public_dns_any


def _wire_reply(packet, *, flags=0x8180, answers=b"", answer_count=0, question=None):
    return (
        struct.pack(">HHHHHH", int.from_bytes(packet[:2], "big"), flags, 1, answer_count, 0, 0)
        + (packet[12:] if question is None else question)
        + answers
    )


def _rr(owner, kind, data):
    return owner + struct.pack(">HHIH", kind, 1, 60, len(data)) + data


def test_noerror_without_an_address_is_not_successful_resolution():
    assert query_public_dns("example.com", send_recv_fn=lambda p, *a: _wire_reply(p)) is False


@pytest.mark.parametrize("flags", [0x8380, 0x8980])
def test_truncated_or_wrong_opcode_reply_is_unknown(flags):
    assert (
        query_public_dns("example.com", send_recv_fn=lambda p, *a: _wire_reply(p, flags=flags))
        is None
    )


def test_a_reply_for_another_question_is_unknown():
    question = b"\x05other\x03com\x00\x00\x01\x00\x01"
    assert (
        query_public_dns(
            "example.com", send_recv_fn=lambda p, *a: _wire_reply(p, question=question)
        )
        is None
    )


def test_an_advertised_answer_missing_from_the_packet_is_unknown():
    assert (
        query_public_dns("example.com", send_recv_fn=lambda p, *a: _wire_reply(p, answer_count=1))
        is None
    )


def test_an_unrelated_a_answer_is_not_successful_resolution():
    answer = _rr(b"\x05other\x03com\x00", 1, b"\x01\x02\x03\x04")
    assert (
        query_public_dns(
            "example.com", send_recv_fn=lambda p, *a: _wire_reply(p, answers=answer, answer_count=1)
        )
        is False
    )


def test_a_compressed_cname_chain_to_an_a_answer_resolves():
    alias = b"\x05alias\x03com\x00"
    answers = _rr(b"\xc0\x0c", 5, alias) + _rr(alias, 1, b"\x01\x02\x03\x04")
    assert (
        query_public_dns(
            "example.com",
            send_recv_fn=lambda p, *a: _wire_reply(p, answers=answers, answer_count=2),
        )
        is True
    )


def test_a_compression_pointer_loop_is_unknown():
    def reply(packet, *args):
        offset = len(packet)
        answer = _rr(struct.pack(">H", 0xC000 | offset), 1, b"\x01\x02\x03\x04")
        return _wire_reply(packet, answers=answer, answer_count=1)

    assert query_public_dns("example.com", send_recv_fn=reply) is None


def test_a_cname_cycle_is_unknown():
    alias = b"\x05alias\x03com\x00"
    answers = _rr(b"\xc0\x0c", 5, alias) + _rr(alias, 5, b"\xc0\x0c")
    assert (
        query_public_dns(
            "example.com",
            send_recv_fn=lambda p, *a: _wire_reply(p, answers=answers, answer_count=2),
        )
        is None
    )


@pytest.mark.parametrize("size", [3, 5])
def test_an_a_record_with_an_invalid_address_length_is_unknown(size):
    answer = _rr(b"\xc0\x0c", 1, b"\x01" * size)
    assert (
        query_public_dns(
            "example.com", send_recv_fn=lambda p, *a: _wire_reply(p, answers=answer, answer_count=1)
        )
        is None
    )


def test_question_name_case_does_not_change_a_valid_answer():
    def reply(packet, *args):
        question = packet[12:].replace(b"example", b"EXAMPLE")
        answer = _rr(b"\xc0\x0c", 1, b"\x01\x02\x03\x04")
        return _wire_reply(packet, answers=answer, answer_count=1, question=question)

    assert query_public_dns("example.com", send_recv_fn=reply) is True


def test_unusable_reply_from_one_public_resolver_allows_the_next():
    asked = []

    def reply(packet, server, *args):
        asked.append(server)
        if len(asked) == 1:
            return _wire_reply(packet, flags=0x8380)
        return _response(packet, 0)

    assert query_public_dns_any("example.com", send_recv_fn=reply) is True
    assert asked == list(PUBLIC_RESOLVERS)


def test_an_overlong_whole_dns_name_is_not_sent():
    sends = []
    domain = ".".join(["x" * 63] * 4)
    assert query_public_dns(domain, send_recv_fn=lambda p, *a: sends.append(p) or b"") is False
    assert sends == []


def _response(packet: bytes, rcode: int) -> bytes:
    """Build a reply the way a real resolver would.

    The previous version of this helper returned a 12-byte header with the
    transaction ID left at 0 and the QR response bit clear -- a datagram no
    resolver ever sends. Because every test used it, the parser could accept
    literally any stray packet and the suite stayed green. A fake that models
    an impossible state hides exactly the bug it should catch.
    """
    # A NOERROR header alone is not evidence that the name resolved. Include
    # the matching question and an A answer, as a successful lookup requires.
    answer = _rr(b"\xc0\x0c", 1, b"\x01\x02\x03\x04") if rcode == 0 else b""
    return _wire_reply(packet, flags=0x8180 | rcode, answers=answer, answer_count=int(rcode == 0))


def test_returns_true_when_rcode_is_zero():
    send_recv_fn = lambda packet, server, port, timeout: _response(packet, 0)
    assert query_public_dns("example.com", send_recv_fn=send_recv_fn) is True


def test_returns_false_when_rcode_is_nonzero():
    send_recv_fn = lambda packet, server, port, timeout: _response(packet, 3)  # NXDOMAIN
    assert query_public_dns("example.com", send_recv_fn=send_recv_fn) is False


def test_returns_none_on_transport_error():
    """No reply means the name was never tested. Returning False here made a
    timeout or a blocked UDP port 53 read as "did NOT resolve via public
    resolver" -- an unknown reported as a failed reading.
    """

    def raising(packet, server, port, timeout):
        raise OSError("network unreachable")

    assert query_public_dns("example.com", send_recv_fn=raising) is None


def test_returns_none_when_the_resolver_never_answers():
    def timing_out(packet, server, port, timeout):
        raise TimeoutError("timed out")

    assert query_public_dns("example.com", send_recv_fn=timing_out) is None


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

    assert query_public_dns("example.com", send_recv_fn=wrong_id) is None


def test_datagram_without_the_response_bit_is_rejected():
    def query_not_response(packet, server, port, timeout):
        reply = bytearray(_response(packet, 0))
        reply[2] = 0x00  # QR clear: this is a query
        return bytes(reply)

    assert query_public_dns("example.com", send_recv_fn=query_not_response) is None


def test_runt_datagram_shorter_than_a_dns_header_is_rejected():
    """An all-zero 5-byte runt has RCODE 0 in the low nibble of byte 3, so the
    old `len(response) < 4` floor read it as a successful answer.
    """
    assert query_public_dns("example.com", send_recv_fn=lambda *a: b"\x00" * 5) is None


def test_undecodable_domain_returns_false_instead_of_raising():
    """`domain` is a constructor default in repair_executor, not a constant, so
    an unencodable name is one config change away. `_encode_query` raises
    UnicodeEncodeError on non-ASCII and ValueError on an over-long label;
    neither is an OSError, so both used to escape the guard entirely.
    """
    sends = []

    def capture(packet, server, port, timeout):
        sends.append(packet)
        return _response(packet, 0)

    assert query_public_dns("münchen.de", send_recv_fn=capture) is False
    assert query_public_dns("a" * 256 + ".com", send_recv_fn=capture) is False
    assert sends == []  # never reached the wire


def test_a_label_over_63_bytes_is_refused_before_it_reaches_the_wire():
    """A length byte of 192 or more is a compression pointer on the wire, so a
    200-byte label would be sent as a pointer into the packet and answered as
    some other name. The 256 case above only pinned struct's own limit.
    """
    sends = []

    def capture(packet, server, port, timeout):
        sends.append(packet)
        return _response(packet, 0)

    assert query_public_dns("a" * 200 + ".com", send_recv_fn=capture) is False
    assert query_public_dns("a" * 64 + ".com", send_recv_fn=capture) is False
    assert sends == []
    assert query_public_dns("a" * 63 + ".com", send_recv_fn=capture) is True


def test_any_tries_the_ipv6_resolver_first():
    asked = []

    def send_recv(packet, server, port, timeout):
        asked.append(server)
        return _response(packet, 0)

    assert query_public_dns_any("example.com", send_recv_fn=send_recv) is True
    assert asked == [PUBLIC_RESOLVERS[0]]
    assert ":" in PUBLIC_RESOLVERS[0]


def test_any_falls_back_to_ipv4_when_ipv6_does_not_reply():
    asked = []

    def send_recv(packet, server, port, timeout):
        asked.append(server)
        if ":" in server:
            raise OSError("no route to host")
        return _response(packet, 3)

    # NXDOMAIN from the IPv4 resolver is an answer, and False, not None.
    assert query_public_dns_any("example.com", send_recv_fn=send_recv) is False
    assert asked == list(PUBLIC_RESOLVERS)


def test_any_is_none_only_when_no_resolver_replied():
    def send_recv(packet, server, port, timeout):
        raise OSError("no route to host")

    assert query_public_dns_any("example.com", send_recv_fn=send_recv) is None
