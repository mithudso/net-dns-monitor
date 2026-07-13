from netdnsmonitor.dns_query import query_public_dns


def _response(rcode: int) -> bytes:
    # Minimal 12-byte DNS header; byte 3 low nibble carries RCODE.
    header = bytearray(12)
    header[3] = rcode & 0x0F
    return bytes(header)


def test_returns_true_when_rcode_is_zero():
    send_recv_fn = lambda packet, server, port, timeout: _response(0)
    assert query_public_dns("example.com", send_recv_fn=send_recv_fn) is True


def test_returns_false_when_rcode_is_nonzero():
    send_recv_fn = lambda packet, server, port, timeout: _response(3)  # NXDOMAIN
    assert query_public_dns("example.com", send_recv_fn=send_recv_fn) is False


def test_returns_false_on_transport_error():
    def raising(packet, server, port, timeout):
        raise OSError("network unreachable")

    assert query_public_dns("example.com", send_recv_fn=raising) is False


def test_query_packet_encodes_domain_labels():
    captured = {}

    def capture(packet, server, port, timeout):
        captured["packet"] = packet
        return _response(0)

    query_public_dns("example.com", send_recv_fn=capture)
    packet = captured["packet"]
    assert b"\x07example\x03com\x00" in packet
