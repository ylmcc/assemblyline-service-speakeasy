"""Real-network gating and the raw HTTP/socket helpers. Only RFC 5737/1918/4193 and other
non-routable ranges are used as blocked-address fixtures; the one real contact is example.com,
IANA-reserved exactly for this kind of protocol test, never a live/attacker host."""
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.winenv import livenet  # noqa: E402


def test_is_public_address_blocks_non_internet_ranges():
    for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.1.1",
               "224.0.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1"):
        assert not livenet.is_public_address(ip), ip


def test_is_public_address_allows_a_real_globally_routed_address():
    # RFC 5737 documentation ranges are correctly excluded from is_global (they are not actually
    # routable), so they cannot stand in for "a real public address" here. 1.1.1.1 is a
    # long-standing, well-known public DNS resolver used only to exercise the classification
    # logic below (a plain string comparison) -- nothing here opens a connection to it.
    assert livenet.is_public_address("1.1.1.1")


def test_resolve_public_rejects_a_private_literal():
    assert livenet.resolve_public("10.0.0.5", 80) is None


def test_resolve_public_rejects_a_hostname_that_only_resolves_privately(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("10.0.0.5", 80))])
    assert livenet.resolve_public("internal.test", 80) is None


def test_resolve_public_accepts_a_hostname_resolving_publicly(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("1.1.1.1", 80))])
    assert livenet.resolve_public("c2.test", 80) == "1.1.1.1"


def test_open_tcp_refuses_a_non_public_address():
    assert livenet.open_tcp("192.168.1.1", 80) is None


def test_fetch_http_refuses_a_non_public_address():
    assert livenet.fetch_http("127.0.0.1", 80, False, b"GET / HTTP/1.1\r\n\r\n") is None


def test_fetch_http_and_open_tcp_work_against_a_real_loopback_stub_server():
    """livenet's own address gate is proven blocked above; here the gate is bypassed the same
    way ElfSim's tests do (a loopback server standing in for "the internet") to exercise the
    actual socket/read code path without depending on a real external host."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    orig = livenet.is_public_address
    livenet.is_public_address = lambda ip: ip == "127.0.0.1" or orig(ip)
    try:
        raw = livenet.fetch_http("127.0.0.1", port, False, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert raw and raw.endswith(b"ok")

        srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv2.bind(("127.0.0.1", 0))
        srv2.listen(1)
        port2 = srv2.getsockname()[1]
        accepted = []
        threading.Thread(target=lambda: accepted.append(srv2.accept()[0]), daemon=True).start()
        sock = livenet.open_tcp("127.0.0.1", port2)
        assert sock is not None
        import time
        for _ in range(50):
            if accepted:
                break
            time.sleep(0.05)
        assert accepted
        assert sock.send(b"hi") == 2
        assert accepted[0].recv(4096) == b"hi"
        accepted[0].sendall(b"bye")
        for _ in range(50):
            if sock.readable():
                break
            time.sleep(0.05)
        assert sock.recv(4096) == b"bye"
        sock.close()
        srv2.close()
    finally:
        livenet.is_public_address = orig
        srv.close()


def _stub_server(respond):
    """One-shot loopback server: ``respond(conn, request_bytes)`` decides what to send and
    whether to close. Returns (port, captured_requests, server_socket)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    seen = []

    def serve():
        conn, _ = srv.accept()
        req = conn.recv(65536)
        seen.append(req)
        respond(conn, req)

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], seen, srv


def _allow_loopback(monkeypatch):
    orig = livenet.is_public_address
    monkeypatch.setattr(livenet, "is_public_address", lambda ip: ip == "127.0.0.1" or orig(ip))


def test_fetch_returns_promptly_when_a_keep_alive_server_never_closes(monkeypatch):
    """Regression: a Cobalt Strike-style stager sets INTERNET_FLAG_KEEP_CONNECTION; the server
    sends the whole stage and leaves the socket open. The read used to wait for the timeout and
    then discard everything received, so the sample got the simulated default.bin instead."""
    _allow_loopback(monkeypatch)
    payload = bytes(range(256)) * 40
    held = []
    port, _, srv = _stub_server(lambda c, r: (held.append(c), c.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n" % len(payload) + payload)))
    import time
    t0 = time.monotonic()
    raw, note = livenet.fetch_http_ex("127.0.0.1", port, False, b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n", timeout=5)
    assert time.monotonic() - t0 < 2
    assert note == ""
    assert livenet.split_http_response(raw)[2] == payload
    srv.close()


def test_fetch_keeps_partial_data_when_the_read_times_out(monkeypatch):
    _allow_loopback(monkeypatch)
    held = []
    port, _, srv = _stub_server(lambda c, r: (held.append(c), c.sendall(b"HTTP/1.1 200 OK\r\n\r\npartial")))
    raw, note = livenet.fetch_http_ex("127.0.0.1", port, False, b"GET / HTTP/1.1\r\n\r\n", timeout=0.5)
    assert raw.endswith(b"partial")
    assert note == "read timed out"
    srv.close()


def test_fetch_reports_why_nothing_came_back(monkeypatch):
    _allow_loopback(monkeypatch)
    port, _, srv = _stub_server(lambda c, r: c.close())
    assert livenet.fetch_http_ex("127.0.0.1", port, False, b"GET / HTTP/1.1\r\n\r\n", timeout=2) == \
        (None, "no response (connection closed by server)")
    srv.close()

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()
    raw, note = livenet.fetch_http_ex("127.0.0.1", closed_port, False, b"GET / HTTP/1.1\r\n\r\n")
    assert raw is None and note.startswith("connection failed")
    assert livenet.fetch_http_ex("10.0.0.5", 80, False, b"") == (None, "blocked: not a public address")


def test_response_complete_handles_length_chunked_and_unbounded_bodies():
    assert not livenet.response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n")
    assert not livenet.response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab")
    assert livenet.response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd")
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert not livenet.response_complete(chunked + b"3\r\nabc\r\n")
    assert livenet.response_complete(chunked + b"3\r\nabc\r\n0\r\n\r\n")
    assert livenet.response_complete(b"HTTP/1.1 204 No Content\r\n\r\n")
    assert not livenet.response_complete(b"HTTP/1.0 200 OK\r\n\r\nuntil close")
