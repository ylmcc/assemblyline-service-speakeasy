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
