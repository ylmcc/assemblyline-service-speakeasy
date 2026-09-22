"""Real network access for the emulated sample, used only when ``network.allow_internet`` is on
in the active config (off by default).

With it off, WinInet/winsock calls are answered entirely from memory as before: nothing here is
touched. With it on, a resolved address is checked against :func:`is_public_address` before any
real socket is opened, so loopback, RFC 1918, link-local, multicast and cloud-metadata addresses
are never reachable this way, regardless of what the sample asks for. Every real network call in
this module is best-effort: any failure (DNS failure, connection refused, timeout, blocked
address) returns ``None``/``b""`` rather than raising, so a live-network problem degrades to the
existing simulated behaviour instead of aborting the run.
"""
from __future__ import annotations

import ipaddress
import select
import socket
import ssl
from typing import Optional

CONNECT_TIMEOUT = 6.0
READ_TIMEOUT = 8.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def is_public_address(ip: str) -> bool:
    """True only for a real, publicly routable unicast IPv4/IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast   # multicast counts as "global" in Python


def resolve_public(host: str, port: int) -> Optional[str]:
    """The first publicly routable address ``host`` resolves to, or None if it's already an IP
    that isn't public, or every resolved address is non-public, or resolution fails."""
    try:
        ipaddress.ip_address(host)
        return host if is_public_address(host) else None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    for _, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if is_public_address(ip):
            return ip
    return None


class LiveSocket:
    """One real socket (TCP or UDP), used the same way regardless of which."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.closed = False

    def send(self, data: bytes, addr: Optional[tuple] = None) -> int:
        if self.closed or not data:
            return 0
        try:
            if addr is not None:
                self.sock.sendto(data, addr)
            else:
                self.sock.sendall(data)
            return len(data)
        except OSError:
            self.close()
            return 0

    def readable(self, wait: float = 0.0) -> bool:
        if self.closed:
            return True
        try:
            return bool(select.select([self.sock], [], [], wait)[0])
        except OSError:
            return False

    def recv(self, n: int) -> Optional[bytes]:
        """Bytes now (or already) available, b"" on EOF/closed, or None if nothing has arrived."""
        if self.closed:
            return b""
        if not self.readable():
            return None
        try:
            data = self.sock.recv(n)
        except OSError:
            data = b""
        if not data:
            self.close()
        return data

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.sock.close()
            except OSError:
                pass


def open_tcp(ip: str, port: int, secure: bool = False, timeout: float = CONNECT_TIMEOUT) -> Optional[LiveSocket]:
    """A real, already-connected TCP socket to a public address, or None on any failure. TLS
    certificate errors are not treated as failures (malicious infrastructure routinely uses
    self-signed/expired certificates) -- only the connection itself has to succeed."""
    if not is_public_address(ip):
        return None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if secure:
            ctx = ssl._create_unverified_context()
            raw = ctx.wrap_socket(raw, server_hostname=ip)
        raw.settimeout(None)
    except OSError:
        return None
    return LiveSocket(raw)


def open_udp() -> LiveSocket:
    return LiveSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))


def fetch_http(ip: str, port: int, secure: bool, request: bytes,
                timeout: float = READ_TIMEOUT, max_bytes: int = MAX_RESPONSE_BYTES) -> Optional[bytes]:
    """One blocking HTTP round trip: connect, send ``request`` verbatim, read until the peer
    closes or ``max_bytes``/``timeout`` is hit, return the raw response bytes (headers + body) or
    None on any failure. Matches WinInet's own synchronous, blocking call shape."""
    if not is_public_address(ip):
        return None
    try:
        raw = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        if secure:
            ctx = ssl._create_unverified_context()
            raw = ctx.wrap_socket(raw, server_hostname=ip)
        raw.settimeout(timeout)
        raw.sendall(request)
        chunks = []
        total = 0
        while total < max_bytes:
            chunk = raw.recv(min(65536, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None
    finally:
        try:
            raw.close()
        except (NameError, OSError):
            pass
    return b"".join(chunks) if chunks else None
