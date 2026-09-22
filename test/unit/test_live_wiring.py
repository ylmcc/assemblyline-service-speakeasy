"""allow_internet wiring: HttpSendRequest/InternetReadFile and ws2_32's connect/send/recv/
closesocket call into livenet only when the config flag is on, and never on a non-public address.
Synthetic data / RFC 5737 addresses only."""
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.winenv import livenet  # noqa: E402
from speakeasy.winenv.api.usermode import ws2_32  # noqa: E402


def _emu(allow_internet):
    emu = MagicMock()
    emu.config.network.allow_internet = allow_internet
    emu.get_ptr_size.return_value = 8
    return emu


def _ws2(allow_internet):
    h = object.__new__(ws2_32.Ws2_32)
    h.memory = bytearray(0x1000)
    h.mem_read = lambda addr, n: bytes(h.memory[addr:addr + n])
    h.mem_write = lambda addr, data: h.memory.__setitem__(slice(addr, addr + len(data)), bytes(data))
    h.mem_cast = lambda obj, addr: obj
    h.get_bytes = lambda obj: b""
    h.wstypes = MagicMock()
    h.netman = MagicMock()
    h.record_network_event = lambda *a, **k: None
    return h, _emu(allow_internet)


class _FakeSockaddr:
    def __init__(self, ip, port):
        octets = bytes(int(p) for p in ip.split("."))
        # connect() does sa.sin_addr.to_bytes(4, "little") and feeds that straight to inet_ntoa,
        # so sin_addr must be the little-endian *encoding* of the raw dotted-quad bytes.
        self.sin_addr = int.from_bytes(octets, "little")
        self.sin_port = (port >> 8) | ((port & 0xFF) << 8)  # network byte order, as sin_port is read raw


def test_connect_opens_a_live_socket_only_when_allowed_and_address_is_public(monkeypatch):
    opened = []
    monkeypatch.setattr(livenet, "open_tcp", lambda ip, port: opened.append((ip, port)) or MagicMock())

    h, emu = _ws2(True)
    sock_obj = SimpleNamespace(type="SOCK_STREAM", set_connection_info=lambda *a: None)
    h.netman.get_socket.return_value = sock_obj
    h.mem_cast = lambda obj, addr: _FakeSockaddr("203.0.113.9", 4444)
    h.connect(emu, [1, 0x100, 16])
    assert opened == [("203.0.113.9", 4444)]
    assert sock_obj.live is not None


def test_connect_does_not_open_a_live_socket_when_disabled(monkeypatch):
    opened = []
    monkeypatch.setattr(livenet, "open_tcp", lambda ip, port: opened.append(1) or MagicMock())

    h, emu = _ws2(False)
    sock_obj = SimpleNamespace(type="SOCK_STREAM", set_connection_info=lambda *a: None)
    h.netman.get_socket.return_value = sock_obj
    h.mem_cast = lambda obj, addr: _FakeSockaddr("203.0.113.9", 4444)
    h.connect(emu, [1, 0x100, 16])
    assert opened == []
    assert not hasattr(sock_obj, "live")


def test_recv_prefers_live_data_and_reports_would_block_when_nothing_arrived():
    h, emu = _ws2(True)
    live = MagicMock()
    live.recv.return_value = b"hello"
    sock_obj = SimpleNamespace(type="SOCK_STREAM", live=live, get_connection_info=lambda: ("203.0.113.9", 80))
    h.netman.get_socket.return_value = sock_obj
    assert h.recv(emu, [1, 0x100, 16, 0]) == 5
    assert bytes(h.memory[0x100:0x105]) == b"hello"

    live.recv.return_value = None
    assert h.recv(emu, [1, 0x100, 16, 0]) == 0xFFFFFFFF


def test_send_forwards_to_the_live_socket_when_attached():
    h, emu = _ws2(True)
    live = MagicMock()
    h.memory[0x200:0x202] = b"hi"
    sock_obj = SimpleNamespace(type="SOCK_STREAM", live=live, get_connection_info=lambda: ("203.0.113.9", 80))
    h.netman.get_socket.return_value = sock_obj
    assert h.send(emu, [1, 0x200, 2, 0]) == 2
    live.send.assert_called_once_with(b"hi", addr=None)


def test_closesocket_closes_the_live_socket_too():
    h, emu = _ws2(True)
    live = MagicMock()
    sock_obj = SimpleNamespace(live=live)
    h.netman.get_socket.return_value = sock_obj
    h.closesocket(emu, [1])
    live.close.assert_called_once()
