"""Named-pipe emulation in the vendored Speakeasy: connected server/client pipe ends, and a
reader that blocks on a pipe is paused until the thread that fills it has run.

The emulation tests run tiny hand-assembled x86 programs (no real sample): a writer thread
creates a named pipe and writes a synthetic payload; the main thread opens and reads it
*before* the writer has run, which is exactly the order Cobalt Strike's artifact kit uses.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

import speakeasy  # noqa: E402
from speakeasy.windows.fileman import FileManager, Pipe, normalize_pipe_name  # noqa: E402

PIPE_NAME = b"\\\\.\\pipe\\test-pipe-0001\0"
PAYLOAD = bytes(range(0x40, 0x80)) * 4          # synthetic, 256 bytes
GENERIC_READ, OPEN_EXISTING, PIPE_ACCESS_DUPLEX = 0x80000000, 3, 3
ERROR_BROKEN_PIPE = 109


# ---- unit: name handling and the server/client channel --------------------------------------
def test_pipe_names_are_normalised_case_insensitively():
    assert normalize_pipe_name("\\\\.\\pipe\\MSSE-1-server") == "msse-1-server"
    assert normalize_pipe_name("\\\\?\\PIPE\\x") == "x"
    assert normalize_pipe_name("\\Device\\NamedPipe\\y") == "y"
    assert normalize_pipe_name("C:\\pipe\\not-a-pipe") is None
    assert normalize_pipe_name("") is None


class _Alloc:
    def __init__(self):
        self.n = 0x400

    def allocate_pipe_handle(self):
        self.n += 4
        return self.n


def _fileman():
    fm = object.__new__(FileManager)
    fm.pipe_handles, fm.pipe_channels = {}, {}
    fm.emu = type("E", (), {"handle_allocator": _Alloc()})()
    fm.get_emu_file = lambda path: None
    return fm


def test_server_and_client_ends_see_each_others_writes():
    fm = _fileman()
    srv = fm.pipe_handles[fm.pipe_open("\\\\.\\pipe\\Chan", 3, 1, 0, 0)]
    assert fm.pipe_connect_client("\\\\.\\pipe\\other") is None          # no such server
    cli = fm.pipe_handles[fm.pipe_connect_client("\\\\.\\PIPE\\chan")]   # name is case-insensitive
    srv.add_data(b"to-client")
    cli.add_data(b"to-server")
    assert cli.available() == 9 and cli.peek(2) == b"to" and cli.available() == 9
    assert cli.get_data(3) == b"to-" and cli.get_data(-1) == b"client" and cli.available() == 0
    assert srv.get_data(100) == b"to-server"


def test_anonymous_pipes_keep_their_old_single_buffer_behaviour():
    fm = _fileman()
    p = fm.pipe_handles[fm.pipe_open("", 0, 1, 0, 0)]
    assert isinstance(p, Pipe) and p.channel is None
    p.add_data(b"abc")
    assert p.get_data(3) == b"abc"


# ---- emulation: hand-assembled x86 ----------------------------------------------------------
class _Asm:
    """Just enough x86 to call APIs (stdcall) and store results."""

    def __init__(self):
        self.code = bytearray()

    def push(self, v):
        self.code += b"\x68" + struct.pack("<I", v & 0xFFFFFFFF)

    def push_mem(self, addr):
        self.code += b"\xff\x35" + struct.pack("<I", addr)

    def call(self, addr, *args):              # args in C order, pushed right to left
        for a in reversed(args):
            self.push_mem(a[1]) if isinstance(a, tuple) else self.push(a)
        self.code += b"\xb8" + struct.pack("<I", addr) + b"\xff\xd0"   # mov eax, addr; call eax

    def store_eax(self, addr):
        self.code += b"\xa3" + struct.pack("<I", addr)


def _run(build):
    """build(asm_main, asm_thread, api, data) -> None; returns (speakeasy, data addresses)."""
    se = speakeasy.Speakeasy()
    base = se.load_shellcode(None, "x86", data=b"\xcc" * 0x1000)
    emu = se.emu
    api = lambda name: emu.get_proc("kernel32", name)  # noqa: E731
    data = {"name": base + 0x800, "payload": base + 0x840, "hsrv": base + 0x980, "hcli": base + 0x984,
            "n": base + 0x988, "ret": base + 0x98C, "err": base + 0x990, "buf": base + 0xA00}
    main, thread = _Asm(), _Asm()
    build(main, thread, api, data, base + 0x400)
    main.code += b"\xc3"
    thread.code += b"\xc2\x04\x00"                                           # ret 4 (thread proc)
    se.mem_write(base, bytes(main.code))
    se.mem_write(base + 0x400, bytes(thread.code))
    se.mem_write(data["name"], PIPE_NAME)
    se.mem_write(data["payload"], PAYLOAD)
    se.run_shellcode(base)
    return se, data


def _u32(se, addr):
    return struct.unpack("<I", bytes(se.mem_read(addr, 4)))[0]


def _writer(t, api, d):
    t.call(api("CreateNamedPipeA"), d["name"], PIPE_ACCESS_DUPLEX, 0, 1, 0, 0, 0, 0)
    t.store_eax(d["hsrv"])
    t.call(api("ConnectNamedPipe"), ("mem", d["hsrv"]), 0)
    t.call(api("WriteFile"), ("mem", d["hsrv"]), d["payload"], len(PAYLOAD), d["n"] + 0x100, 0)


def test_reader_that_opens_the_pipe_before_its_writer_thread_ran_gets_the_payload():
    def build(m, t, api, d, thread_addr):
        _writer(t, api, d)
        m.call(api("CreateThread"), 0, 0, thread_addr, 0, 0, 0)
        m.call(api("CreateFileA"), d["name"], GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0)
        m.store_eax(d["hcli"])
        m.call(api("ReadFile"), ("mem", d["hcli"]), d["buf"], len(PAYLOAD), d["n"], 0)
        m.store_eax(d["ret"])

    se, d = _run(build)
    assert _u32(se, d["ret"]) == 1 and _u32(se, d["n"]) == len(PAYLOAD)
    assert bytes(se.mem_read(d["buf"], len(PAYLOAD))) == PAYLOAD
    # The paused-and-resumed reader is still one entry point, and its API log has each call once.
    eps = se.get_report().entry_points
    assert [e.ep_type for e in eps].count("shellcode") == 1
    apis = [ev.api_name for e in eps for ev in e.events or [] if getattr(ev, "api_name", None)]
    assert apis.count("kernel32.CreateFileA") == 1 and apis.count("kernel32.ReadFile") == 1


def test_peek_waits_for_the_writer_too():
    def build(m, t, api, d, thread_addr):
        _writer(t, api, d)
        m.call(api("CreateThread"), 0, 0, thread_addr, 0, 0, 0)
        m.call(api("CreateNamedPipeA"), d["name"], PIPE_ACCESS_DUPLEX, 0, 1, 0, 0, 0, 0)  # server exists up front, so Peek is what waits
        m.call(api("CreateFileA"), d["name"], GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0)
        m.store_eax(d["hcli"])
        m.call(api("PeekNamedPipe"), ("mem", d["hcli"]), 0, 0, 0, d["n"], 0)

    se, d = _run(build)
    assert _u32(se, d["n"]) == len(PAYLOAD)          # lpTotalBytesAvail once the writer has run


def test_reading_an_empty_pipe_with_no_writer_left_fails_instead_of_hanging():
    def build(m, t, api, d, thread_addr):
        m.call(api("CreateNamedPipeA"), d["name"], PIPE_ACCESS_DUPLEX, 0, 1, 0, 0, 0, 0)
        m.call(api("CreateFileA"), d["name"], GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0)
        m.store_eax(d["hcli"])
        m.call(api("ReadFile"), ("mem", d["hcli"]), d["buf"], 16, d["n"], 0)
        m.store_eax(d["ret"])
        m.call(api("GetLastError"))
        m.store_eax(d["err"])

    se, d = _run(build)
    assert _u32(se, d["ret"]) == 0 and _u32(se, d["err"]) == ERROR_BROKEN_PIPE
