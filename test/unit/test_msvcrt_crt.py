"""New msvcrt CRT stubs discovered missing while chasing a crypter's reflective loader
(realloc, towlower, strtol/wcstoull, and FILE*-stream stdio). Synthetic data only."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.winenv.api.usermode.msvcrt import Msvcrt  # noqa: E402


def _handler():
    h = object.__new__(Msvcrt)
    h.memory = bytearray(0x10000)
    h.next_addr = 0x1000
    h.file_streams = {}
    h.mem_read = lambda addr, n: bytes(h.memory[addr:addr + n])
    h.mem_write = lambda addr, data: h.memory.__setitem__(slice(addr, addr + len(data)), bytes(data))
    h.read_string = lambda addr, max_chars=0: bytes(h.memory[addr:h.memory.index(0, addr)]).decode()
    def _read_wide(addr, max_chars=0):
        end = addr
        while h.memory[end] or h.memory[end + 1]:
            end += 2
        return bytes(h.memory[addr:end]).decode("utf-16-le")

    h.read_wide_string = _read_wide

    def heap_alloc(size, heap):
        addr, h.next_addr = h.next_addr, h.next_addr + max(size, 1) + 0x10
        emu_.heap_allocs.append((addr, size, heap))
        return addr

    h.heap_alloc = heap_alloc
    h.mem_free = lambda addr: None

    class _FakeFile:
        def __init__(self):
            self.buf = bytearray()
            self.pos = 0

        def add_data(self, data):
            self.buf[self.pos:self.pos + len(data)] = data
            self.pos += len(data)

        def get_data(self, size=-1):
            data = bytes(self.buf[self.pos:self.pos + size]) if size >= 0 else bytes(self.buf[self.pos:])
            self.pos += len(data)
            return data

        def seek(self, offset, whence):
            self.pos = offset if whence == 0 else self.pos + offset

        def tell(self):
            return self.pos

    files = {}

    def file_open(path, create=False, truncate=False):
        hfile = len(files) + 1
        files[hfile] = _FakeFile()
        return hfile

    emu_ = MagicMock()
    emu_.heap_allocs = []
    emu_.get_ptr_size.return_value = 8
    emu_.file_open = file_open
    emu_.file_get = lambda hfile: files.get(hfile)
    h.emu = emu_
    h.get_ptr_size = lambda: 8
    h.file_open = file_open
    h.file_get = emu_.file_get
    return h, emu_


def _put(h, addr, data):
    h.mem_write(addr, data)


def test_realloc_grows_and_copies_using_the_heap_s_own_size_record():
    h, emu = _handler()
    p = h.malloc(emu, [10])
    _put(h, p, b"0123456789")
    p2 = h.realloc(emu, [p, 20])
    assert h.memory[p2:p2 + 10] == b"0123456789"


def test_realloc_null_is_malloc_and_zero_size_is_free():
    h, emu = _handler()
    p = h.realloc(emu, [0, 16])
    assert p != 0
    assert h.realloc(emu, [p, 0]) == 0


def test_towlower():
    h, emu = _handler()
    assert h.towlower(emu, [ord("Q")]) == ord("q")
    assert h.towlower(emu, [ord("q")]) == ord("q")


def test_strtol_parses_leading_digits_and_sets_endptr():
    h, emu = _handler()
    _put(h, 0x2000, b"  42abc\x00")
    endptr = 0x3000
    assert h.strtol(emu, [0x2000, endptr, 10]) == 42
    consumed = int.from_bytes(h.mem_read(endptr, 8), "little") - 0x2000
    assert h.memory[0x2000:0x2000 + consumed] == b"  42"


def test_wcstoull_wide_string():
    h, emu = _handler()
    _put(h, 0x2000, "123xyz".encode("utf-16-le") + b"\x00\x00")
    assert h.wcstoull(emu, [0x2000, 0, 10]) == 123


def _stream(h, emu, addr=0x9000):
    """A FILE* the way fread/fseek/fwrite/etc use it: file_streams maps the pointer to a handle
    that emu.file_get() resolves to a fake File."""
    hfile = emu.file_open("f.bin", create=True, truncate=True)
    h.file_streams[addr] = hfile
    return addr


def test_fwrite_then_fread_round_trip():
    h, emu = _handler()
    stream = _stream(h, emu)
    _put(h, 0x5000, b"hello")
    assert h.fwrite(emu, [0x5000, 1, 5, stream]) == 5
    h.fseek(emu, [stream, 0, 0])
    assert h.fgetc(emu, [stream]) == ord("h")


def test_fgetc_reports_eof():
    h, emu = _handler()
    stream = _stream(h, emu)
    assert h.fgetc(emu, [stream]) == -1


def test_fflush_setvbuf_lock_unlock_are_harmless_no_ops():
    h, emu = _handler()
    stream = _stream(h, emu)
    assert h.fflush(emu, [stream]) == 0
    assert h.setvbuf(emu, [stream, 0, 0, 0]) == 0
    h._lock_file(emu, [stream])
    h._unlock_file(emu, [stream])


def test_fgetpos_fsetpos_round_trip():
    h, emu = _handler()
    stream = _stream(h, emu)
    _put(h, 0x5000, b"0123456789")
    h.fwrite(emu, [0x5000, 1, 10, stream])
    h.fseek(emu, [stream, 3, 0])
    pos_ptr = 0x6000
    assert h.fgetpos(emu, [stream, pos_ptr]) == 0
    h.fseek(emu, [stream, 0, 0])
    assert h.fsetpos(emu, [stream, pos_ptr]) == 0
    assert h.fgetc(emu, [stream]) == ord("3")


def test_time64_and_localtime64_s_fill_a_plausible_struct_tm():
    h, emu = _handler()
    t_ptr = 0x7000
    now = h._time64(emu, [t_ptr])
    assert now > 1_600_000_000
    assert int.from_bytes(h.mem_read(t_ptr, 8), "little", signed=True) == now
    tm_ptr = 0x8000
    assert h._localtime64_s(emu, [tm_ptr, t_ptr]) == 0
    year = int.from_bytes(h.mem_read(tm_ptr + 20, 4), "little", signed=True) + 1900
    assert 2020 <= year <= 2100


def _str(h, addr, text):
    h.mem_write(addr, text.encode())
    return addr
