"""GetSystemPreferredUILanguages: upstream leaves it unhooked, so a caller's wcslen() on the
(never-written) output buffer crashed the emulation. Synthetic data only."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.winenv.api.usermode.kernel32 import Kernel32  # noqa: E402


def _handler():
    h = object.__new__(Kernel32)
    h.memory = bytearray(0x2000)
    h.mem_read = lambda addr, n: bytes(h.memory[addr:addr + n])
    h.mem_write = lambda addr, data: h.memory.__setitem__(slice(addr, addr + len(data)), bytes(data))
    return h, MagicMock()


def test_first_call_with_no_buffer_reports_the_needed_size():
    h, emu = _handler()
    count_ptr, size_ptr = 0x100, 0x104
    assert h.GetSystemPreferredUILanguages(emu, [0x8, count_ptr, 0, size_ptr]) == 1
    assert int.from_bytes(h.mem_read(count_ptr, 4), "little") == 1
    needed = int.from_bytes(h.mem_read(size_ptr, 4), "little")
    assert needed > 0


def test_second_call_with_a_big_enough_buffer_writes_a_real_language_string():
    h, emu = _handler()
    count_ptr, size_ptr, buf = 0x100, 0x104, 0x200
    h.GetSystemPreferredUILanguages(emu, [0x8, count_ptr, 0, size_ptr])
    needed = int.from_bytes(h.mem_read(size_ptr, 4), "little")
    h.mem_write(size_ptr, needed.to_bytes(4, "little"))
    assert h.GetSystemPreferredUILanguages(emu, [0x8, count_ptr, buf, size_ptr]) == 1
    text = h.mem_read(buf, needed * 2).decode("utf-16-le")
    assert text.startswith("en-US\x00") and text.endswith("\x00\x00")


def test_a_too_small_buffer_is_treated_like_no_buffer():
    h, emu = _handler()
    size_ptr = 0x104
    h.mem_write(size_ptr, (1).to_bytes(4, "little"))
    assert h.GetSystemPreferredUILanguages(emu, [0x8, 0, 0x200, size_ptr]) == 1
    assert int.from_bytes(h.mem_read(size_ptr, 4), "little") > 1
