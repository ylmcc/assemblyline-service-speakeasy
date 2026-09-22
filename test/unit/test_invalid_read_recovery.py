"""An unmapped read no longer ends the run (mirrors the existing invalid_write recovery: the
faulting page is mapped zero-filled and execution continues); it's still recorded, and a run
that keeps faulting like this in a loop is still capped rather than spun forever."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.profiler import Run  # noqa: E402
from speakeasy.windows.win32 import Win32Emulator  # noqa: E402


def _emu():
    e = object.__new__(Win32Emulator)
    e.curr_run = Run()
    e.tmp_maps = []
    e.page_size = 0x1000
    e.get_mod_from_addr = lambda addr: None
    e.mem_map = lambda *a, **k: None
    e.get_error_info = lambda *a, **k: {"type": "invalid_read", "address": a[1] if len(a) > 1 else None}
    e.on_run_complete = MagicMock()
    e.config = MagicMock()
    e.config.exceptions.dispatch_handlers = False
    return e


def test_a_single_invalid_read_is_recorded_but_does_not_end_the_run():
    e = _emu()
    assert e._handle_invalid_read(None, 0xDEAD0000, 4, None) is True
    e.on_run_complete.assert_not_called()
    assert len(e.curr_run.recovered_read_errors) == 1
    assert e.curr_run.error is None


def test_faults_in_a_loop_are_capped_and_then_end_the_run():
    e = _emu()
    for _ in range(1001):
        e._handle_invalid_read(None, 0xDEAD0000, 4, None)
    assert len(e.curr_run.recovered_read_errors) == 1001
    e.on_run_complete.assert_called_once()
    assert e.curr_run.error is not None
