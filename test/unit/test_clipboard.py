"""Clipboard emulation: the vendored user32 handlers and the service section built from them.

All text here is synthetic: wallet-shaped strings built from repeating patterns, not real addresses.
"""
import json
import os
import re
import subprocess
import sys
from unittest.mock import MagicMock, patch

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "..", "service_manifest.yml")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.winenv.api.usermode import user32  # noqa: E402

from speakeasy_service.speakeasy_service import Speakeasy, classify_wallet, clipboard_replacements  # noqa: E402

CF_UNICODETEXT = 13


def _handler():
    """A User32 handler with just enough of an emulator behind it to run the clipboard APIs."""
    h = object.__new__(user32.User32)
    h.clipboard_reads = h.clipboard_seq_calls = h.clipboard_writes = 0
    h.clipboard_text = None
    h.mem = {}
    h.events = []
    h.next_addr = 0x10000
    emu = MagicMock()
    emu.mem_write.side_effect = lambda addr, data: h.mem.__setitem__(addr, bytes(data))

    def heap_alloc(size, heap):
        addr, h.next_addr = h.next_addr, h.next_addr + 0x1000
        return addr

    h.heap_alloc = heap_alloc
    h.read_mem_string = lambda addr, width, max_chars=0: h.mem[addr].decode("utf-16-le" if width == 2 else "ascii").rstrip("\0")
    h.record_clipboard_event = lambda action, fmt, text=None: h.events.append((action, fmt, text))
    return h, emu


def test_decoys_have_wallet_shape_and_are_distinct():
    decoys = user32.CLIPBOARD_DECOYS
    assert len(set(decoys)) == len(decoys)
    assert any(re.fullmatch(r"0x[0-9a-f]{40}", d) for d in decoys)
    assert any(re.fullmatch(r"bc1q[a-z0-9]{38}", d) for d in decoys)
    assert any(re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{33,34}", d) for d in decoys)


def test_get_clipboard_data_returns_a_real_readable_pointer():
    h, emu = _handler()
    hmem = h.GetClipboardData(emu, [CF_UNICODETEXT])
    assert hmem
    assert h.mem[hmem].decode("utf-16-le").rstrip("\0") == user32.CLIPBOARD_DECOYS[0]
    assert h.events == [("read", "CF_UNICODETEXT", user32.CLIPBOARD_DECOYS[0])]


def test_ansi_text_and_unsupported_format():
    h, emu = _handler()
    hmem = h.GetClipboardData(emu, [1])
    assert h.mem[hmem].rstrip(b"\0").decode() == user32.CLIPBOARD_DECOYS[0]
    assert h.GetClipboardData(emu, [2]) == 0  # CF_BITMAP: not offered


def test_each_read_offers_the_next_decoy_then_an_empty_clipboard():
    h, emu = _handler()
    seen = [h.mem[h.GetClipboardData(emu, [CF_UNICODETEXT])].decode("utf-16-le").rstrip("\0")
            for _ in user32.CLIPBOARD_DECOYS]
    assert seen == user32.CLIPBOARD_DECOYS
    assert h.GetClipboardData(emu, [CF_UNICODETEXT]) == 0  # polling loops must still end


def test_set_clipboard_data_records_the_written_text():
    h, emu = _handler()
    src = 0x50000
    h.mem[src] = "synthetic-replacement".encode("utf-16-le") + b"\0\0"
    assert h.SetClipboardData(emu, [CF_UNICODETEXT, src]) == src
    assert h.events[-1] == ("write", "CF_UNICODETEXT", "synthetic-replacement")
    assert h.clipboard_writes == 1


def test_sequence_number_changes_on_every_call():
    h, emu = _handler()
    assert [h.GetClipboardSequenceNumber(emu, []) for _ in range(3)] == [295, 296, 297]


def test_format_availability_is_text_only():
    h, emu = _handler()
    assert h.IsClipboardFormatAvailable(emu, [CF_UNICODETEXT]) == 1
    assert h.IsClipboardFormatAvailable(emu, [2]) == 0
    assert h.OpenClipboard(emu, [0]) == 1
    assert h.CloseClipboard(emu, []) == 1


def test_replacements_pair_each_read_with_the_write_that_follows():
    events = [
        {"event": "clipboard", "action": "read", "format": "CF_UNICODETEXT", "text": "aaa"},
        {"event": "clipboard", "action": "empty", "format": ""},
        {"event": "clipboard", "action": "write", "format": "CF_UNICODETEXT", "text": "bbb"},
        {"event": "clipboard", "action": "read", "format": "CF_UNICODETEXT", "text": "ccc"},
        {"event": "clipboard", "action": "write", "format": "CF_UNICODETEXT", "text": "ccc"},  # unchanged
    ]
    assert clipboard_replacements(events) == [("aaa", "bbb")]
    assert clipboard_replacements(events[3:4]) == []
    assert clipboard_replacements([events[2]]) == []  # a write with no earlier read is not a replacement


class _Request:
    def __init__(self, path):
        self.file_path, self.result, self.supplementary = path, None, []
        self.extracted_names = []
        self.params = {
            "max_events_displayed": 50, "emulation_timeout_seconds": 30, "max_emulation_memory_mb": 512,
            "emulate_children": False, "extract_strings": True, "raw_mode": False, "raw_arch": "",
            "raw_offset_hex": "", "allow_self_modifying_writes": True, "allow_internet": False,
        }

    def get_param(self, name):
        return self.params[name]

    def add_supplementary(self, path, name, desc):
        self.supplementary.append(name)

    def add_extracted(self, path, name, *args, **kwargs):
        self.extracted_names.append(name)
        return True


def _run_service(tmp_path, events, data=None):
    report = {"report_version": "4.0.0", "arch": "amd64", "filetype": "dll", "errors": [],
              "emulation_total_runtime": 0.1, "data": data or {},
              "entry_points": [{"ep_type": "dll_entry", "start_addr": "0x1000", "events": events}]}

    def fake_run(cmd, **kwargs):
        with open(cmd[cmd.index("--output") + 1], "w") as f:
            json.dump(report, f)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")

    class Svc(Speakeasy):
        working_directory = str(tmp_path)

    svc = Svc()
    req = _Request(str(sample))
    with patch("speakeasy_service.runner.subprocess.run", side_effect=fake_run):
        svc.execute(req)
    _run_service.last_service = svc
    _run_service.last_request = req
    return {s.title_text: s for s in req.result.sections}


def test_service_flags_a_clipboard_hijacker(tmp_path):
    sections = _run_service(tmp_path, [
        {"event": "clipboard", "action": "read", "format": "CF_UNICODETEXT", "text": "0xaaaa"},
        {"event": "clipboard", "action": "write", "format": "CF_UNICODETEXT", "text": "0xbbbb"},
    ])
    section = next(s for t, s in sections.items() if t.startswith("Clipboard activity"))
    assert section.heuristic.heur_id == 7
    assert "clipboard_replaced" in section.heuristic.signatures
    assert section.heuristic.score == 500
    assert section.tags == {"file.string.extracted": ["0xbbbb"]}
    assert "0xaaaa  ->  0xbbbb" in section.subsections[0].body


def test_service_read_only_access_scores_zero(tmp_path):
    sections = _run_service(tmp_path, [
        {"event": "clipboard", "action": "read", "format": "CF_UNICODETEXT", "text": "0xaaaa"},
    ])
    section = next(s for t, s in sections.items() if t.startswith("Clipboard activity"))
    assert section.heuristic.score == 0
    assert not section.subsections
    assert not section.tags


def test_service_has_no_clipboard_section_without_clipboard_events(tmp_path):
    sections = _run_service(tmp_path, [])
    assert not any(t.startswith("Clipboard activity") for t in sections)


def test_every_decoy_shape_is_classified_by_its_own_format():
    coins = [classify_wallet(d) for d in user32.CLIPBOARD_DECOYS]
    assert coins == ["Bitcoin", "Bitcoin", "Bitcoin", "Ethereum", "Litecoin", "Dogecoin", "TRON", "XRP",
                     "Solana", "Monero"]
    assert classify_wallet("not a wallet") is None
    assert classify_wallet("ltc1" + "q" * 38) == "Litecoin"


def test_replacement_wallets_go_into_the_malware_config_ontology(tmp_path):
    read = lambda text: {"event": "clipboard", "action": "read", "format": "CF_UNICODETEXT", "text": text}  # noqa: E731
    write = lambda text: {"event": "clipboard", "action": "write", "format": "CF_UNICODETEXT", "text": text}  # noqa: E731
    btc, eth = "bc1q" + "q" * 38, "0x" + "ab" * 20
    _run_service(tmp_path, [
        read(user32.CLIPBOARD_DECOYS[0]), write(btc),
        read(user32.CLIPBOARD_DECOYS[2]), write(btc),  # same wallet twice: listed once
        read(user32.CLIPBOARD_DECOYS[3]), write(eth),
    ])
    parts = list(_run_service.last_service.ontology._result_parts.values())
    assert len(parts) == 1
    config = parts[0]
    assert config.config_extractor == "Speakeasy"
    assert [(c.coin, c.address, c.usage) for c in config.cryptocurrency] == [
        ("Bitcoin", btc, "other"), ("Ethereum", eth, "other")]


def test_no_ontology_part_without_a_replacement(tmp_path):
    _run_service(tmp_path, [{"event": "clipboard", "action": "read", "format": "CF_UNICODETEXT", "text": "0xaaaa"}])
    assert not _run_service.last_service.ontology._result_parts
