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


def test_pipe_traffic_is_reported_as_artifacts_after_the_reader_consumed_it():
    fm = _fileman()
    fm.files, fm.downloads = [], []
    srv = fm.pipe_handles[fm.pipe_open("\\\\.\\pipe\\Chan", 3, 1, 0, 0)]
    cli = fm.pipe_handles[fm.pipe_connect_client("\\\\.\\pipe\\chan")]
    srv.add_data(b"stage")
    srv.add_data(b"r!")
    assert cli.get_data(-1) == b"stager!"                     # the reader drains the buffer...
    dropped = fm.get_dropped_files()                          # ...but the transcript survives
    assert [(a.path, a.get_data()) for a in dropped] == [("\\\\.\\pipe\\Chan (server to client)", b"stager!")]
    fm.add_download("http://203.0.113.9:8080/x.bin", b"body")
    assert fm.get_dropped_files()[-1].path == "http://203.0.113.9:8080/x.bin"


def test_live_http_responses_are_split_into_the_decoded_body():
    from speakeasy.winenv.livenet import split_http_response
    assert split_http_response(b"HTTP/1.1 200 OK\r\nContent-Type: a\r\n\r\nBODY") == (200, {"content-type": "a"}, b"BODY")
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nstag\r\n2\r\ner\r\n0\r\n\r\n"
    assert split_http_response(chunked)[2] == b"stager"
    assert split_http_response(b"\x90\x90 not http") == (0, {}, b"\x90\x90 not http")


# ---- service: extraction and sections -------------------------------------------------------
def _service_with_artifacts(tmp_path, artifacts):
    import base64
    import hashlib
    import json
    import subprocess
    import zlib
    from unittest.mock import patch

    os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "..", "service_manifest.yml")
    from speakeasy_service.speakeasy_service import Speakeasy
    from test.unit.test_clipboard import _Request

    data, eps = {}, []
    for per_run in artifacts:                       # one list of (path, bytes) per entry point
        dropped = []
        for path, blob in per_run:
            sha = hashlib.sha256(blob).hexdigest()
            data[sha] = {"compression": "zlib", "encoding": "base64", "size": len(blob),
                         "data": base64.b64encode(zlib.compress(blob)).decode()}
            dropped.append({"path": path, "size": len(blob), "sha256": sha, "data_ref": sha})
        eps.append({"ep_type": "thread", "start_addr": "0x1000", "events": [], "dropped_files": dropped})
    report = {"report_version": "4.0.0", "arch": "x86", "filetype": "exe", "errors": [],
              "emulation_total_runtime": 0.1, "data": data, "entry_points": eps}

    def fake_run(cmd, **kwargs):
        with open(cmd[cmd.index("--output") + 1], "w") as f:
            json.dump(report, f)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")

    class Svc(Speakeasy):
        working_directory = str(tmp_path)

    req = _Request(str(sample))
    extracted = []
    req.add_extracted = lambda path, name, desc, **kw: extracted.append((name, desc, kw.get("parent_relation"), open(path, "rb").read())) or True
    with patch("speakeasy_service.runner.subprocess.run", side_effect=fake_run):
        Svc().execute(req)
    return {s.title_text: s for s in req.result.sections}, extracted


def test_service_extracts_the_pipe_payload_once_using_its_fullest_copy(tmp_path):
    from assemblyline_v4_service.common.task import PARENT_RELATION
    pipe = "\\\\.\\pipe\\MSSE-1-server (server to client)"
    stager = bytes(range(256)) * 3                             # synthetic 768-byte "stager"
    sections, extracted = _service_with_artifacts(tmp_path, [
        [(pipe, stager[:100])],                                # reported mid-transfer by an earlier run
        [(pipe, stager)],
        [(pipe, stager)],                                      # and again by a later run
    ])
    assert len(extracted) == 1
    name, desc, relation, body = extracted[0]
    assert body == stager and relation == PARENT_RELATION.DYNAMIC
    assert name.startswith("pipe_MSSE-1-server") and "named pipe" in desc
    section = sections["Payloads passed between threads through named pipes"]
    assert section.heuristic.heur_id == 10 and section.heuristic.score == 300
    assert "Files dropped during emulation" not in sections


def test_service_extracts_downloads_as_downloaded_and_tags_the_url(tmp_path):
    from assemblyline_v4_service.common.task import PARENT_RELATION
    url = "http://203.0.113.9:8080/payload.bin"
    sections, extracted = _service_with_artifacts(tmp_path, [[(url, b"downloaded body"), ("C:\\drop.txt", b"x")]])
    by_desc = {d.split(" ")[0]: (n, r, b) for n, d, r, b in extracted}
    assert by_desc["Downloaded"][1] == PARENT_RELATION.DOWNLOADED and by_desc["Downloaded"][2] == b"downloaded body"
    assert by_desc["Downloaded"][0].endswith("_payload.bin")
    assert by_desc["File"][1] == PARENT_RELATION.DYNAMIC
    section = sections["Files downloaded during emulation (real connections)"]
    assert section.heuristic.heur_id == 11 and section.tags == {"network.dynamic.uri": [url]}
    assert "Files dropped during emulation" in sections


def test_service_extracts_runtime_code_as_a_memory_dump(tmp_path):
    from assemblyline_v4_service.common.task import PARENT_RELATION
    region = "memory 0x50000-0x50300 (code generated at runtime, api.VirtualAlloc.0x50000)"
    code = b"\xfc\xe8" + bytes(range(1, 255)) * 3
    sections, extracted = _service_with_artifacts(tmp_path, [[(region, code)]])
    (name, desc, relation, body), = extracted
    assert relation == PARENT_RELATION.MEMDUMP and body == code and name.startswith("memdump_0x50000_")
    section = sections["Code generated at runtime and executed (decoded payloads)"]
    assert section.heuristic.heur_id == 12 and section.heuristic.score == 250


def test_canned_simulated_responses_are_never_dumped_as_payloads():
    from speakeasy.windows.winemu import _is_canned_response
    root = os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src",
                        "speakeasy", "resources", "web", "default.bin")
    canned = open(root, "rb").read().rstrip(b"\x00")
    assert _is_canned_response(canned) and _is_canned_response(canned + b"\x90" * 32)
    assert not _is_canned_response(b"\xfc\xe8" + bytes(range(64)))


def test_repeating_xor_key_is_recovered_from_before_and_after_bytes():
    from speakeasy_service.speakeasy_service import repeating_xor_key
    plain = b"\xfc\xe8" + bytes(range(2, 200))
    key = b"\x11\x22\x33\x44"
    enc = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
    assert repeating_xor_key(enc, plain) == key
    assert repeating_xor_key(enc + b"\x99", plain[:-1]) == key     # dump trimmed / sizes differ by a byte
    assert repeating_xor_key(plain, plain) is None                   # a copy, not a decode
    import hashlib
    a = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(4))
    b = b"".join(hashlib.sha256(bytes([i + 100])).digest() for i in range(4))
    assert repeating_xor_key(a, b) is None                           # unrelated


def test_runtime_code_row_shows_its_decode_and_what_its_thread_did(tmp_path):
    import base64, hashlib, json, subprocess, zlib
    from unittest.mock import patch
    from speakeasy_service.speakeasy_service import Speakeasy
    from test.unit.test_clipboard import _Request

    plain = b"\xfc\xe8" + bytes(range(2, 250))
    key = b"\xa1\xb2\xc3\xd4"
    enc = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
    pipe = "\\\\.\\pipe\\stage-1 (server to client)"
    region = "memory 0x50000-0x500fc (code generated at runtime, api.VirtualAlloc.0x50000; first run by tid 77)"
    data, dropped = {}, []
    for path, blob in ((pipe, enc), (region, plain)):
        sha = hashlib.sha256(blob).hexdigest()
        data[sha] = {"compression": "zlib", "encoding": "base64", "size": len(blob),
                     "data": base64.b64encode(zlib.compress(blob)).decode()}
        dropped.append({"path": path, "size": len(blob), "sha256": sha, "data_ref": sha})
    http = {"event": "net_http", "server": "203.0.113.5", "port": 8080, "pos": {"pc": 0},
            "headers": "GET /a/b.js HTTP/1.1\nHost: x"}
    report = {"report_version": "4.0.0", "arch": "x86", "filetype": "exe", "errors": [], "data": data,
              "emulation_total_runtime": 0.1, "entry_points": [
                  {"ep_type": "module_entry", "start_addr": "0x401000", "tid": 1, "events": [], "dropped_files": dropped},
                  {"ep_type": "thread", "start_addr": "0x401500", "tid": 77, "events": [http], "dropped_files": dropped}]}

    def fake_run(cmd, **kw):
        json.dump(report, open(cmd[cmd.index("--output") + 1], "w"))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    (tmp_path / "s.bin").write_bytes(b"MZ")

    class Svc(Speakeasy):
        working_directory = str(tmp_path)

    req = _Request(str(tmp_path / "s.bin"))
    with patch("speakeasy_service.runner.subprocess.run", side_effect=fake_run):
        Svc().execute(req)
    section = next(s for s in req.result.sections if s.title_text.startswith("Code generated at runtime"))
    row = json.loads(section.body)[0]
    assert row["decoded_from"] == f"{pipe} XOR key a1b2c3d4 (4 bytes)"
    assert row["behaviour"] == "GET http://203.0.113.5:8080/a/b.js"
    assert section.tags == {"network.dynamic.uri": ["http://203.0.113.5:8080/a/b.js"]}
