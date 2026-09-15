"""Canned Speakeasy report payloads for tests, shaped exactly per the project's own
documented schema (doc/reporting.md's annotated example). Speakeasy's own emulation
correctness is Mandiant's problem, not ours -- tests mock the subprocess boundary so
this service's own flag-construction/parsing/result-building logic is verified without
needing a real PE sample or the (heavyweight, compiled) speakeasy package installed.
"""
import base64
import zlib

_DROPPED_CONTENT = b"dropped file content for testing, not a real payload"
_DROPPED_SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
_DROPPED_COMPRESSED = base64.b64encode(zlib.compress(_DROPPED_CONTENT)).decode()

SUCCESS_REPORT = {
    "report_version": "4.0.0",
    "emulation_total_runtime": 1.234,
    "timestamp": 1760000000,
    "arch": "x86",
    "filepath": "/samples/payload.bin",
    "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "size": 4096,
    "filetype": "exe",
    "errors": [],
    "data": {
        _DROPPED_SHA256: {"compression": "zlib", "encoding": "base64", "size": len(_DROPPED_CONTENT), "data": _DROPPED_COMPRESSED},
    },
    "entry_points": [
        {
            "ep_type": "module_entry",
            "start_addr": "0x401000",
            "ep_args": [],
            "pid": 1337,
            "tid": 2000,
            "instr_count": 12345,
            "apihash": "2222222222222222222222222222222222222222222222222222222222222222",
            "ret_val": "0x0",
            "events": [
                {"pos": {"tick": 10, "tid": 2000, "pid": 1337, "pc": 4198400}, "event": "api",
                 "api_name": "kernel32.LoadLibraryA", "args": ["ws2_32"], "ret_val": "0x78c00000"},
                {"pos": {"tick": 20, "tid": 2000, "pid": 1337, "pc": 4198410}, "event": "process_create",
                 "path": "C:\\Windows\\System32\\cmd.exe", "cmdline": "cmd.exe /c whoami", "pid": 4200},
                {"pos": {"tick": 30, "tid": 2000, "pid": 1337, "pc": 4198420}, "event": "mem_alloc",
                 "path": "C:\\Windows\\System32\\notepad.exe", "base": "0x10000000", "size": "0x1000",
                 "protect": "PAGE_EXECUTE_READWRITE", "pid": 4242},
                {"pos": {"tick": 100, "tid": 2000, "pid": 1337, "pc": 4198490}, "event": "thread_inject",
                 "path": "C:\\Windows\\System32\\notepad.exe", "start_addr": "0x10000000", "param": "0x0",
                 "pid": 4242, "tid": 4300},
                {"pos": {"tick": 110, "tid": 2000, "pid": 1337, "pc": 4198500}, "event": "file_create",
                 "path": "C:\\ProgramData\\drop.bin", "handle": "0x80",
                 "open_flags": ["CREATE_ALWAYS"], "access_flags": ["GENERIC_WRITE"]},
                {"pos": {"tick": 190, "tid": 2000, "pid": 1337, "pc": 4198580}, "event": "net_dns",
                 "query": "example.org", "response": "93.184.216.34"},
                {"pos": {"tick": 200, "tid": 2000, "pid": 1337, "pc": 4198590}, "event": "net_traffic",
                 "server": "93.184.216.34", "port": 443, "proto": "tcp", "type": "connect",
                 "data_ref": None, "method": "winsock.connect"},
            ],
            "dropped_files": [
                {"path": "C:\\ProgramData\\drop.bin", "size": len(_DROPPED_CONTENT),
                 "sha256": _DROPPED_SHA256, "data_ref": _DROPPED_SHA256},
            ],
        }
    ],
}

MINIMAL_REPORT = {
    "report_version": "4.0.0",
    "emulation_total_runtime": 0.012,
    "timestamp": 1760000000,
    "arch": "x86",
    "filepath": "/samples/minimal.bin",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "size": 1234,
    "filetype": "exe",
    "entry_points": [
        {
            "ep_type": "module_entry", "start_addr": "0x401000", "ep_args": [],
            "apihash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    ],
}
