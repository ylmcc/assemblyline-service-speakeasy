"""Readable views over a Speakeasy report. All data is synthetic."""
import base64
import zlib

from speakeasy_service import report_views as v
from test.unit.test_clipboard import _run_service


def _api(name, args=(), ret=None):
    ev = {"event": "api", "api_name": name, "args": list(args)}
    if ret is not None:
        ev["ret_val"] = ret
    return ev


def test_short_api_and_argument_cleaning():
    assert v.short_api("api-ms-win-crt-heap-l1-1-0.malloc") == "crt.malloc"
    assert v.short_api("kernel32.GetProcAddress") == "kernel32.GetProcAddress"
    assert v.clean_arg("a\x00\x14b") == "a..b"
    assert len(v.clean_arg("x" * 500)) == 48


def test_trace_folds_consecutive_repeats_and_reports_the_omitted_rows():
    calls = [_api("kernel32.Sleep", ["0x64"]), _api("kernel32.Sleep", ["0x64"]), _api("kernel32.Sleep", ["0x64"]),
             _api("kernel32.ExitProcess", ["0x0"]), _api("kernel32.Sleep", ["0x1"])]
    rows, omitted = v.collapse_trace(calls, limit=2)
    assert [(r["seq"], r["api"], r["times"]) for r in rows] == [(1, "kernel32.Sleep", 3), (2, "kernel32.ExitProcess", "")]
    assert omitted == 1


def test_categories_group_apis_and_keep_anti_analysis_separate():
    calls = [_api("kernel32.IsDebuggerPresent"), _api("kernel32.GetCursorPos"), _api("bcrypt.BCryptDecrypt"),
             _api("kernel32.VirtualAlloc"), _api("kernel32.VirtualAlloc"), _api("kernel32.GetProcAddress"),
             _api("wininet.InternetOpenA"), _api("kernel32.SomethingUnknown")]
    cats = v.categorise(calls)
    assert set(cats) == {"anti_debug", "environment_check", "crypto", "memory", "dynamic_resolution", "network"}
    assert cats["memory"] == {"count": 2, "apis": ["kernel32.VirtualAlloc"]}


def test_runtime_strings_exclude_what_is_in_the_file():
    report = {"strings": {"static": {"ansi": ["in the file"], "unicode": []},
                          "in_memory": {"ansi": ["in the file", "only at run time", "tiny", "windir=C:\\Windows"],
                                      "unicode": ["wide run time text"]}}}
    assert v.runtime_strings(report, 10) == ["only at run time", "wide run time text"]


def test_image_sections_flag_odd_names_and_rwx():
    ep = {"memory": {"modules": [{"segments": [
        {"name": ".text", "address": "0x1000", "size": "0x10", "prot": "r-x"},
        {"name": "zzqqzz", "address": "0x2000", "size": "0x10", "prot": "r-x"},
        {"name": ".data", "address": "0x3000", "size": "0x10", "prot": "rwx"}]}]}}
    notes = [r["note"] for r in v.image_sections(ep)]
    assert notes == ["", "non-standard name", "writable and executable"]


def test_stop_reason():
    assert v.stop_reason({"error": {"type": "invalid_fetch"}}, []) == "invalid_fetch"
    assert v.stop_reason({}, [_api("kernel32.ExitProcess", ["0x1"])]) == "the sample called kernel32.ExitProcess(0x1)"
    assert v.stop_reason({"ret_val": "0x0"}, [_api("kernel32.Sleep")]) == "the entry point returned 0x0"


def test_service_extracts_decrypted_data_and_scores_a_large_payload(tmp_path):
    payload = b"MZ" + b"\x90" * 2000  # synthetic stand-in for a decrypted executable
    ref = "ab" * 32
    report_data = {ref: {"compression": "zlib", "encoding": "base64", "size": len(payload),
                         "data": base64.b64encode(zlib.compress(payload)).decode()}}
    events = [_api("kernel32.GetProcAddress", ["0x1", "name"], "0x0"),
              {"event": "crypto", "operation": "decrypt", "algorithm": "AES", "mode": "GCM", "key": "00" * 32,
               "iv": "11" * 12, "input_size": len(payload), "output_size": len(payload), "data_ref": ref}]
    sections = _run_service(tmp_path, events, data=report_data)
    crypto = next(s for t, s in sections.items() if t.startswith("Cryptographic operations"))
    assert crypto.heuristic.heur_id == 9 and "payload_decrypted" in crypto.heuristic.signatures
    assert "Notable API activity" in sections and "API call trace" in sections
    assert _run_service.last_request.extracted_names == ["decrypted_1.bin"]
    assert (tmp_path / "crypto_1_decrypt.bin").read_bytes() == payload


def test_small_crypto_operation_scores_zero(tmp_path):
    sections = _run_service(tmp_path, [
        {"event": "crypto", "operation": "encrypt", "algorithm": "AES", "mode": "CBC", "key": "00" * 16,
         "iv": None, "input_size": 16, "output_size": 32, "data_ref": None}])
    crypto = next(s for t, s in sections.items() if t.startswith("Cryptographic operations"))
    assert crypto.heuristic.score == 0
