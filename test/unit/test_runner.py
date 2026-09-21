import json
import subprocess
from unittest.mock import patch

from speakeasy_service.runner import resolve_data_ref, run_speakeasy
from test.unit.fixtures import MINIMAL_REPORT, SUCCESS_REPORT


def _writes_report(payload):
    """Mimics the real speakeasy CLI: writes the report to the --output path it was
    given and returns a normal exit."""

    def _fake_run(cmd, **kwargs):
        out_path = cmd[cmd.index("--output") + 1]
        with open(out_path, "w") as f:
            json.dump(payload, f)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    return _fake_run


def test_success_parses_report(tmp_path):
    with patch("speakeasy_service.runner.subprocess.run", side_effect=_writes_report(MINIMAL_REPORT)):
        result = run_speakeasy("/tmp/sample.exe", str(tmp_path), timeout=30)

    assert result.ok
    assert result.report["arch"] == "x86"


def test_timeout_reported(tmp_path):
    with patch("speakeasy_service.runner.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd=["speakeasy"], timeout=30)):
        result = run_speakeasy("/tmp/sample.exe", str(tmp_path), timeout=30)

    assert not result.ok
    assert result.timed_out
    assert result.error == "extraction_timeout"


def test_no_report_produced_reported_not_crashed(tmp_path):
    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="crashed")

    with patch("speakeasy_service.runner.subprocess.run", side_effect=_fake_run):
        result = run_speakeasy("/tmp/sample.exe", str(tmp_path), timeout=30)

    assert not result.ok
    assert result.error == "no_report_produced"


def test_unparseable_report_reported_not_crashed(tmp_path):
    def _fake_run(cmd, **kwargs):
        out_path = cmd[cmd.index("--output") + 1]
        with open(out_path, "w") as f:
            f.write("not json")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("speakeasy_service.runner.subprocess.run", side_effect=_fake_run):
        result = run_speakeasy("/tmp/sample.exe", str(tmp_path), timeout=30)

    assert not result.ok
    assert result.error == "unparseable_report"


def test_flags_are_passed_through(tmp_path):
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _writes_report(MINIMAL_REPORT)(cmd, **kwargs)

    with patch("speakeasy_service.runner.subprocess.run", side_effect=_fake_run):
        run_speakeasy(
            "/tmp/sample.bin", str(tmp_path), timeout=30, emulate_children=True,
            extract_strings=False, raw_mode=True, raw_arch="x86", raw_offset_hex="0x20",
        )

    cmd = captured["cmd"]
    assert "--emulate-children" in cmd
    assert "--no-analysis-strings" in cmd
    assert "--raw" in cmd
    assert "--arch" in cmd and "x86" in cmd
    assert "--raw-offset" in cmd and "0x20" in cmd


def test_resolve_data_ref_decodes_zlib_base64():
    data = resolve_data_ref(SUCCESS_REPORT, "3333333333333333333333333333333333333333333333333333333333333333")
    assert data == b"dropped file content for testing, not a real payload"


def test_resolve_data_ref_missing_returns_none():
    assert resolve_data_ref(SUCCESS_REPORT, "does-not-exist") is None


def test_allow_self_modifying_writes_defaults_to_enabled_flag(tmp_path):
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _writes_report(MINIMAL_REPORT)(cmd, **kwargs)

    with patch("speakeasy_service.runner.subprocess.run", side_effect=_fake_run):
        run_speakeasy("/tmp/sample.bin", str(tmp_path), timeout=30)

    cmd = captured["cmd"]
    assert "--memory-allow-self-modifying-writes" in cmd
    assert "--no-memory-allow-self-modifying-writes" not in cmd


def test_allow_self_modifying_writes_can_be_disabled(tmp_path):
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _writes_report(MINIMAL_REPORT)(cmd, **kwargs)

    with patch("speakeasy_service.runner.subprocess.run", side_effect=_fake_run):
        run_speakeasy("/tmp/sample.bin", str(tmp_path), timeout=30, allow_self_modifying_writes=False)

    cmd = captured["cmd"]
    assert "--no-memory-allow-self-modifying-writes" in cmd
    assert "--memory-allow-self-modifying-writes" not in cmd
