"""The flags run_speakeasy builds must be real, valid CLI flags -- test_runner.py mocks
subprocess.run entirely, so a wrong flag name (like the "--network-no-allow-internet" vs
--no-network-allow-internet mixup this project shipped once) doesn't fail there. This
checks the constructed command against the CLI's own real argument parser."""
import os
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy_service.runner import run_speakeasy  # noqa: E402


def test_every_flag_is_accepted_by_the_real_cli_parser(tmp_path):
    """Builds the real speakeasy CLI's own top-level parser (cli.main's own setup, minus running
    it) and feeds every flag combination run_speakeasy can produce through it -- catches a wrong
    flag name the way the mocked-subprocess tests elsewhere in this suite cannot."""
    (tmp_path / "sample.bin").write_bytes(b"MZ")
    import argparse

    from speakeasy.cli import get_config_cli_field_specs
    from speakeasy.cli_config import add_config_cli_arguments

    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("-t", "--target")
    parser.add_argument("-o", "--output")
    parser.add_argument("--no-mp", action="store_true")
    add_config_cli_arguments(parser, get_config_cli_field_specs())

    for allow_internet in (True, False):
        for allow_self_modifying in (True, False):
            captured = {}

            def fake_run(cmd, **_):
                captured["cmd"] = cmd
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

            with patch("speakeasy_service.runner.subprocess.run", side_effect=fake_run):
                run_speakeasy(str(tmp_path / "sample.bin"), str(tmp_path), timeout=5,
                              allow_internet=allow_internet, allow_self_modifying_writes=allow_self_modifying)
            parser.parse_args(captured["cmd"][1:])  # raises on any unrecognized argument


def test_default_params_flag_is_the_off_form():
    """Specifically pins the bug this test exists to catch: the off-case flag must start with
    --no-, not have -no- spliced into the middle of the option name."""
    cmd = None
    with patch("speakeasy_service.runner.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            run_speakeasy(os.path.join(d, "s.bin"), d, timeout=5, allow_internet=False)
        cmd = mock_run.call_args[0][0]
    assert "--no-network-allow-internet" in cmd
    assert "--network-no-allow-internet" not in cmd
