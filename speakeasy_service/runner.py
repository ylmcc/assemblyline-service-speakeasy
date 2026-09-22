"""Runs the vendored Speakeasy CLI (see speakeasy_service/vendor/, NOTICE) against a
submitted file and parses its JSON report.

Speakeasy is a pure CPU-instruction emulator (Unicorn engine): it single-steps the
sample's own machine code against a modeled/faked Windows API, filesystem, registry,
and network surface. No real syscalls reach the host OS, no real network socket is
opened (its "net_dns"/"net_traffic"/"net_http" report events are speakeasy's own
simulated responses, not real connections), and no real filesystem/registry mutation
occurs outside speakeasy's in-memory virtual models. This wrapper never runs the
sample any other way.

Invoked as a subprocess (not a library call) with an RLIMIT_AS memory cap and a
wall-clock timeout on top of Speakeasy's own --timeout, since a malformed or
adversarially crafted binary is exactly the kind of input an emulator is pointed at.

`allow_self_modifying_writes` (on by default) passes through to speakeasy's own
`--memory-allow-self-modifying-writes` flag: when a write faults only because its
destination page lacks write permission, and the destination is within memory the
currently-executing module/process itself owns, speakeasy grants that page write
permission and keeps emulating instead of aborting the run on the spot. This is the
common self-decrypting/self-modifying unpacking stub pattern; disable it only to
study strict W^X-violation behavior instead of a sample's real post-unpacking
behavior.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import os
import resource
import shutil
import subprocess
import tempfile
import zlib

SPEAKEASY_BIN = shutil.which("speakeasy") or "speakeasy"


@dataclasses.dataclass
class SpeakeasyResult:
    ok: bool
    error: str | None
    report: dict | None  # parsed speakeasy JSON report, present iff ok
    timed_out: bool
    stdout: str
    stderr: str


def _limit_resources(max_memory_bytes: int):
    def _apply():
        resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))

    return _apply


def resolve_data_ref(report: dict, data_ref: str) -> bytes | None:
    """Decodes a top-level `data` store entry (see doc/reporting.md): base64, then
    optionally zlib-decompressed. Returns None if the ref is missing or undecodable.
    """
    entry = (report.get("data") or {}).get(data_ref)
    if not entry:
        return None
    try:
        raw = base64.b64decode(entry["data"])
        if entry.get("compression") == "zlib":
            raw = zlib.decompress(raw)
        return raw
    except (KeyError, ValueError, zlib.error):
        return None


def run_speakeasy(
    sample_path: str,
    work_dir: str,
    timeout: int,
    max_memory_mb: int = 2048,
    emulate_children: bool = False,
    extract_strings: bool = True,
    raw_mode: bool = False,
    raw_arch: str = "",
    raw_offset_hex: str = "",
    allow_self_modifying_writes: bool = True,
    allow_internet: bool = False,
) -> SpeakeasyResult:
    report_fd, report_path = tempfile.mkstemp(dir=work_dir, prefix="speakeasy_report_", suffix=".json")
    os.close(report_fd)
    os.remove(report_path)  # speakeasy must create this itself; a pre-existing empty file is not valid JSON

    # A comfortable buffer over speakeasy's own --timeout so it has a chance to write
    # a partial report on its own internal timeout before we kill the process outright.
    subprocess_timeout = timeout + 30

    cmd = [
        SPEAKEASY_BIN, "--target", os.path.abspath(sample_path),
        "--no-mp", "--output", report_path, "--timeout", str(timeout),
        "--analysis-strings" if extract_strings else "--no-analysis-strings",
        "--memory-allow-self-modifying-writes" if allow_self_modifying_writes
        else "--no-memory-allow-self-modifying-writes",
        "--network-allow-internet" if allow_internet else "--network-no-allow-internet",
    ]
    if emulate_children:
        cmd.append("--emulate-children")
    if raw_mode:
        cmd.append("--raw")
        if raw_arch:
            cmd += ["--arch", raw_arch]
        if raw_offset_hex:
            cmd += ["--raw-offset", raw_offset_hex]

    timed_out = False
    stdout = stderr = ""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=subprocess_timeout,
            check=False,
            preexec_fn=_limit_resources(max_memory_mb * 1024 * 1024),
        )
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")

    if timed_out:
        return SpeakeasyResult(ok=False, error="extraction_timeout", report=None,
                                timed_out=True, stdout=stdout, stderr=stderr)

    if not os.path.exists(report_path):
        return SpeakeasyResult(ok=False, error="no_report_produced", report=None,
                                timed_out=False, stdout=stdout, stderr=stderr)

    try:
        with open(report_path) as f:
            report = json.load(f)
    except (json.JSONDecodeError, ValueError, OSError):
        return SpeakeasyResult(ok=False, error="unparseable_report", report=None,
                                timed_out=False, stdout=stdout, stderr=stderr)

    return SpeakeasyResult(ok=True, error=None, report=report, timed_out=False, stdout=stdout, stderr=stderr)
