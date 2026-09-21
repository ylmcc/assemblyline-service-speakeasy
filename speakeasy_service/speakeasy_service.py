"""Speakeasy: emulates Windows PE binaries, drivers, and raw shellcode against a
modeled Windows runtime (Unicorn CPU emulation + faked API/filesystem/registry/network
surface) to observe behavior a static-only pass would miss, using a vendored copy of
Mandiant's Speakeasy (see speakeasy_service/vendor/, NOTICE, LICENSE -- MIT).

Pure emulation: the sample's own machine code is single-stepped by Speakeasy's CPU
emulator against a fake Windows environment. No real syscalls reach the host OS, no
real network socket is opened (network-shaped report events are Speakeasy's own
simulated responses), and no real filesystem/registry mutation occurs outside
Speakeasy's in-memory virtual models. This service never executes the submitted
sample any other way.
"""
from __future__ import annotations

import json
import os
import re

from assemblyline.odm.models.ontology.results import MalwareConfig
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from assemblyline_v4_service.common.task import PARENT_RELATION

from speakeasy_service.runner import resolve_data_ref, run_speakeasy

_CROSS_PROCESS_EVENTS = {"mem_alloc", "mem_write", "mem_protect", "mem_free", "thread_create", "thread_inject"}
_NETWORK_EVENTS = {"net_dns", "net_traffic", "net_http"}


_B58 = "[1-9A-HJ-NP-Za-km-z]"
# Most specific first: several formats overlap on length, so the generic Solana shape goes last.
_WALLET_FORMATS = [
    ("Bitcoin", re.compile(r"(?:bc1[ac-hj-np-z02-9]{11,71}|[13]%s{25,34})" % _B58)),
    ("Litecoin", re.compile(r"(?:ltc1[ac-hj-np-z02-9]{11,71}|[LM]%s{26,33})" % _B58)),
    ("Ethereum", re.compile(r"0x[0-9a-fA-F]{40}")),
    ("TRON", re.compile(r"T%s{33}" % _B58)),
    ("Dogecoin", re.compile(r"D%s{33}" % _B58)),
    ("XRP", re.compile(r"r%s{24,34}" % _B58)),
    ("Monero", re.compile(r"[48]%s{94}" % _B58)),
    ("Solana", re.compile(r"%s{32,44}" % _B58)),
]


def classify_wallet(address: str) -> str | None:
    """Name the cryptocurrency an address is shaped like, or None. Shape only: no checksum is
    verified, and Ethereum-format addresses are shared by every EVM chain."""
    for coin, pattern in _WALLET_FORMATS:
        if pattern.fullmatch(address):
            return coin
    return None


def clipboard_replacements(events: list[dict]) -> list[tuple[str, str]]:
    """(text read, text written back) pairs where the sample replaced clipboard text with different
    text: the behaviour of a clipboard hijacker. Text the sample writes without having read
    anything first is not a replacement."""
    pairs, last_read = [], None
    for ev in events:
        if ev.get("event") != "clipboard":
            continue
        if ev.get("action") == "read":
            last_read = ev.get("text")
        elif ev.get("action") == "write" and last_read and ev.get("text") and ev["text"] != last_read:
            pairs.append((last_read, ev["text"]))
    return pairs


class Speakeasy(ServiceBase):
    def __init__(self, config=None) -> None:
        super().__init__(config)

    def start(self) -> None:
        pass

    def execute(self, request: ServiceRequest) -> None:
        max_rows = request.get_param("max_events_displayed")

        speakeasy = run_speakeasy(
            request.file_path,
            self.working_directory,
            timeout=request.get_param("emulation_timeout_seconds"),
            max_memory_mb=request.get_param("max_emulation_memory_mb"),
            emulate_children=request.get_param("emulate_children"),
            extract_strings=request.get_param("extract_strings"),
            raw_mode=request.get_param("raw_mode"),
            raw_arch=request.get_param("raw_arch"),
            raw_offset_hex=request.get_param("raw_offset_hex"),
            allow_self_modifying_writes=request.get_param("allow_self_modifying_writes"),
        )

        result = Result()

        if not speakeasy.ok:
            reason = {
                "extraction_timeout": "Emulation did not finish within the configured timeout.",
                "no_report_produced": "Speakeasy exited without producing a report file.",
                "unparseable_report": "Speakeasy's report file was not valid JSON.",
            }.get(speakeasy.error, speakeasy.error)
            failed = ResultSection("Emulation incomplete or failed",
                                    body=f"{reason} See the supplementary log for details.")
            failed.set_heuristic(6, signature=speakeasy.error or "unknown")
            result.add_section(failed)
            request.result = result
            self._save_log(request, speakeasy)
            return

        report = speakeasy.report
        entry_points = report.get("entry_points") or []

        info = ResultKeyValueSection("Emulation summary")
        info.set_item("arch", report.get("arch") or "unknown")
        info.set_item("filetype", report.get("filetype") or "unknown")
        info.set_item("entry_points", len(entry_points))
        info.set_item("runtime_seconds", report.get("emulation_total_runtime"))
        info.set_heuristic(1, signature="emulation_completed")
        result.add_section(info)

        all_events = [ev for ep in entry_points for ev in (ep.get("events") or [])]

        injection_events = [
            ev for ev in all_events
            if ev["event"] in _CROSS_PROCESS_EVENTS and ev.get("pid") is not None
        ] + [ev for ev in all_events if ev["event"] == "process_create"]
        if injection_events:
            injection_table = ResultTableSection("Cross-process / injection activity")
            heur2 = Heuristic(2)
            for ev in injection_events[:max_rows]:
                injection_table.add_row(TableRow(
                    event=ev["event"], path=ev.get("path", ""),
                    target_pid=ev.get("pid", ""), tid=ev.get("tid", ""),
                ))
                heur2.add_signature_id(ev["event"])
            injection_table.set_heuristic(heur2)
            result.add_section(injection_table)

        dropped_count = 0
        for ep in entry_points:
            for dropped in ep.get("dropped_files") or []:
                data = resolve_data_ref(report, dropped.get("data_ref", ""))
                if data is None:
                    continue
                out_path = os.path.join(self.working_directory, f"dropped_{dropped['sha256']}.bin")
                with open(out_path, "wb") as f:
                    f.write(data)
                display_name = os.path.basename(dropped.get("path", dropped["sha256"]).replace("\\", "/"))
                request.add_extracted(
                    out_path, f"{dropped['sha256']}_{display_name}",
                    f"File written by the sample during emulation: {dropped.get('path')}",
                    parent_relation=PARENT_RELATION.DYNAMIC,
                )
                dropped_count += 1
        if dropped_count:
            dropped_section = ResultSection(
                "Files dropped during emulation",
                body=f"{dropped_count} file(s) written by the sample during emulation were recovered "
                     "and submitted for further analysis.",
            )
            dropped_section.set_heuristic(3, signature="dropped_files")
            result.add_section(dropped_section)

        network_events = [ev for ev in all_events if ev["event"] in _NETWORK_EVENTS]
        if network_events:
            net_table = ResultTableSection("Emulated network activity (simulated, not real traffic)")
            heur4 = Heuristic(4)
            for ev in network_events[:max_rows]:
                net_table.add_row(TableRow(
                    event=ev["event"], server=ev.get("server", ""), port=ev.get("port", ""),
                    query=ev.get("query", ""), response=ev.get("response", ""),
                ))
                heur4.add_signature_id(ev["event"])
            net_table.set_heuristic(heur4)
            result.add_section(net_table)

        clipboard_events = [ev for ev in all_events if ev["event"] == "clipboard"]
        if clipboard_events:
            replacements = clipboard_replacements(clipboard_events)
            clip_table = ResultTableSection("Clipboard activity (emulated clipboard with synthetic wallet-shaped text)")
            for ev in clipboard_events[:max_rows]:
                clip_table.add_row(TableRow(
                    action=ev.get("action", ""), format=ev.get("format", ""), text=ev.get("text") or "",
                ))
            if replacements:
                clip_table.add_subsection(ResultSection(
                    "Clipboard text was replaced (clipboard hijacker behaviour)",
                    body="\n".join(f"{old}  ->  {new}" for old, new in replacements[:max_rows]),
                ))
                clip_table.set_heuristic(7, signature="clipboard_replaced")
                wallets = list(dict.fromkeys(new for _, new in replacements))
                for wallet in wallets:
                    clip_table.add_tag("file.string.extracted", wallet)
                # The attacker's wallets are what a clipper is configured with, so they go into the
                # result ontology as a malware config's cryptocurrency list.
                self.ontology.add_result_part(MalwareConfig, {
                    "config_extractor": "Speakeasy",
                    "family": [],
                    "attack": ["T1115"],
                    "cryptocurrency": [
                        {k: v for k, v in (("coin", classify_wallet(w)), ("address", w), ("usage", "other")) if v}
                        for w in wallets
                    ],
                })
            else:
                clip_table.set_heuristic(7, signature="clipboard_access")
            result.add_section(clip_table)

        top_level_errors = report.get("errors") or []
        ep_errors = [(i, ep) for i, ep in enumerate(entry_points) if ep.get("error")]
        if top_level_errors or ep_errors:
            lines = []
            for i, ep in ep_errors:
                err = ep["error"]
                lines.append(
                    f"Entry point {i} ({ep.get('ep_type', 'unknown')} at {ep.get('start_addr', '?')}): "
                    f"{err.get('type', 'unknown error')} at pc={err.get('pc', '?')} "
                    f"(instr: {err.get('instr', '?')})"
                )
            for err in top_level_errors:
                lines.append(
                    f"Session-level: {err.get('type', 'unknown error')} at pc={err.get('pc', '?')} "
                    f"(instr: {err.get('instr', '?')})"
                )
            error_section = ResultSection("Emulation errors encountered", body="\n".join(lines))
            error_section.set_heuristic(5, signature="emulation_error")
            result.add_section(error_section)

        request.result = result
        self._save_log(request, speakeasy)

    def _save_log(self, request: ServiceRequest, speakeasy) -> None:
        log_path = os.path.join(self.working_directory, "speakeasy_report.json")
        with open(log_path, "w") as f:
            if speakeasy.report is not None:
                json.dump(speakeasy.report, f, indent=2)
            else:
                f.write(speakeasy.stdout)
                f.write("\n---- stderr ----\n")
                f.write(speakeasy.stderr)
        request.add_supplementary(log_path, "speakeasy_report.json", "Full raw Speakeasy emulation report")
