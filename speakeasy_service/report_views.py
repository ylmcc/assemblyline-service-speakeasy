"""Turn a Speakeasy report into readable rows.

Pure functions over the report's JSON structure (no AssemblyLine imports), so they can be tested with
small synthetic reports.
"""
from __future__ import annotations

import re

_CRT = re.compile(r"^api-ms-win-crt-\w+-l\d+-\d+-\d+\.")
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
_ENV_ENTRY = re.compile(r"^[A-Za-z_()]+=")

# Checked in order; an API lands in the first category it matches.
_CATEGORIES: list[tuple[str, re.Pattern]] = [(name, re.compile(rx, re.I)) for name, rx in [
    ("anti_debug", r"\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString\w*|NtSetInformationThread|"
                   r"NtQueryInformationProcess|DebugActiveProcess|ZwQueryInformationProcess)$"),
    ("environment_check", r"\b(GetSystemFirmwareTable|EnumSystemFirmwareTables|GetCursorPos|GlobalMemoryStatusEx|"
                          r"GetDiskFreeSpaceEx\w|GetComputerName\w*|GetUserName\w*|GetSystemMetrics|GetTickCount\w*|"
                          r"GetSystemInfo|GetNativeSystemInfo|GetVolumeInformation\w|IsProcessorFeaturePresent|"
                          r"GetLastInputInfo|GetKeyboardLayout|SetupDi\w+|EnumDisplay\w+)$"),
    ("crypto", r"^(bcrypt|ncrypt|crypt32)\.|\.(Crypt\w+|BCrypt\w+|NCrypt\w+|CertOpen\w+)$"),
    ("dynamic_resolution", r"\b(GetProcAddress|LoadLibrary\w*|LdrLoadDll|LdrGetProcedureAddress|GetModuleHandle\w*)$"),
    ("memory", r"\b(VirtualAlloc\w*|VirtualProtect\w*|WriteProcessMemory|ReadProcessMemory|NtAllocateVirtualMemory|"
               r"NtProtectVirtualMemory|NtWriteVirtualMemory|NtMapViewOfSection|HeapCreate|MapViewOfFile\w*)$"),
    ("process", r"\b(CreateProcess\w*|CreateRemoteThread\w*|OpenProcess|ShellExecute\w*|WinExec|NtCreateThreadEx|"
                r"QueueUserAPC|SetThreadContext|ResumeThread|CreateThread|TerminateProcess|NtCreateUserProcess)$"),
    ("file", r"\b(CreateFile\w*|WriteFile|ReadFile|DeleteFile\w*|MoveFile\w*|CopyFile\w*|FindFirstFile\w*|"
             r"NtCreateFile|NtWriteFile|GetTempPath\w*|SetFileAttributes\w*)$"),
    ("registry", r"\b(Reg\w+|NtOpenKey|NtSetValueKey|NtQueryValueKey)$"),
    ("network", r"\b(Internet\w+|Http\w+|WSA\w+|socket|connect|send|recv|sendto|recvfrom|bind|listen|accept|"
                r"URLDownloadToFile\w*|DnsQuery\w*|getaddrinfo|gethostbyname|WinHttp\w+)$"),
    ("persistence", r"\b(CreateService\w*|StartService\w*|ChangeServiceConfig\w*|SchRpc\w+)$"),
]]

_STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".pdata", ".rsrc", ".reloc", ".idata", ".edata", ".bss", ".tls", ".crt", ".didat",
    ".gfids", ".00cfg", ".xdata", ".CRT", ".itext", ".eh_fram", ".buildid", ".sxdata", ".debug", "INIT", "PAGE",
    "PAGEKD", ".pdb", "headers",
}


def short_api(name: str) -> str:
    """kernel32.GetProcAddress stays as is; api-ms-win-crt-heap-l1-1-0.malloc becomes crt.malloc."""
    return _CRT.sub("crt.", name or "")


def clean_arg(value, width: int = 48) -> str:
    text = _UNPRINTABLE.sub(".", str(value))
    return text if len(text) <= width else text[:width - 1] + "…"


def api_events(events: list[dict]) -> list[dict]:
    return [ev for ev in events if ev.get("event") == "api"]


def format_args(args, total_width: int = 160) -> str:
    text = ", ".join(clean_arg(a) for a in (args or []))
    return text if len(text) <= total_width else text[:total_width - 1] + "…"


def collapse_trace(calls: list[dict], limit: int) -> tuple[list[dict], int]:
    """Rows for the API trace in call order, with consecutive identical calls folded into one row with a
    repeat count. Returns (rows, number of rows left out because of the limit)."""
    rows: list[dict] = []
    for call in calls:
        api, args, ret = short_api(call.get("api_name", "")), format_args(call.get("args")), call.get("ret_val", "")
        if rows and (rows[-1]["api"], rows[-1]["arguments"], rows[-1]["returned"]) == (api, args, ret):
            rows[-1]["times"] += 1
            continue
        rows.append({"api": api, "arguments": args, "returned": ret, "times": 1})
    omitted = max(0, len(rows) - limit)
    shown = rows[:limit]
    for number, row in enumerate(shown, 1):
        row["seq"] = number
    return [{"seq": r["seq"], "api": r["api"], "arguments": r["arguments"], "returned": r["returned"],
             "times": r["times"] if r["times"] > 1 else ""} for r in shown], omitted


def categorise(calls: list[dict]) -> dict[str, dict]:
    """category -> {"count": total calls, "apis": sorted distinct API names}."""
    found: dict[str, dict] = {}
    for call in calls:
        name = short_api(call.get("api_name", ""))
        for category, pattern in _CATEGORIES:
            if pattern.search(name):
                entry = found.setdefault(category, {"count": 0, "apis": set()})
                entry["count"] += 1
                entry["apis"].add(name)
                break
    return {c: {"count": v["count"], "apis": sorted(v["apis"])} for c, v in found.items()}


def crypto_operations(events: list[dict]) -> list[dict]:
    return [ev for ev in events if ev.get("event") == "crypto"]


def runtime_strings(report: dict, limit: int, min_len: int = 6) -> list[str]:
    """Strings the emulated process held in memory that are not present in the file itself: text a sample
    decoded, decrypted or built at run time."""
    strings = report.get("strings") or {}
    static = {s for kind in (strings.get("static") or {}).values() for s in kind}
    seen: list[str] = []
    for kind in (strings.get("in_memory") or {}).values():
        for text in kind:
            # The emulated process's own environment block (comspec=..., windir=...) is not the sample's.
            if _ENV_ENTRY.match(text):
                continue
            if len(text) >= min_len and text not in static and text not in seen:
                seen.append(text)
    return [clean_arg(s, 200) for s in seen[:limit]]


def image_sections(entry_point: dict) -> list[dict]:
    """The main image's sections with a note on anything a packer or crypter tends to leave behind."""
    modules = (entry_point.get("memory") or {}).get("modules") or []
    if not modules:
        return []
    rows = []
    for seg in modules[0].get("segments") or []:
        name, prot = seg.get("name", ""), seg.get("prot", "")
        notes = []
        if name not in _STANDARD_SECTIONS:
            notes.append("non-standard name")
        if "w" in prot and "x" in prot:
            notes.append("writable and executable")
        rows.append({"name": name, "address": seg.get("address", ""), "size": seg.get("size", ""), "prot": prot,
                     "note": ", ".join(notes)})
    return rows


def memory_summary(entry_point: dict) -> dict:
    layout = (entry_point.get("memory") or {}).get("layout") or []
    live = [r for r in layout if not r.get("is_free")]
    return {
        "regions": len(live),
        "executable_regions": sum(1 for r in live if "x" in r.get("prot", "")),
        "writable_executable_regions": sum(1 for r in live if "x" in r.get("prot", "") and "w" in r.get("prot", "")),
    }


def stop_reason(entry_point: dict, calls: list[dict]) -> str:
    error = entry_point.get("error") or {}
    if error:
        api = error.get("api_name")
        return f"{error.get('type', 'error')}" + (f" ({api})" if api else "")
    if calls:
        last = calls[-1]
        if re.search(r"(exit|ExitProcess|TerminateProcess|_exit|quick_exit)$", last.get("api_name", ""), re.I):
            return f"the sample called {short_api(last['api_name'])}({format_args(last.get('args'), 40)})"
    return "the entry point returned" + (f" {entry_point['ret_val']}" if entry_point.get("ret_val") else "")
