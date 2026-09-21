# Speakeasy

Docker Hub: [kylemc54321/assemblyline-service-speakeasy](https://hub.docker.com/r/kylemc54321/assemblyline-service-speakeasy)

An AssemblyLine v4 service that emulates Windows PE binaries, drivers, and raw
shellcode against a modeled Windows runtime — API calls, process/thread behavior,
filesystem, registry, and network activity — using a vendored copy of
[Mandiant's Speakeasy](https://github.com/mandiant/speakeasy). It surfaces behavior a
static-only pass would miss: unpacking, process injection, dropped files, registry
persistence, and C2-shaped network indicators.

## Safety: this is pure emulation, not real execution

Speakeasy is a CPU-instruction emulator (built on [Unicorn](https://www.unicorn-engine.org/)):
it single-steps the sample's own machine code against a **modeled** Windows API,
filesystem, registry, and network surface, not the real host.

- **No real syscalls reach the host OS.** Every `kernel32`/`ntdll`/etc. call the
  sample makes is intercepted and answered by Speakeasy's own Python API handlers.
- **No real network connection is ever made.** Report events like `net_dns`,
  `net_traffic`, and `net_http` are Speakeasy's own simulated responses to the
  sample's API calls, not real sockets. `allow_internet_access: false` in this
  service's manifest reflects that this is true by construction, not just policy.
- **No real filesystem/registry mutation occurs** outside Speakeasy's in-memory
  virtual models; "dropped files" are recovered from that virtual model, not the host
  disk.

This service never executes the submitted sample any other way.

## License

MIT. This repository vendors the source of Mandiant's Speakeasy (also MIT) — see
`NOTICE` for exact provenance, including how the two upstream build-time-only git
submodules (`win32json`, `phnt` — both MIT, used only to generate Windows API
signature databases) were handled: rather than vendoring their source or requiring
network access during the Docker build, their generated output
(`signatures.json.gz` / `phnt_signatures.json.gz`) was produced once and committed
directly, since `pip install` on the upstream package hard-fails without one or the
other being present.

## How it works

The vendored `speakeasy` CLI entry point is invoked as a subprocess (`--target
<sample> --no-mp --output <report.json> --timeout ...`), with an `RLIMIT_AS` memory
cap and a wall-clock timeout on top of Speakeasy's own internal timeout, since a
malformed or adversarially crafted binary is exactly the kind of input an emulator is
pointed at. The resulting JSON report (schema documented upstream in
[doc/reporting.md](https://github.com/mandiant/speakeasy/blob/master/doc/reporting.md))
is parsed directly; the full raw report is always attached as a supplementary file.
Files the sample wrote during emulation (`dropped_files`, resolved through the
report's own `data` store: base64 + optional zlib) are recovered and resubmitted to
AssemblyLine for further static analysis.

## Detected signals

| Heuristic | Meaning |
|---|---|
| 1. Emulation completed | Informational: Speakeasy produced a usable report. |
| 2. Cross-process / injection activity | Memory allocation/write in another process, remote thread creation/injection, or child process spawn. |
| 3. Files dropped during emulation | Files written by the sample were recovered and re-submitted. |
| 4. Emulated network activity | DNS/network/HTTP-shaped API calls (simulated responses, not real traffic) — still a useful C2/beacon-shaped indicator. |
| 5. Emulation errors encountered | Session- or entry-point-level errors were recorded (e.g. an unsupported API). |
| 6. Emulation incomplete or failed | Timeout, or no parseable report was produced. |
| 7. Clipboard activity | The sample used the clipboard. Speakeasy's emulated clipboard offers synthetic wallet-address-shaped text (BTC, ETH, LTC, DOGE, TRX, XRP, SOL, XMR formats), so a sample that writes back different text is a clipboard hijacker: scored 500 as `clipboard_replaced`, with the substituted text tagged `file.string.extracted` and the wallets added to the result ontology as a `MalwareConfig` `cryptocurrency` list (coin inferred from the address format; shape only, no checksum check). Plain reads score 0. |

## Submission parameters

| Param | Default | Purpose |
|---|---|---|
| `emulation_timeout_seconds` | 60 | Speakeasy's own `--timeout`; the subprocess wall-clock timeout is this plus a 30s buffer. |
| `max_emulation_memory_mb` | 2048 | `RLIMIT_AS` cap on the Speakeasy subprocess. |
| `max_events_displayed` | 500 | Cap on rows shown per event table; the full report is always in the supplementary JSON. |
| `emulate_children` | false | Passes `-k` / `--emulate-children` (also emulate child processes spawned by the sample). |
| `extract_strings` | true | Passes `--analysis-strings` / `--no-analysis-strings`. |
| `raw_mode` | false | Passes `--raw` (treat input as raw shellcode instead of a PE). |
| `raw_arch` | "" | Passes `--arch` when `raw_mode` is set (`x86`/`amd64`). |
| `raw_offset_hex` | "" | Passes `--raw-offset` when `raw_mode` is set. |

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install assemblyline-v4-service assemblyline-service-utilities pytest pyyaml
.venv/bin/pytest test/
```

No test in this repo invokes the real vendored Speakeasy binary against an actual PE
sample — that would require the full (heavyweight, compiled) speakeasy install plus a
real executable fixture. Speakeasy's own emulation correctness is Mandiant's problem,
not this wrapper's — tests mock the `subprocess.run` boundary with a canned,
schema-accurate JSON report (see `test/unit/fixtures.py`, shaped after Speakeasy's own
documented `doc/reporting.md` example) and verify this service's own flag
construction, dropped-file decoding, and result-building logic against it. The sample
fixture in `test/samples/*.cart` is therefore just an arbitrary placeholder file, not
a real or real-shaped executable. The Docker image itself was manually verified to
build and run the real vendored `speakeasy` binary correctly (`speakeasy
--dump-default-config`, which needs no target file at all).
