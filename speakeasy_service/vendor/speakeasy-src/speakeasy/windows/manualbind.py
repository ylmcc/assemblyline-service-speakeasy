"""Best-effort import binding for a PE image a sample maps into memory itself (VirtualAlloc +
write raw bytes + VirtualProtect -- the common reflective-loader/crypter pattern for running an
embedded payload). Speakeasy's own PE loader binds imports when it loads a module directly;
nothing binds imports for an image the *guest* maps by hand, so a manually-mapped payload's IAT is
left exactly as it was in the file -- valid only when the payload happens to land at its own
preferred image base. Mapped anywhere else, calling through an unbound slot jumps to garbage.

This mirrors what the real Windows loader does for a normally-loaded module: walk the image's own
import directory and write each named-import slot the same resolved address get_proc() already
gives Speakeasy's own hooked imports. It reads directly from guest memory (never a copy of the
file), and is best-effort throughout: any malformed/unreadable structure just stops early rather
than raising, so a genuinely broken or non-PE region is silently left alone.
"""
from __future__ import annotations

import struct
from typing import Optional


def _read(emu, addr: int, size: int) -> Optional[bytes]:
    try:
        data = emu.mem_read(addr, size)
    except Exception:
        return None
    return bytes(data) if data else None


def looks_like_pe_image(emu, base: int) -> bool:
    """True if guest memory at ``base`` starts with a DOS header whose e_lfanew points at a
    readable "PE\\0\\0" signature. Doesn't guarantee the image is well-formed beyond that."""
    hdr = _read(emu, base, 0x40)
    if not hdr or hdr[:2] != b"MZ":
        return False
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    if not (0 < e_lfanew <= 0x1000):
        return False
    return _read(emu, base + e_lfanew, 4) == b"PE\x00\x00"


def bind_manual_image(emu, base: int) -> Optional[int]:
    """Walk the import directory of the PE image mapped at ``base`` in guest memory and write a
    resolved address into every named-import IAT slot (ordinal-only imports are left alone: there
    is no name to resolve them by here). Returns the number of slots bound, or None if ``base``
    doesn't hold a readable "MZ"/"PE" image."""
    hdr = _read(emu, base, 0x40)
    if not hdr or hdr[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    if not (0 < e_lfanew <= 0x1000):
        return None
    nt_hdr = _read(emu, base + e_lfanew, 0x108)
    if not nt_hdr or nt_hdr[:4] != b"PE\x00\x00":
        return None

    machine = struct.unpack_from("<H", nt_hdr, 4)[0]
    is_64 = machine == 0x8664
    if not is_64 and machine != 0x14C:
        return 0  # not x86/x64; the ordinal-flag/pointer-size assumptions below don't apply

    opt_hdr_off = 24
    magic = struct.unpack_from("<H", nt_hdr, opt_hdr_off)[0]
    if (magic == 0x20B) != is_64:
        return 0  # PE32/PE32+ mismatch against the declared machine; not confident enough to bind

    num_dirs_off = opt_hdr_off + (108 if is_64 else 92)
    if num_dirs_off + 4 > len(nt_hdr):
        return 0
    num_dirs = struct.unpack_from("<I", nt_hdr, num_dirs_off)[0]
    if num_dirs < 2:
        return 0
    import_rva, _import_size = struct.unpack_from("<II", nt_hdr, num_dirs_off + 4 + 8)
    if not import_rva:
        return 0

    ptr_size = 8 if is_64 else 4
    ordinal_flag = 1 << (63 if is_64 else 31)
    ordinal_mask = (1 << 63) - 1 if is_64 else (1 << 31) - 1
    bound = 0
    desc_addr = base + import_rva
    seen_descriptors = 0

    while seen_descriptors < 512:  # a real import table is never anywhere near this large
        seen_descriptors += 1
        desc = _read(emu, desc_addr, 20)
        if not desc:
            break
        orig_first_thunk, _time, _fwd, name_rva, first_thunk = struct.unpack("<IIIII", desc)
        if not name_rva and not first_thunk:
            break

        name_bytes = _read(emu, base + name_rva, 64) or b""
        dll = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace").split(".")[0]

        thunk_rva = orig_first_thunk or first_thunk
        ilt_addr = base + thunk_rva if thunk_rva else 0
        iat_addr = base + first_thunk
        thunks_walked = 0
        while ilt_addr and thunks_walked < 8192:
            thunks_walked += 1
            entry = _read(emu, ilt_addr, ptr_size)
            if not entry:
                break
            value = int.from_bytes(entry, "little")
            if value == 0:
                break
            if value & ordinal_flag:
                ilt_addr += ptr_size
                iat_addr += ptr_size
                continue  # ordinal-only import: no name here to resolve it by
            hint_name = _read(emu, base + (value & ordinal_mask) + 2, 128) or b""
            func = hint_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            if func and dll:
                try:
                    resolved = emu.get_proc(dll, func)
                except Exception:
                    resolved = None
                if resolved:
                    if _read(emu, iat_addr, ptr_size) is not None:
                        try:
                            emu.mem_write(iat_addr, resolved.to_bytes(ptr_size, "little"))
                            bound += 1
                        except Exception:
                            pass
            ilt_addr += ptr_size
            iat_addr += ptr_size
        desc_addr += 20

    return bound
