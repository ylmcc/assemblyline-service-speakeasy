"""Emulated CNG symmetric crypto (AES-CBC and AES-GCM) checked against pycryptodome. Synthetic keys and data."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from Crypto.Cipher import AES  # noqa: E402
from speakeasy.winenv.api.usermode.bcrypt import STATUS_AUTH_TAG_MISMATCH, Bcrypt  # noqa: E402

KEY = bytes(range(32))
NONCE = bytes(range(12))
BASE_IN, BASE_OUT, BASE_INFO, BASE_NONCE, BASE_TAG, BASE_AAD, BASE_RES, BASE_IV = (
    0x1000, 0x20000, 0x40000, 0x41000, 0x42000, 0x43000, 0x44000, 0x45000)


def _handler(mode):
    h = object.__new__(Bcrypt)
    h.memory = bytearray(0x50000)
    h.events = []
    h.sym_keys = {0x684: {"alg": "AES", "mode": mode, "mode_name": mode, "secret": KEY}}
    h.mem_read = lambda addr, n: bytes(h.memory[addr:addr + n])
    h.mem_write = lambda addr, data: h.memory.__setitem__(slice(addr, addr + len(data)), bytes(data))
    h.record_crypto_event = lambda *args: h.events.append(args)
    emu = MagicMock()
    emu.get_ptr_size.return_value = 8
    return h, emu


def _put(h, addr, data):
    h.mem_write(addr, data)


def _argv(size, out_size, info=0, iv=0, flags=0):
    return [0x684, BASE_IN, size, info, iv, 16 if iv else 0, BASE_OUT, out_size, BASE_RES, flags]


def test_cbc_decrypt_with_padding_matches_pycryptodome():
    h, emu = _handler("CBC")
    iv = bytes(16)
    plain = b"synthetic payload bytes!"
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(plain + bytes([8]) * 8)
    _put(h, BASE_IN, ct)
    _put(h, BASE_IV, iv)
    assert h._symmetric(emu, _argv(len(ct), 64, iv=BASE_IV, flags=1), encrypt=False) == 0
    assert h.memory[BASE_OUT:BASE_OUT + len(plain)] == plain
    assert int.from_bytes(h.memory[BASE_RES:BASE_RES + 4], "little") == len(plain)
    assert h.events[0][:3] == ("decrypt", "AES", "CBC") and h.events[0][-1] == plain
    assert h.memory[BASE_IV:BASE_IV + 16] == ct[-16:]  # chaining value left in the caller's IV buffer


def test_cbc_size_query_and_bad_length():
    h, emu = _handler("CBC")
    _put(h, BASE_IN, b"x" * 20)
    argv = _argv(20, 0, flags=1)
    argv[6] = 0  # no output buffer: report the size needed
    assert h._symmetric(emu, argv, encrypt=True) == 0
    assert int.from_bytes(h.memory[BASE_RES:BASE_RES + 4], "little") == 32
    assert h._symmetric(emu, _argv(20, 64, flags=0), encrypt=True) == 0xC0000206  # not block aligned, no padding


def _gcm_info(h, nonce, tag, aad):
    _put(h, BASE_NONCE, nonce)
    _put(h, BASE_TAG, tag)
    _put(h, BASE_AAD, aad)
    info = bytearray(96)
    for offset, value in ((8, BASE_NONCE), (16, len(nonce)), (24, BASE_AAD), (32, len(aad)),
                          (40, BASE_TAG), (48, len(tag))):
        info[offset:offset + 8] = value.to_bytes(8, "little")
    _put(h, BASE_INFO, bytes(info))


def test_gcm_decrypt_verifies_the_tag_and_returns_plaintext():
    h, emu = _handler("GCM")
    plain = b"p" * 1000
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    cipher.update(b"header")
    ct, tag = cipher.encrypt_and_digest(plain)
    _put(h, BASE_IN, ct)
    _gcm_info(h, NONCE, tag, b"header")
    assert h._symmetric(emu, _argv(len(ct), 2000, info=BASE_INFO), encrypt=False) == 0
    assert h.memory[BASE_OUT:BASE_OUT + len(plain)] == plain
    assert h.events[0][2] == "GCM" and h.events[0][4] == NONCE


def test_gcm_decrypt_with_a_wrong_tag_fails_like_windows():
    h, emu = _handler("GCM")
    ct = AES.new(KEY, AES.MODE_GCM, nonce=NONCE).encrypt(b"data")
    _put(h, BASE_IN, ct)
    _gcm_info(h, NONCE, bytes(16), b"")
    assert h._symmetric(emu, _argv(len(ct), 64, info=BASE_INFO), encrypt=False) == STATUS_AUTH_TAG_MISMATCH
    assert not h.events


def test_gcm_encrypt_writes_the_tag_back():
    h, emu = _handler("GCM")
    _put(h, BASE_IN, b"hello world")
    _gcm_info(h, NONCE, bytes(16), b"")
    assert h._symmetric(emu, _argv(11, 64, info=BASE_INFO), encrypt=True) == 0
    ct, tag = AES.new(KEY, AES.MODE_GCM, nonce=NONCE).encrypt_and_digest(b"hello world")
    assert h.memory[BASE_OUT:BASE_OUT + 11] == ct
    assert h.memory[BASE_TAG:BASE_TAG + 16] == tag


def test_unsupported_key_size_is_reported_not_faked():
    h, emu = _handler("CBC")
    h.sym_keys[0x684]["secret"] = b"short"
    assert h._symmetric(emu, _argv(16, 64), encrypt=False) == 0xC00000BB
