# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import speakeasy.winenv.defs.nt.ddk as ntdefs

from .. import api


STATUS_INVALID_BUFFER_SIZE = 0xC0000206
BCRYPT_BLOCK_PADDING = 0x1
STATUS_AUTH_TAG_MISMATCH = 0xC000A002
_MODES = {"ChainingModeCBC": "CBC", "ChainingModeECB": "ECB", "ChainingModeCFB": "CFB", "ChainingModeGCM": "GCM"}


class Bcrypt(api.ApiHandler):
    """
    Implements exported functions from bcrypt.dll
    """

    name = "bcrypt"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        # Symmetric-key state for the CNG calls below: handle -> chaining mode, handle -> {alg, mode, secret}.
        self.chaining_modes = {}
        self.sym_keys = {}

        super().__get_hook_attrs__(self)

    @apihook("BCryptOpenAlgorithmProvider", argc=4)
    def BCryptOpenAlgorithmProvider(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptOpenAlgorithmProvider(
          BCRYPT_ALG_HANDLE *phAlgorithm,
          LPCWSTR           pszAlgId,
          LPCWSTR           pszImplementation,
          ULONG             dwFlags
        );
        """
        phAlgorithm, pszAlgId, pszImplementation, dwFlags = argv

        algid = self.read_wide_string(pszAlgId)
        if algid:
            argv[1] = algid

        implementation = ""
        if pszImplementation:
            implementation = self.read_wide_string(pszImplementation)
            if implementation:
                argv[2] = implementation

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(pname=implementation, ptype=algid, flags=dwFlags)
        if hnd:
            self.mem_write(phAlgorithm, hnd.to_bytes(emu.get_ptr_size(), "little"))
            argv[0] = hnd

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptImportKeyPair", argc=7)
    def BCryptImportKeyPair(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptImportKeyPair(
          BCRYPT_ALG_HANDLE hAlgorithm,
          BCRYPT_KEY_HANDLE hImportKey,
          LPCWSTR           pszBlobType,
          BCRYPT_KEY_HANDLE *phKey,
          PUCHAR            pbInput,
          ULONG             cbInput,
          ULONG             dwFlags
        );
        """
        ctx = ctx or {}
        hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags = argv

        blob_type = self.read_wide_string(pszBlobType)
        argv[2] = blob_type

        cbInput = cbInput & 0xFFFFFFFF
        blob = self.mem_read(pbInput, cbInput)
        argv[4] = base64.b64encode(blob).decode("utf-8")

        cm = emu.get_crypt_manager()
        if hAlgorithm and phKey:
            ctx = cm.crypt_get(hAlgorithm)
            hnd = ctx.import_key(blob_type=blob_type, blob=blob, blob_len=cbInput, flags=dwFlags)
            if hnd:
                self.mem_write(phKey, hnd.to_bytes(emu.get_ptr_size(), "little"))
                argv[3] = hnd

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptCloseAlgorithmProvider", argc=2)
    def BCryptCloseAlgorithmProvider(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptCloseAlgorithmProvider(
          BCRYPT_ALG_HANDLE hAlgorithm,
          ULONG             dwFlags
        );
        """
        hAlgorithm, dwFlags = argv

        cm = emu.get_crypt_manager()
        if hAlgorithm:
            cm.crypt_close(hAlgorithm)

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptGetProperty", argc=6)
    def BCryptGetProperty(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptGetProperty(
          BCRYPT_HANDLE hObject,
          LPCWSTR       pszProperty,
          PUCHAR        pbOutput,
          ULONG         cbOutput,
          ULONG         *pcbResult,
          ULONG         dwFlags
        );
        """
        hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags = argv

        property = self.read_wide_string(pszProperty)
        if property:
            argv[1] = property

        # TODO: implement property retrieval

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptSetProperty", argc=5)
    def BCryptSetProperty(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptSetProperty(
          BCRYPT_HANDLE hObject,
          LPCWSTR       pszProperty,
          PUCHAR        pbInput,
          ULONG         cbInput,
          ULONG         dwFlags
        );
        """
        hObject, pszProperty, pbInput, cbInput, dwFlags = argv
        prop = self.read_wide_string(pszProperty)
        if prop:
            argv[1] = prop
        if prop == "ChainingMode" and pbInput and cbInput:
            value = self.read_wide_string(pbInput, max_chars=(cbInput & 0xFFFFFFFF) // 2)
            self.chaining_modes[hObject] = value.rstrip("\x00")
        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptGenerateSymmetricKey", argc=7)
    def BCryptGenerateSymmetricKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptGenerateSymmetricKey(
          BCRYPT_ALG_HANDLE hAlgorithm,
          BCRYPT_KEY_HANDLE *phKey,
          PUCHAR            pbKeyObject,
          ULONG             cbKeyObject,
          PUCHAR            pbSecret,
          ULONG             cbSecret,
          ULONG             dwFlags
        );
        """
        hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags = argv
        cm = emu.get_crypt_manager()
        alg = cm.crypt_get(hAlgorithm)
        if alg is None:
            return ntdefs.STATUS_INVALID_HANDLE
        secret = self.mem_read(pbSecret, cbSecret & 0xFFFFFFFF) if pbSecret else b""
        hnd = cm.allocator.allocate_crypt_context_handle()
        self.sym_keys[hnd] = {
            "alg": (alg.ptype or "").upper(),
            "mode": _MODES.get(self.chaining_modes.get(hAlgorithm, "ChainingModeCBC")),
            "mode_name": self.chaining_modes.get(hAlgorithm, "ChainingModeCBC"),
            "secret": secret,
        }
        self.mem_write(phKey, hnd.to_bytes(emu.get_ptr_size(), "little"))
        argv[1] = hnd
        argv[4] = secret.hex()
        return ntdefs.STATUS_SUCCESS

    def _symmetric(self, emu, argv, encrypt):
        hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags = argv
        key = self.sym_keys.get(hKey)
        if key is None:
            return ntdefs.STATUS_INVALID_HANDLE
        if key["alg"] != "AES" or key["mode"] is None or len(key["secret"]) not in (16, 24, 32):
            return ntdefs.STATUS_NOT_SUPPORTED

        cbInput &= 0xFFFFFFFF
        cbIV &= 0xFFFFFFFF
        cbOutput &= 0xFFFFFFFF
        data = self.mem_read(pbInput, cbInput) if pbInput and cbInput else b""
        if key["mode"] == "GCM":
            return self._gcm(emu, argv, key, data, encrypt)
        iv = self.mem_read(pbIV, cbIV) if pbIV and cbIV else None
        padded = bool(dwFlags & BCRYPT_BLOCK_PADDING)

        if key["mode"] == "ECB":
            cipher = AES.new(key["secret"], AES.MODE_ECB)
        elif key["mode"] == "CBC":
            cipher = AES.new(key["secret"], AES.MODE_CBC, (iv or bytes(16))[:16].ljust(16, b"\x00"))
        else:  # CFB: CNG's default feedback is 8 bits
            cipher = AES.new(key["secret"], AES.MODE_CFB, (iv or bytes(16))[:16].ljust(16, b"\x00"), segment_size=8)

        block_mode = key["mode"] in ("CBC", "ECB")
        if encrypt:
            if block_mode and padded:
                data_in = pad(data, 16)
            else:
                data_in = data
            needed = len(data_in)
        else:
            needed = cbInput

        if block_mode and not padded and cbInput % 16:
            return STATUS_INVALID_BUFFER_SIZE

        if not pbOutput:
            if pcbResult:
                self.mem_write(pcbResult, needed.to_bytes(4, "little"))
            return ntdefs.STATUS_SUCCESS

        try:
            out = cipher.encrypt(data_in) if encrypt else cipher.decrypt(data)
            if not encrypt and block_mode and padded:
                out = unpad(out, 16)
        except ValueError:
            return ntdefs.STATUS_INVALID_PARAMETER
        if len(out) > cbOutput:
            if pcbResult:
                self.mem_write(pcbResult, len(out).to_bytes(4, "little"))
            return ntdefs.STATUS_BUFFER_TOO_SMALL

        self.mem_write(pbOutput, out)
        if pcbResult:
            self.mem_write(pcbResult, len(out).to_bytes(4, "little"))
        if key["mode"] == "CBC" and pbIV and cbIV:
            # CNG leaves the chaining value (the last ciphertext block) in the caller's IV buffer.
            last = (out if encrypt else data)[-16:]
            if len(last) == 16:
                self.mem_write(pbIV, last)

        plaintext = data if encrypt else out
        self.record_crypto_event("encrypt" if encrypt else "decrypt", key["alg"], key["mode"], key["secret"], iv,
                                 cbInput, len(out), plaintext)
        argv[1] = "<%d bytes>" % cbInput
        return ntdefs.STATUS_SUCCESS

    def _gcm(self, emu, argv, key, data, encrypt):
        """AES-GCM: the nonce, tag and additional data arrive in a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO."""
        _, _, _, pPaddingInfo, _, _, pbOutput, cbOutput, pcbResult, _ = argv
        cbOutput &= 0xFFFFFFFF
        if not pPaddingInfo:
            return ntdefs.STATUS_INVALID_PARAMETER
        ptr = emu.get_ptr_size()
        # Field offsets of the structure for 4- and 8-byte pointers (each pointer is followed by its ULONG size).
        offs = (8, 16, 24, 32, 40, 48) if ptr == 8 else (8, 12, 16, 20, 24, 28)

        def field(offset, size):
            return int.from_bytes(self.mem_read(pPaddingInfo + offset, size), "little")

        nonce_p, nonce_n, aad_p, aad_n, tag_p, tag_n = (
            field(offs[0], ptr), field(offs[1], 4), field(offs[2], ptr), field(offs[3], 4),
            field(offs[4], ptr), field(offs[5], 4))
        nonce = self.mem_read(nonce_p, nonce_n) if nonce_p and nonce_n else b""
        aad = self.mem_read(aad_p, aad_n) if aad_p and aad_n else b""
        tag = self.mem_read(tag_p, tag_n) if tag_p and tag_n else b""

        if not pbOutput:
            if pcbResult:
                self.mem_write(pcbResult, len(data).to_bytes(4, "little"))
            return ntdefs.STATUS_SUCCESS
        if len(data) > cbOutput:
            return ntdefs.STATUS_BUFFER_TOO_SMALL
        if not nonce:
            return ntdefs.STATUS_INVALID_PARAMETER

        cipher = AES.new(key["secret"], AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        if encrypt:
            out = cipher.encrypt(data)
            if tag_p:
                self.mem_write(tag_p, cipher.digest()[:tag_n])
        else:
            try:
                out = cipher.decrypt_and_verify(data, tag)
            except ValueError:
                return STATUS_AUTH_TAG_MISMATCH
        self.mem_write(pbOutput, out)
        if pcbResult:
            self.mem_write(pcbResult, len(out).to_bytes(4, "little"))
        self.record_crypto_event("encrypt" if encrypt else "decrypt", key["alg"], "GCM", key["secret"], nonce,
                                 len(data), len(out), data if encrypt else out)
        argv[1] = "<%d bytes>" % len(data)
        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptEncrypt", argc=10)
    def BCryptEncrypt(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptEncrypt(
          BCRYPT_KEY_HANDLE hKey,
          PUCHAR            pbInput,
          ULONG             cbInput,
          VOID              *pPaddingInfo,
          PUCHAR            pbIV,
          ULONG             cbIV,
          PUCHAR            pbOutput,
          ULONG             cbOutput,
          ULONG             *pcbResult,
          ULONG             dwFlags
        );
        """
        return self._symmetric(emu, argv, encrypt=True)

    @apihook("BCryptDecrypt", argc=10)
    def BCryptDecrypt(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptDecrypt(
          BCRYPT_KEY_HANDLE hKey,
          PUCHAR            pbInput,
          ULONG             cbInput,
          VOID              *pPaddingInfo,
          PUCHAR            pbIV,
          ULONG             cbIV,
          PUCHAR            pbOutput,
          ULONG             cbOutput,
          ULONG             *pcbResult,
          ULONG             dwFlags
        );
        """
        return self._symmetric(emu, argv, encrypt=False)

    @apihook("BCryptDestroyKey", argc=1)
    def BCryptDestroyKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptDestroyKey(
          BCRYPT_KEY_HANDLE hKey
        );
        """
        ctx = ctx or {}
        (hKey,) = argv
        if self.sym_keys.pop(hKey, None) is not None:
            return ntdefs.STATUS_SUCCESS
        cm = emu.get_crypt_manager()
        for hnd, ctx in cm.ctx_handles.items():
            hnd_key = ctx.get_key(hKey)
            if hnd_key:
                ctx.delete_key(hKey)
                return ntdefs.STATUS_SUCCESS

        return ntdefs.STATUS_INVALID_HANDLE
