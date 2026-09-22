import speakeasy.winenv.arch as _arch

from .. import api

ERROR_RESOURCE_DATA_NOT_FOUND = 1812


class Version(api.ApiHandler):
    """
    Implements exported functions from version.dll.

    Nothing in the emulated file system carries version resources, so every query reports "no version
    information". What matters is that the DLL loads: a reflective loader that cannot resolve one of its
    payload's imports aborts, and the payload never runs.
    """

    name = "version"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("GetFileVersionInfoSizeW", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def GetFileVersionInfoSizeW(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetFileVersionInfoSizeW(
          LPCWSTR lptstrFilename,
          LPDWORD lpdwHandle
        );
        """
        emu.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND)
        return 0

    @apihook("GetFileVersionInfoSizeA", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def GetFileVersionInfoSizeA(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetFileVersionInfoSizeA(
          LPCSTR  lptstrFilename,
          LPDWORD lpdwHandle
        );
        """
        emu.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND)
        return 0

    @apihook("GetFileVersionInfoW", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def GetFileVersionInfoW(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetFileVersionInfoW(
          LPCWSTR lptstrFilename,
          DWORD   dwHandle,
          DWORD   dwLen,
          LPVOID  lpData
        );
        """
        emu.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND)
        return 0

    @apihook("GetFileVersionInfoA", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def GetFileVersionInfoA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetFileVersionInfoA(
          LPCSTR lptstrFilename,
          DWORD  dwHandle,
          DWORD  dwLen,
          LPVOID lpData
        );
        """
        emu.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND)
        return 0

    @apihook("VerQueryValueW", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def VerQueryValueW(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL VerQueryValueW(
          LPCVOID pBlock,
          LPCWSTR lpSubBlock,
          LPVOID  *lplpBuffer,
          PUINT   puLen
        );
        """
        return 0

    @apihook("VerQueryValueA", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def VerQueryValueA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL VerQueryValueA(
          LPCVOID pBlock,
          LPCSTR  lpSubBlock,
          LPVOID  *lplpBuffer,
          PUINT   puLen
        );
        """
        return 0
