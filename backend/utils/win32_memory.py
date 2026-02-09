"""Win32 memory inspection wrappers — Bond's reconnaissance tools.

Provides ctypes wrappers for VirtualQueryEx, ReadProcessMemory,
EnumProcessModules, and GetMappedFileNameW for process memory forensics.
"""

import ctypes
import ctypes.wintypes
from typing import Optional

from .logging import get_logger

logger = get_logger("utils.win32_memory")

# Constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_ALL_ACCESS = 0x001FFFFF

MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE = 0x10
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_NOACCESS = 0x01

# Max bytes to read in a single ReadProcessMemory call
MAX_READ_SIZE = 64 * 1024  # 64 KB

# Try to load Windows libraries
try:
    _kernel32 = ctypes.windll.kernel32
    _psapi = ctypes.windll.psapi
    _WINDOWS = True
except (AttributeError, OSError):
    _kernel32 = None
    _psapi = None
    _WINDOWS = False


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION structure."""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


def is_available() -> bool:
    """Check if Win32 memory APIs are available."""
    return _WINDOWS and _kernel32 is not None


def open_process(pid: int, access: int = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) -> Optional[int]:
    """Open a process handle. Returns handle or None."""
    if not _WINDOWS:
        return None
    try:
        handle = _kernel32.OpenProcess(access, False, pid)
        return handle if handle else None
    except Exception as e:
        logger.debug("open_process_failed", pid=pid, error=str(e))
        return None


def close_handle(handle: int) -> None:
    """Close a process handle."""
    if _WINDOWS and handle:
        try:
            _kernel32.CloseHandle(handle)
        except Exception:
            pass


def virtual_query_ex(handle: int, address: int = 0) -> list[dict]:
    """Enumerate memory regions of a process via VirtualQueryEx.

    Returns list of region dicts with base, size, state, protect, type.
    """
    regions = []
    if not _WINDOWS:
        return regions

    mbi = MEMORY_BASIC_INFORMATION()
    current = address

    while True:
        result = _kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(current),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if result == 0:
            break

        region = {
            "base_address": mbi.BaseAddress,
            "allocation_base": mbi.AllocationBase,
            "allocation_protect": mbi.AllocationProtect,
            "region_size": mbi.RegionSize,
            "state": mbi.State,
            "protect": mbi.Protect,
            "type": mbi.Type,
            "is_rwx": mbi.Protect == PAGE_EXECUTE_READWRITE,
            "is_executable": mbi.Protect in (
                PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            ),
            "is_committed": mbi.State == MEM_COMMIT,
            "is_image": mbi.Type == MEM_IMAGE,
            "is_private": mbi.Type == MEM_PRIVATE,
        }
        regions.append(region)

        # Advance to next region
        next_addr = mbi.BaseAddress + mbi.RegionSize
        if next_addr <= current:
            break
        current = next_addr

    return regions


def read_process_memory(handle: int, address: int, size: int) -> Optional[bytes]:
    """Read process memory. Bounded to MAX_READ_SIZE."""
    if not _WINDOWS:
        return None

    read_size = min(size, MAX_READ_SIZE)
    buf = ctypes.create_string_buffer(read_size)
    bytes_read = ctypes.c_size_t(0)

    try:
        success = _kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(address),
            buf,
            read_size,
            ctypes.byref(bytes_read),
        )
        if success and bytes_read.value > 0:
            return buf.raw[:bytes_read.value]
    except Exception as e:
        logger.debug("read_process_memory_failed", address=hex(address), error=str(e))

    return None


def enum_process_modules(handle: int) -> list[dict]:
    """Enumerate loaded modules (DLLs) of a process."""
    modules = []
    if not _WINDOWS or not _psapi:
        return modules

    ARRAY_SIZE = 1024
    hModules = (ctypes.wintypes.HMODULE * ARRAY_SIZE)()
    cbNeeded = ctypes.wintypes.DWORD()

    try:
        success = _psapi.EnumProcessModulesEx(
            handle,
            ctypes.byref(hModules),
            ctypes.sizeof(hModules),
            ctypes.byref(cbNeeded),
            3,  # LIST_MODULES_ALL
        )
        if not success:
            return modules

        count = min(cbNeeded.value // ctypes.sizeof(ctypes.wintypes.HMODULE), ARRAY_SIZE)
        for i in range(count):
            mod_handle = hModules[i]
            if not mod_handle:
                continue

            # Get module filename
            filename = ctypes.create_unicode_buffer(512)
            _psapi.GetModuleFileNameExW(handle, mod_handle, filename, 512)

            modules.append({
                "handle": mod_handle,
                "path": filename.value,
                "name": filename.value.split("\\")[-1] if filename.value else "",
            })
    except Exception as e:
        logger.debug("enum_modules_failed", error=str(e))

    return modules


def get_mapped_file_name(handle: int, address: int) -> Optional[str]:
    """Get the file name mapped at a memory address."""
    if not _WINDOWS or not _psapi:
        return None

    try:
        filename = ctypes.create_unicode_buffer(512)
        length = _psapi.GetMappedFileNameW(handle, ctypes.c_void_p(address), filename, 512)
        if length > 0:
            return filename.value
    except Exception:
        pass
    return None


def get_protection_string(protect: int) -> str:
    """Convert protection flags to human-readable string."""
    flags = {
        PAGE_NOACCESS: "---",
        PAGE_READONLY: "R--",
        PAGE_READWRITE: "RW-",
        PAGE_EXECUTE: "--X",
        PAGE_EXECUTE_READ: "R-X",
        PAGE_EXECUTE_READWRITE: "RWX",
        PAGE_EXECUTE_WRITECOPY: "RWX(C)",
    }
    return flags.get(protect, f"0x{protect:04X}")
