import ctypes
import os
import platform
import sys
import tempfile
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Tuple, Union, Dict, Any, List
import threading
import socket
from contextlib import closing

import rpyc



class ForwardIO(rpyc.Service):
    """
    A remote procedure call (RPC) service for forwarding I/O streams.

    This class extends rpyc.Service to provide remote methods for writing to
    stdout and stderr. It allows a client connected via rpyc to send output
    that will be displayed on the server's standard output and error streams.

    Methods:
        exposed_stdout_write: Write data to standard output.
        exposed_stderr_write: Write data to standard error.
    """
    def exposed_stdout_write(self, data: Any):
        print(data, end="", file=sys.stdout)

    def exposed_stderr_write(self, data: Any):
        print(data, end="", file=sys.stderr)


class _PortAllocFileLock:
    """Cross-process lock for port allocation using file locking.

    Uses fcntl.flock (Unix) or msvcrt.locking (Windows) to serialize port
    allocation across both threads and processes on the same machine.
    Each __enter__ opens a fresh fd (stored per-thread via thread-local storage),
    so concurrent threads within the same process are also properly serialized.
    """
    _LOCK_PATH = os.path.join(tempfile.gettempdir(), ".headless_ida_port.lock")
    _local = threading.local()

    def __enter__(self):
        f = open(self._LOCK_PATH, "w")
        self._local.lock_file = f
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *args):
        f = self._local.lock_file
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_UN)
        f.close()


PortAllocLock = _PortAllocFileLock()

def find_free_port() -> int:
    """
    Find a free port on localhost.
    **Needs to be locked externally to ensure thread-safety.**
    
    Returns:
        int: A free port number.
    """
    # with _port_allocation_lock:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('localhost', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]
        
        
def escape_path(path: Union[str, Path]) -> str:
    path = str(path)
    if os.name == "nt":
        _GetShortPathName = ctypes.windll.kernel32.GetShortPathNameW
        _GetShortPathName.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        _GetShortPathName.restype = ctypes.c_uint

        buffer = ctypes.create_unicode_buffer(len(path) + 1)
        if _GetShortPathName(path, buffer, len(buffer)):
            return buffer.value
        else:
            raise Exception("Failed to get short path")
    else:
        return f'\\"{path}\\"'


class IDABackendType(Enum):
    """Enumeration of IDA backend types."""
    IDA = auto()
    IDAT = auto()
    IDALIB = auto()


def resolve_ida_path(path: Union[str, Path], bits:int=64) -> Tuple[IDABackendType, str]:
    """
    Resolve the IDA installation path and determine the backend type.
    
    This function identifies the appropriate IDA binary (idalib, ida, or idat) 
    from a given file or directory path. It supports Windows, Linux, and macOS 
    platforms and handles both 32-bit and 64-bit variants.
    
    Args:
        path (Union[str, Path]): A file path to an IDA binary or a directory 
                                  containing IDA binaries.
        bits (int, optional): The architecture bit version (32 or 64). Defaults to 64.
                             Used when searching in a directory to prioritize 
                             the appropriate binary variant.
    
    Returns:
        Tuple[IDABackendType, str]: A tuple containing:
            - IDABackendType: The type of IDA backend found (IDALIB, IDA, or IDAT)
            - str: The absolute path to the resolved IDA binary
    
    Raises:
        ValueError: If the platform is unsupported or the IDA path is invalid 
                   (file not found or no valid IDA binary found in directory)
    
    Raises:
        ValueError: If the specified path does not exist or does not contain 
                   any recognized IDA binaries.
    
    Examples:
        >>> backend_type, ida_path = resolve_ida_path("/opt/ida")
        >>> backend_type
        <IDABackendType.IDAT: ...>
        >>> ida_path
        '/opt/ida/idat64'
    """
    path = str(path)
    IDA_BINARIES = {
        "Windows": {
            "idalib": ["idalib64.dll", "idalib.dll"],
            "ida": ["ida64.exe", "ida.exe"],
            "idat": ["idat64.exe", "idat.exe"],
        },
        "Linux": {
            "idalib": ["libidalib64.so", "libidalib.so"],
            "ida": ["ida64", "ida"],
            "idat": ["idat64", "idat"],
        },
        "Darwin": {
            "idalib": ["libidalib64.dylib", "libidalib.dylib"],
            "ida": ["ida64", "ida"],
            "idat": ["idat64", "idat"],
        },
    }

    system = platform.system()
    if system not in IDA_BINARIES:
        raise ValueError(f"Unsupported platform: {system}")

    binaries = IDA_BINARIES[system]

    if os.path.isfile(path):
        filename = os.path.basename(path)
        if filename in binaries["idalib"]:
            return IDABackendType.IDALIB, path
        if filename in binaries["ida"]:
            return IDABackendType.IDA, path
        if filename in binaries["idat"]:
            return IDABackendType.IDAT, path

    elif os.path.isdir(path):
        # Check for idalib variants
        for idalib_binary in binaries["idalib"]:
            idalib_path = os.path.join(path, idalib_binary)
            if os.path.exists(idalib_path):
                return IDABackendType.IDALIB, idalib_path

        idat_binary = binaries["idat"][0 if bits == 64 else 1]
        idat_path = os.path.join(path, idat_binary)
        if os.path.exists(idat_path):
            return IDABackendType.IDAT, idat_path

        ida_binary = binaries["ida"][0 if bits == 64 else 1]
        ida_path = os.path.join(path, ida_binary)
        if os.path.exists(ida_path):
            return IDABackendType.IDA, ida_path

    raise ValueError(f"Invalid IDA path: {path}")
