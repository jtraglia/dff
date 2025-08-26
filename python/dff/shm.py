"""System V shared memory wrapper for Python."""

import ctypes
import ctypes.util
import sys
from typing import Optional

IPC_CREAT = 0o1000
IPC_EXCL = 0o2000
IPC_RMID = 0

if sys.platform == "darwin":
    libc_name = ctypes.util.find_library("c")
elif sys.platform.startswith("linux"):
    libc_name = ctypes.util.find_library("c")
else:
    raise OSError(f"Unsupported platform: {sys.platform}")

if not libc_name:
    raise OSError("Could not find libc")

libc = ctypes.CDLL(libc_name)


class ShmidDs(ctypes.Structure):
    """Shared memory segment descriptor structure."""
    if sys.platform == "darwin":
        _fields_ = [
            ("shm_perm", ctypes.c_void_p),
            ("shm_segsz", ctypes.c_size_t),
            ("shm_lpid", ctypes.c_int),
            ("shm_cpid", ctypes.c_int),
            ("shm_nattch", ctypes.c_short),
            ("shm_atime", ctypes.c_long),
            ("shm_dtime", ctypes.c_long),
            ("shm_ctime", ctypes.c_long),
            ("shm_internal", ctypes.c_void_p),
        ]
    else:
        _fields_ = [
            ("shm_perm", ctypes.c_void_p),
            ("shm_segsz", ctypes.c_size_t),
            ("shm_atime", ctypes.c_long),
            ("shm_dtime", ctypes.c_long),
            ("shm_ctime", ctypes.c_long),
            ("shm_cpid", ctypes.c_int),
            ("shm_lpid", ctypes.c_int),
            ("shm_nattch", ctypes.c_short),
        ]


libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
libc.shmget.restype = ctypes.c_int

libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
libc.shmat.restype = ctypes.c_void_p

libc.shmdt.argtypes = [ctypes.c_void_p]
libc.shmdt.restype = ctypes.c_int

libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ShmidDs)]
libc.shmctl.restype = ctypes.c_int


class SharedMemory:
    """Wrapper for System V shared memory operations."""

    def __init__(self, shmid: int, size: int = 0):
        """Initialize shared memory wrapper.

        Args:
            shmid: Shared memory ID
            size: Size of the shared memory segment (for reference)
        """
        self.shmid = shmid
        self.size = size
        self.addr: Optional[int] = None
        self._attached = False

    @classmethod
    def create(cls, key: int, size: int, perm: int = 0o666) -> "SharedMemory":
        """Create a new shared memory segment.

        Args:
            key: IPC key for the shared memory segment
            size: Size of the segment in bytes
            perm: Permissions for the segment

        Returns:
            SharedMemory object

        Raises:
            OSError: If creation fails
        """
        flags = perm | IPC_CREAT | IPC_EXCL
        shmid = libc.shmget(key, size, flags)
        if shmid == -1:
            raise OSError(f"Failed to create shared memory with key {key}")
        return cls(shmid, size)

    @classmethod
    def get(cls, key: int, size: int = 0) -> "SharedMemory":
        """Get existing shared memory segment.

        Args:
            key: IPC key for the shared memory segment
            size: Expected size (0 to get existing)

        Returns:
            SharedMemory object

        Raises:
            OSError: If segment doesn't exist
        """
        shmid = libc.shmget(key, size, 0)
        if shmid == -1:
            raise OSError(f"Failed to get shared memory with key {key}")
        return cls(shmid, size)

    def attach(self, addr: int = 0, flags: int = 0) -> ctypes.Array:
        """Attach to the shared memory segment.

        Args:
            addr: Preferred attach address (0 for system choice)
            flags: Attach flags

        Returns:
            ctypes array of the attached segment

        Raises:
            OSError: If attach fails
        """
        if self._attached:
            raise RuntimeError("Already attached to shared memory")

        result = libc.shmat(self.shmid, addr, flags)
        if result == -1:
            raise OSError(f"Failed to attach to shared memory ID {self.shmid}")

        self.addr = result
        self._attached = True

        if self.size > 0:
            return (ctypes.c_ubyte * self.size).from_address(self.addr)
        else:
            return (ctypes.c_ubyte * (100 * 1024 * 1024)).from_address(self.addr)

    def detach(self) -> None:
        """Detach from the shared memory segment."""
        if not self._attached or self.addr is None:
            return

        result = libc.shmdt(self.addr)
        if result == -1:
            raise OSError("Failed to detach from shared memory")

        self.addr = None
        self._attached = False

    def remove(self) -> None:
        """Remove the shared memory segment."""
        result = libc.shmctl(self.shmid, IPC_RMID, None)
        if result == -1:
            raise OSError(f"Failed to remove shared memory ID {self.shmid}")

    def __del__(self) -> None:
        """Cleanup - detach if still attached."""
        if self._attached:
            try:
                self.detach()
            except:
                pass


def attach_by_id(shmid: int, size: int = 0) -> ctypes.Array:
    """Convenience function to attach to shared memory by ID.

    Args:
        shmid: Shared memory ID
        size: Expected size (0 for default max)

    Returns:
        ctypes array of the attached segment
    """
    shm = SharedMemory(shmid, size)
    return shm.attach()