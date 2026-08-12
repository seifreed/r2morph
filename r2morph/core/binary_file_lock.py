"""File-based locking for coordinated binary writes."""

from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

if sys.platform == "win32":
    try:
        import importlib.util as _ilu

        HAS_MSVCRT = _ilu.find_spec("msvcrt") is not None
    except Exception:
        HAS_MSVCRT = False
    FCNTL_AVAILABLE = False
else:
    try:
        import fcntl

        FCNTL_AVAILABLE = True
    except ImportError:
        FCNTL_AVAILABLE = False
    HAS_MSVCRT = False


class BinaryFileLock:
    """
    File-based lock for coordinating binary writes across processes.

    Provides exclusive locking for binary modifications to prevent
    race conditions when multiple processes attempt to write to
    the same binary file.
    """

    def __init__(self, binary_path: Path, timeout: float = 30.0) -> None:
        self.binary_path = Path(binary_path)
        self.lock_path = self.binary_path.with_suffix(self.binary_path.suffix + ".lock")
        self.timeout = timeout
        self._lock_file: Any = None
        self._lock_dir_path: Path | None = None
        self._locked = False
        self._mutex = threading.RLock()

    def acquire(self, blocking: bool = True) -> bool:
        """Acquire the file lock (thread-safe; serialized per instance)."""
        with self._mutex:
            return self._acquire_locked(blocking)

    def _acquire_locked(self, blocking: bool = True) -> bool:
        if self._locked:
            return True

        lock_file: Any = None
        try:
            lock_file = self.lock_path.open("w")
            if FCNTL_AVAILABLE:
                return self._acquire_fcntl(lock_file, blocking)
            if HAS_MSVCRT:
                return self._acquire_msvcrt(lock_file, blocking)
            return self._acquire_directory(lock_file, blocking)
        except Exception as exc:
            logger.error(f"Failed to acquire lock for {self.binary_path}: {exc}")
            if lock_file:
                lock_file.close()
            return False

    def _acquire_fcntl(self, lock_file: Any, blocking: bool) -> bool:
        lock_type = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        started_at = time.time()
        while True:
            try:
                fcntl.flock(lock_file.fileno(), lock_type)
                return self._mark_acquired(lock_file)
            except OSError:
                if not self._wait_for_retry(lock_file, blocking, started_at):
                    return False

    def _acquire_msvcrt(self, lock_file: Any, blocking: bool) -> bool:
        started_at = time.time()
        while True:
            try:
                msvcrt_module = __import__("msvcrt")
                mode = msvcrt_module.LK_LOCK if blocking else msvcrt_module.LK_NBLCK
                msvcrt_module.locking(lock_file.fileno(), mode, 1)
                return self._mark_acquired(lock_file)
            except OSError:
                if not self._wait_for_retry(lock_file, blocking, started_at):
                    return False

    def _acquire_directory(self, lock_file: Any, blocking: bool) -> bool:
        logger.warning("No native locking available, using directory-based fallback")
        lock_dir = self.lock_path.with_suffix(".lockdir")
        self._lock_dir_path = lock_dir
        started_at = time.time()
        while True:
            try:
                lock_dir.mkdir(parents=True, exist_ok=False)
                return self._mark_acquired(lock_file)
            except FileExistsError:
                if not self._wait_for_retry(lock_file, blocking, started_at):
                    return False
            except Exception as exc:
                logger.error(f"Failed to acquire lock for {self.binary_path}: {exc}")
                lock_file.close()
                return False

    def _mark_acquired(self, lock_file: Any) -> bool:
        self._lock_file = lock_file
        self._locked = True
        logger.debug(f"Acquired lock for {self.binary_path}")
        return True

    def _wait_for_retry(self, lock_file: Any, blocking: bool, started_at: float) -> bool:
        if not blocking:
            lock_file.close()
            return False
        if time.time() - started_at > self.timeout:
            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
            lock_file.close()
            return False
        time.sleep(0.1)
        return True

    def release(self) -> None:
        """Release the file lock and always close the lock file."""
        with self._mutex:
            self._release_locked()

    def _release_locked(self) -> None:
        try:
            if self._locked:
                if FCNTL_AVAILABLE and self._lock_file:
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                elif HAS_MSVCRT and self._lock_file:
                    _msvcrt = __import__("msvcrt")
                    _msvcrt.locking(self._lock_file.fileno(), _msvcrt.LK_UNLCK, 1)
                elif self._lock_dir_path and self._lock_dir_path.exists():
                    self._lock_dir_path.rmdir()
                self._locked = False
                logger.debug(f"Released lock for {self.binary_path}")
        except OSError as exc:
            logger.error(f"Failed to release lock for {self.binary_path}: {exc}")
        finally:
            if self._lock_file is not None:
                try:
                    self._lock_file.close()
                except OSError as exc:
                    logger.debug(f"Ignoring error closing lock file: {exc}")
                self._lock_file = None
            self._lock_dir_path = None

    def __del__(self) -> None:
        """Finalizer safety net: never leak the lock fd."""
        lock_file = getattr(self, "_lock_file", None)
        if lock_file is None:
            return
        try:
            lock_file.close()
        except OSError:
            return

    def __enter__(self) -> BinaryFileLock:
        acquired = self.acquire()
        if not acquired:
            raise TimeoutError(f"Failed to acquire lock for {self.binary_path} within {self.timeout}s")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()

    def is_locked(self) -> bool:
        return self._locked


__all__ = ["BinaryFileLock"]
