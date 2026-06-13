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
            lock_file = open(self.lock_path, "w")

            if FCNTL_AVAILABLE:
                lock_type = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
                start_time = time.time()
                while True:
                    try:
                        fcntl.flock(lock_file.fileno(), lock_type)
                        self._lock_file = lock_file
                        self._locked = True
                        logger.debug(f"Acquired lock for {self.binary_path}")
                        return True
                    except OSError:
                        if not blocking:
                            lock_file.close()
                            return False
                        if time.time() - start_time > self.timeout:
                            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
                            lock_file.close()
                            return False
                        time.sleep(0.1)
            elif HAS_MSVCRT:
                start_time = time.time()
                while True:
                    try:
                        _msvcrt = __import__("msvcrt")
                        _msvcrt.locking(
                            lock_file.fileno(),
                            _msvcrt.LK_NBLCK if not blocking else _msvcrt.LK_LOCK,
                            1,
                        )
                        self._lock_file = lock_file
                        self._locked = True
                        logger.debug(f"Acquired lock for {self.binary_path}")
                        return True
                    except OSError:
                        if not blocking:
                            lock_file.close()
                            return False
                        if time.time() - start_time > self.timeout:
                            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
                            lock_file.close()
                            return False
                        time.sleep(0.1)
            else:
                logger.warning("No native locking available, using directory-based fallback")
                lock_dir = self.lock_path.with_suffix(".lockdir")
                self._lock_dir_path = lock_dir
                start_time = time.time()
                while True:
                    try:
                        lock_dir.mkdir(parents=True, exist_ok=False)
                        self._lock_file = lock_file
                        self._locked = True
                        logger.debug(f"Acquired lock for {self.binary_path}")
                        return True
                    except FileExistsError:
                        if not blocking:
                            lock_file.close()
                            return False
                        if time.time() - start_time > self.timeout:
                            logger.warning(f"Lock acquisition timeout for {self.binary_path}")
                            lock_file.close()
                            return False
                        time.sleep(0.1)
                    except Exception as exc:
                        logger.error(f"Failed to acquire lock for {self.binary_path}: {exc}")
                        lock_file.close()
                        return False

        except Exception as exc:
            logger.error(f"Failed to acquire lock for {self.binary_path}: {exc}")
            if lock_file:
                lock_file.close()
            return False

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
