"""Adapter wrapping r2pipe to implement DisassemblerInterface.

This module provides the concrete implementation of DisassemblerInterface
using r2pipe for actual radare2 interaction.
"""

import r2pipe
from pathlib import Path
from typing import Any

from .disassembler import DisassemblerInterface


class R2PipeAdapter:
    """Adapter wrapping r2pipe to implement DisassemblerInterface.

    This adapter provides a clean interface to r2pipe while implementing
    the DisassemblerInterface protocol. It manages the lifecycle of the
    r2pipe connection and provides consistent error handling.

    Example usage:
        adapter = R2PipeAdapter()
        adapter.open(Path("/path/to/binary"))
        try:
            info = adapter.cmdj("ij")
            functions = adapter.cmdj("aflj")
        finally:
            adapter.close()

    Or using context manager pattern (when implemented):
        with R2PipeAdapter() as adapter:
            adapter.open(Path("/path/to/binary"))
            # ... do analysis
    """

    def __init__(self) -> None:
        """Initialize the adapter with no active connection."""
        self._r2: r2pipe.open | None = None

    def open(self, path: Path, flags: list[str] | None = None) -> None:
        """Open a binary for analysis.

        Args:
            path: Path to the binary file to analyze.
            flags: Optional list of flags to pass to r2pipe.
                   Common flags include ["-2"] for quiet mode.

        Raises:
            FileNotFoundError: If the binary file does not exist.
            RuntimeError: If r2pipe fails to open the file.
        """
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")

        flags = flags or []
        try:
            self._r2 = r2pipe.open(str(path), flags=flags)
        except Exception as e:
            raise RuntimeError(f"Failed to open binary with r2pipe: {e}") from e

    def close(self) -> None:
        """Close the r2pipe connection.

        This releases the radare2 process and any associated resources.
        Safe to call multiple times.
        """
        if self._r2 is not None:
            try:
                self._r2.quit()
            except Exception:
                # Ignore errors during cleanup
                pass
            finally:
                self._r2 = None

    def cmd(self, command: str) -> str:
        """Execute a command and return string result.

        Args:
            command: The radare2 command to execute.

        Returns:
            The string output from the command.

        Raises:
            RuntimeError: If the disassembler is not open.
        """
        if self._r2 is None:
            raise RuntimeError("Disassembler not open")
        return self._r2.cmd(command)

    def cmdj(self, command: str) -> Any:
        """Execute a command and return JSON result.

        Args:
            command: The radare2 command to execute (typically ending with 'j').

        Returns:
            The parsed JSON output from the command.

        Raises:
            RuntimeError: If the disassembler is not open.
        """
        if self._r2 is None:
            raise RuntimeError("Disassembler not open")
        return self._r2.cmdj(command)

    def is_open(self) -> bool:
        """Check if the r2pipe connection is active.

        Returns:
            True if connected to radare2, False otherwise.
        """
        return self._r2 is not None

    def __enter__(self) -> "R2PipeAdapter":
        """Support context manager protocol."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Ensure connection is closed when exiting context."""
        self.close()


# Type assertion to verify R2PipeAdapter implements DisassemblerInterface
def _verify_protocol() -> None:
    """Static verification that R2PipeAdapter implements DisassemblerInterface."""
    adapter: DisassemblerInterface = R2PipeAdapter()  # noqa: F841
