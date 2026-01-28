"""Protocol interface for disassembler operations.

This module defines the abstract interface that all disassembler adapters
must implement. Using Protocol allows for structural subtyping, enabling
dependency injection and easier testing.
"""

from typing import Protocol, Any, runtime_checkable
from pathlib import Path


@runtime_checkable
class DisassemblerInterface(Protocol):
    """Interface for disassembler operations.

    This protocol defines the contract that any disassembler implementation
    must satisfy. It enables dependency inversion by allowing code to depend
    on this abstraction rather than concrete implementations like r2pipe.

    Example usage:
        def analyze_binary(disasm: DisassemblerInterface, path: Path) -> dict:
            disasm.open(path)
            try:
                info = disasm.cmdj("ij")
                return info
            finally:
                disasm.close()
    """

    def open(self, path: Path, flags: list[str] | None = None) -> None:
        """Open a binary for analysis.

        Args:
            path: Path to the binary file to analyze.
            flags: Optional list of flags to pass to the disassembler.
                   Common flags include ["-2"] for analysis.

        Raises:
            FileNotFoundError: If the binary file does not exist.
            RuntimeError: If the disassembler fails to open the file.
        """
        ...

    def close(self) -> None:
        """Close the connection to the disassembler.

        This should release any resources held by the disassembler.
        Calling close() on an already closed connection should be safe.
        """
        ...

    def cmd(self, command: str) -> str:
        """Execute a command and return string result.

        Args:
            command: The disassembler command to execute.

        Returns:
            The string output from the command.

        Raises:
            RuntimeError: If the disassembler is not open.
        """
        ...

    def cmdj(self, command: str) -> Any:
        """Execute a command and return JSON result.

        This is used for commands that return structured data (typically
        commands ending with 'j' in radare2).

        Args:
            command: The disassembler command to execute.

        Returns:
            The parsed JSON output from the command, typically a dict or list.

        Raises:
            RuntimeError: If the disassembler is not open.
        """
        ...

    def is_open(self) -> bool:
        """Check if connection is open.

        Returns:
            True if the disassembler has an active connection, False otherwise.
        """
        ...
