"""
Binary class for handling binary executables with r2pipe.
"""

import logging
import shutil
from pathlib import Path
from typing import Any

import r2pipe

logger = logging.getLogger(__name__)


class Binary:
    """
    Represents a binary executable and provides an interface to radare2 through r2pipe.

    Attributes:
        path: Path to the binary file
        r2: r2pipe connection instance
        info: Binary metadata from radare2
    """

    def __init__(self, path: str | Path, flags: list[str] | None = None, writable: bool = False):
        """
        Initialize a Binary instance.

        Args:
            path: Path to the binary file
            flags: Optional list of radare2 flags (e.g., ['-2', '-A'])
            writable: If True, open binary in write mode

        Raises:
            FileNotFoundError: If binary file doesn't exist
            RuntimeError: If r2pipe connection fails
        """
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Binary not found: {self.path}")

        self.flags = flags or ["-2"]
        if writable:
            self.flags.append("-w")

        self.r2: r2pipe.open_sync.open | None = None
        self.info: dict[str, Any] = {}
        self._analyzed = False
        self._writable = writable

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def open(self) -> "Binary":
        """
        Open the binary with r2pipe.

        Returns:
            Self for method chaining
        """
        try:
            logger.info(f"Opening binary: {self.path}")
            self.r2 = r2pipe.open(str(self.path), flags=self.flags)
            self.info = self.r2.cmdj("ij") or {}
            logger.debug(f"Binary info: {self.info.get('core', {}).get('format', 'unknown')}")
        except Exception as e:
            raise RuntimeError(f"Failed to open binary with r2pipe: {e}")
        return self

    def close(self):
        """Close the r2pipe connection."""
        if self.r2:
            self.r2.quit()
            self.r2 = None
            logger.info(f"Closed binary: {self.path}")

    def analyze(self, level: str = "aaa") -> "Binary":
        """
        Run radare2 analysis on the binary.

        Args:
            level: Analysis level (aa, aaa, aaaa, etc.)
                - aa: basic analysis
                - aaa: analyze all referenced code (recommended)
                - aaaa: experimental analysis (slower)

        Returns:
            Self for method chaining
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        logger.info(f"Running analysis: {level}")
        self.r2.cmd(level)
        self._analyzed = True
        return self

    def get_functions(self) -> list[dict[str, Any]]:
        """
        Get list of functions in the binary.

        Returns:
            List of function dictionaries with metadata
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        functions = self.r2.cmdj("aflj") or []
        logger.debug(f"Found {len(functions)} functions")
        return functions

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        """
        Get disassembly of a function at given address.

        Args:
            address: Function address

        Returns:
            List of instruction dictionaries
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        disasm = self.r2.cmdj(f"pdfj @ {address}") or {}
        return disasm.get("ops", [])

    def get_basic_blocks(self, address: int) -> list[dict[str, Any]]:
        """
        Get basic blocks for a function at given address.

        Args:
            address: Function address

        Returns:
            List of basic block dictionaries
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        blocks = self.r2.cmdj(f"afbj @ {address}") or []
        return blocks

    def assemble(self, instruction: str) -> bytes | None:
        """
        Assemble an instruction using radare2's rasm2.

        Args:
            instruction: Assembly instruction (e.g., "nop", "xor eax, eax")

        Returns:
            Assembled bytes or None if failed
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        try:
            result = self.r2.cmd(f"pa {instruction}")
            hex_str = result.strip()
            if hex_str:
                return bytes.fromhex(hex_str)
            else:
                logger.error(f"Failed to assemble: {instruction}")
                return None
        except Exception as e:
            logger.error(f"Assembly error for '{instruction}': {e}")
            return None

    def write_bytes(self, address: int, data: bytes) -> bool:
        """
        Write bytes to binary at specified address.

        Args:
            address: Target virtual address (will be converted to physical offset)
            data: Bytes to write

        Returns:
            True if successful
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        if not self._writable:
            logger.warning("Binary opened in read-only mode, write may fail")

        try:
            paddr_result = self.r2.cmd(f"s2p 0x{address:x}")

            if not paddr_result or paddr_result.strip() == "":
                physical_offset = address
                logger.debug(f"Using address directly as physical offset: 0x{address:x}")
            else:
                try:
                    physical_offset = int(paddr_result.strip(), 16)
                    logger.debug(f"Converted vaddr 0x{address:x} -> paddr 0x{physical_offset:x}")
                except ValueError:
                    physical_offset = address
                    logger.debug(f"Could not parse paddr, using direct: 0x{address:x}")

            with open(self.path, "r+b") as f:
                f.seek(physical_offset)
                f.write(data)
            logger.debug(f"Wrote {len(data)} bytes at physical offset 0x{physical_offset:x}")
            return True
        except Exception as e:
            logger.error(f"Failed to write bytes at 0x{address:x}: {e}")
            return False

    def write_instruction(self, address: int, instruction: str) -> bool:
        """
        Assemble and write an instruction at specified address.

        Args:
            address: Target address
            instruction: Assembly instruction

        Returns:
            True if successful
        """
        assembled = self.assemble(instruction)
        if assembled:
            return self.write_bytes(address, assembled)
        return False

    def nop_fill(self, address: int, size: int) -> bool:
        """
        Fill a region with NOPs.

        Args:
            address: Start address
            size: Number of bytes to fill

        Returns:
            True if successful
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        nop_bytes = b"\x90" * size
        return self.write_bytes(address, nop_bytes)

    def save(self, output_path: str | Path | None = None):
        """
        Save modified binary to file.

        Args:
            output_path: Output file path. If None, keeps current file.
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        if output_path and output_path != self.path:
            output_path = Path(output_path)

            shutil.copy2(self.path, output_path)
            logger.info(f"Copied binary to: {output_path}")
        else:
            logger.info(f"Changes already written to: {self.path}")

    def get_arch_info(self) -> dict[str, Any]:
        """
        Get architecture information from the binary.

        Returns:
            Dictionary with arch, bits, endian, etc.
        """
        core_info = self.info.get("bin", {})
        return {
            "arch": core_info.get("arch", "unknown"),
            "bits": core_info.get("bits", 0),
            "endian": core_info.get("endian", "unknown"),
            "format": core_info.get("class", "unknown"),
            "machine": core_info.get("machine", "unknown"),
        }

    def is_analyzed(self) -> bool:
        """Check if binary has been analyzed."""
        return self._analyzed
