"""
Binary class for handling binary executables with r2pipe.

Refactored following Single Responsibility Principle:
- BinaryReader: handles all read operations
- BinaryWriter: handles all write operations
- AssemblyService: handles assembly with fallbacks
- Binary: coordinates services and manages r2pipe connection
"""

import logging
import shutil
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

import r2pipe

from r2morph.core.constants import BATCH_MUTATION_CHECKPOINT

if TYPE_CHECKING:
    from r2morph.core.assembly import AssemblyService
    from r2morph.core.memory_manager import MemoryManager
    from r2morph.core.reader import BinaryReader
    from r2morph.core.writer import BinaryWriter

logger = logging.getLogger(__name__)


class Binary:
    """
    Represents a binary executable and provides an interface to radare2 through r2pipe.

    This class coordinates services following Single Responsibility Principle:
    - AssemblyService: instruction encoding with intelligent fallbacks
    - MemoryManager: batch processing and memory management
    - BinaryReader: all read operations (functions, disasm, sections, etc.)
    - BinaryWriter: all write operations (bytes, instructions, NOPs)

    Attributes:
        path: Path to the binary file
        r2: r2pipe connection instance
        info: Binary metadata from radare2
    """

    def __init__(
        self,
        path: str | Path,
        flags: list[str] | None = None,
        writable: bool = False,
        low_memory: bool = False,
        disassembler: Any = None,
    ):
        """Initialize Binary.

        Args:
            path: Path to the binary file
            flags: r2pipe flags (default: ["-2"])
            writable: Open in write mode
            low_memory: Enable low memory mode
            disassembler: Optional DisassemblerInterface instance for DIP.
                          If provided, used instead of r2pipe.open() directly.
        """
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Binary not found: {self.path}")

        self.flags = flags or ["-2"]
        if writable:
            self.flags.append("-w")

        self._injected_disassembler = disassembler
        self.r2: Any = None
        self.info: dict[str, Any] = {}
        self._analyzed = False
        self._writable = writable
        self._low_memory = low_memory
        self._functions_cache: list[dict[str, Any]] | None = None
        self._mutation_counter = 0

        # Thread safety for lazy-loaded services
        self._lock = threading.Lock()

        # Lazy-loaded services
        self._assembly_service: "AssemblyService | None" = None
        self._memory_manager: "MemoryManager | None" = None
        self._reader: "BinaryReader | None" = None
        self._writer: "BinaryWriter | None" = None

    @property
    def assembly(self) -> "AssemblyService":
        """Get the AssemblyService instance (lazy-loaded)."""
        if self._assembly_service is None:
            with self._lock:
                if self._assembly_service is None:
                    from r2morph.core.assembly import get_assembly_service

                    self._assembly_service = get_assembly_service()
        return self._assembly_service

    @property
    def memory_manager(self) -> "MemoryManager":
        """Get the MemoryManager instance (lazy-loaded)."""
        if self._memory_manager is None:
            with self._lock:
                if self._memory_manager is None:
                    from r2morph.core.memory_manager import get_memory_manager

                    self._memory_manager = get_memory_manager()
        return self._memory_manager

    @property
    def reader(self) -> "BinaryReader":
        """Get the BinaryReader instance (lazy-loaded)."""
        if self._reader is None:
            with self._lock:
                if self._reader is None:
                    from r2morph.core.reader import BinaryReader

                    self._reader = BinaryReader(self.r2)
        return self._reader

    @property
    def writer(self) -> "BinaryWriter":
        """Get the BinaryWriter instance (lazy-loaded)."""
        if self._writer is None:
            with self._lock:
                if self._writer is None:
                    from r2morph.core.writer import BinaryWriter

                    self._writer = BinaryWriter(self.r2, self.path, self._writable)
        return self._writer

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self) -> "Binary":
        try:
            logger.info(f"Opening binary: {self.path}")
            if self._injected_disassembler is not None:
                # Use injected disassembler (DIP: enables testing without r2pipe)
                self._injected_disassembler.open(self.path, self.flags)
                self.r2 = self._injected_disassembler
            else:
                self.r2 = r2pipe.open(str(self.path), flags=self.flags)
            self.info = self.r2.cmdj("ij") or {}

            if self._low_memory:
                logger.debug("Configuring r2 for low memory mode")
                self.r2.cmd("e bin.cache=false")
                self.r2.cmd("e io.cache=false")
                self.r2.cmd("e bin.strings=false")

            logger.debug(f"Binary info: {self.info.get('core', {}).get('format', 'unknown')}")

            # Update services with new r2 connection
            if self._reader:
                self._reader.set_r2(self.r2)
            if self._writer:
                self._writer.set_r2(self.r2)

        except Exception as e:
            raise RuntimeError(f"Failed to open binary with r2pipe: {e}")
        return self

    def close(self):
        if self.r2:
            self.r2.quit()
            self.r2 = None
            logger.info(f"Closed binary: {self.path}")

    def reload(self):
        logger.debug("Reloading r2 connection to free memory")
        was_analyzed = self._analyzed
        with self._lock:
            self.close()
            self._reader = None
            self._writer = None
            self.open()
        # Re-run analysis if it was previously done, so caches are fresh
        if was_analyzed:
            self.analyze()
        else:
            self._analyzed = False
            self._functions_cache = None

    def analyze(self, level: str = "aaa") -> "Binary":
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        logger.info(f"Running analysis: {level}")

        if level in ["aaa", "aaaa"]:
            logger.warning("Analysis may take 2-5 minutes for large binaries. Please wait...")

        self.r2.cmd(level)
        self._analyzed = True

        try:
            self._functions_cache = self.r2.cmdj("aflj") or []
            logger.info(f"Analysis complete - cached {len(self._functions_cache)} functions")
        except Exception as e:
            logger.warning(f"Failed to cache functions: {e}")
            self._functions_cache = None

        return self

    # Delegated read methods to BinaryReader

    def get_functions(self) -> list[dict[str, Any]]:
        """Get list of functions in the binary."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        return self.reader.get_functions(cached=self._functions_cache)

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        """Get disassembly of a function at given address."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        return self.reader.get_function_disasm(address)

    def get_basic_blocks(self, address: int) -> list[dict[str, Any]]:
        """Get basic blocks for a function at given address."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        return self.reader.get_basic_blocks(address)

    def get_sections(self) -> list[dict[str, Any]]:
        """Get sections from the binary."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        return self.reader.get_sections()

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the binary at a virtual address."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        return self.reader.read_bytes(address, size)

    def get_arch_info(self) -> dict[str, Any]:
        """Get architecture information from the binary."""
        return self.reader.get_arch_info(self.info)

    def get_arch_family(self) -> tuple[str, int]:
        """Return (arch_family, bits) tuple."""
        return self.reader.get_arch_family(self.info)

    # Delegated write methods to BinaryWriter

    def write_bytes(self, address: int, data: bytes) -> bool:
        """Write bytes to binary at specified address."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        if not self._writable:
            logger.warning("Binary opened in read-only mode, write may fail")

        success = self.writer.write_bytes(
            address,
            data,
            resolve_physical_offset_func=self.reader.resolve_physical_offset,
        )

        # Track mutation for batch processing
        if success and self._low_memory:
            self._mutation_counter += 1
            if self._mutation_counter % BATCH_MUTATION_CHECKPOINT == 0:
                logger.info(
                    f"Batch checkpoint: {self._mutation_counter} mutations applied. Reloading r2 to free memory..."
                )
                self.reload()

        return success

    def write_instruction(self, address: int, instruction: str) -> bool:
        """Assemble and write an instruction at specified address."""
        assembled = self.assemble(instruction)
        if assembled:
            return self.write_bytes(address, assembled)
        return False

    def nop_fill(self, address: int, size: int) -> bool:
        """Fill a region with NOPs."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        arch_info = self.get_arch_info()
        arch = arch_info.get("arch", "x86").lower()
        bits = arch_info.get("bits", 64)

        if arch in ("arm", "arm64", "aarch64"):
            if bits == 64:
                nop_bytes = b"\x1f\x20\x03\xd5" * (size // 4)
                # ARM64 instructions are always 4 bytes; pad remainder with x86 NOPs
                # which are safe as padding but won't execute (only reached by alignment)
                remainder = size % 4
                if remainder:
                    nop_bytes += b"\x00" * remainder
            else:
                nop_bytes = b"\x00\x00\xa0\xe1" * (size // 4)
                remainder = size % 4
                if remainder:
                    nop_bytes += b"\x00" * remainder
        else:
            nop_bytes = b"\x90" * size

        return self.write_bytes(address, nop_bytes)

    def save(self, output_path: str | Path | None = None):
        """Save modified binary to file."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        self.writer.save(output_path)

    # Assembly (delegated to AssemblyService)

    def assemble(self, instruction: str, function_addr: int | None = None) -> bytes | None:
        """Assemble an instruction using radare2's rasm2 with intelligent fallbacks."""
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")
        return self.assembly.assemble(self, instruction, function_addr)

    # Mutation tracking (delegated to MemoryManager)

    def track_mutation(self, batch_size: int = BATCH_MUTATION_CHECKPOINT):
        """Track mutation count and reload r2 periodically for batch processing."""
        if not self._low_memory:
            return

        self._mutation_counter += 1
        if self._mutation_counter % batch_size == 0:
            logger.info(f"Batch checkpoint: {self._mutation_counter} mutations applied. Reloading r2 to free memory...")
            self.reload()

    # Utility methods

    def is_analyzed(self) -> bool:
        """Check if binary has been analyzed."""
        return self._analyzed

    # Internal methods for backward compatibility

    def _resolve_symbolic_vars(self, instruction: str, function_addr: int | None = None) -> str:
        """Resolve symbolic variable names in instruction to actual addresses."""
        return self.reader.resolve_symbolic_vars(instruction, function_addr)

    def _normalize_assembly_syntax(self, instruction: str) -> str:
        """Normalize assembly syntax to work around radare2 assembler quirks."""
        return instruction

    def _assemble_movzx_movsx_fallback(self, instruction: str) -> bytes | None:
        """Manually encode movzx/movsx instructions using direct opcodes."""
        return self.assembly._assemble_movzx_movsx_fallback(instruction)

    def _assemble_segment_prefix_fallback(self, instruction: str) -> bytes | None:
        """Manually encode instructions with segment prefixes (fs:, gs:, etc.)."""
        return self.assembly._assemble_segment_prefix_fallback(self, instruction)
