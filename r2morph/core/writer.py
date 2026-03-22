"""
Binary writer service for writing data to binary files.

Extracted from Binary class following Single Responsibility Principle.
Handles all write operations: bytes, instructions, NOP fills.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from r2morph.adapters.disassembler import DisassemblerInterface

logger = logging.getLogger(__name__)


class BinaryWriter:
    """
    Service for writing data to binary executables through r2pipe.

    Handles all write operations:
    - Raw bytes writing with address translation
    - Instruction writing with assembly
    - NOP fills
    - Batch mutation tracking
    """

    def __init__(self, r2: "DisassemblerInterface | None", path: Path, writable: bool = False):
        """
        Initialize BinaryWriter.

        Args:
            r2: Disassembler connection (r2pipe or DisassemblerInterface)
            path: Path to the binary file
            writable: Whether the binary was opened in write mode
        """
        self._r2: "DisassemblerInterface | None" = r2
        self._path = path
        self._writable = writable
        self._mutation_counter = 0

    def set_r2(self, r2: "DisassemblerInterface | None") -> None:
        """Update the disassembler connection after reload."""
        self._r2 = r2

    def set_writable(self, writable: bool) -> None:
        """Update writable mode."""
        self._writable = writable

    def track_mutation(self) -> int:
        """
        Track mutation count for batch processing.

        Returns:
            Current mutation counter after increment
        """
        self._mutation_counter += 1
        return self._mutation_counter

    def reset_mutation_counter(self) -> None:
        """Reset the mutation counter."""
        self._mutation_counter = 0

    def get_mutation_counter(self) -> int:
        """Get the current mutation counter."""
        return self._mutation_counter

    def _validate_address_bounds(
        self,
        address: int,
        data_len: int,
        sections: list[dict] | None = None,
    ) -> bool:
        """
        Validate that write is within valid address space.

        Args:
            address: Target virtual address
            data_len: Length of data to write
            sections: Optional list of sections from binary

        Returns:
            True if address is valid, False if address is outside known sections
        """
        if address < 0:
            logger.warning(f"Negative address: 0x{address:x}")
            return False

        if sections:
            valid = False
            for section in sections:
                vaddr = section.get("vaddr", section.get("virtual_address", 0))
                if vaddr is None:
                    vaddr = 0
                vsize = section.get("vsize", section.get("virtual_size", section.get("size", 0)))
                if vsize is None:
                    vsize = 0
                section_end = vaddr + vsize
                if section_end < vaddr:
                    continue
                write_end = address + data_len
                if write_end < address:
                    continue
                if vaddr <= address < section_end:
                    if write_end <= section_end:
                        valid = True
                        break
            if not valid:
                end_addr = address + data_len
                if end_addr < address:
                    return False
                for section in sections:
                    vaddr = section.get("vaddr", section.get("virtual_address", 0))
                    if vaddr is None:
                        vaddr = 0
                    vsize = section.get("vsize", section.get("virtual_size", section.get("size", 0)))
                    if vsize is None:
                        vsize = 0
                    section_end = vaddr + vsize
                    if section_end < vaddr:
                        continue
                    if vaddr <= address < section_end or vaddr <= end_addr <= section_end:
                        valid = True
                        break
            if not valid:
                logger.warning(f"Address 0x{address:x} outside known sections, write may fail")
                return False
        return True

    def write_bytes(
        self,
        address: int,
        data: bytes,
        resolve_physical_offset_func=None,
        sections: list[dict] | None = None,
    ) -> bool:
        """
        Write bytes to binary at specified address.

        Args:
            address: Target virtual address
            data: Bytes to write
            resolve_physical_offset_func: Optional function to resolve physical offset
            sections: Optional list of sections for bounds checking

        Returns:
            True if successful
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        if not data:
            logger.debug(f"write_bytes called with empty data at 0x{address:x}, no-op")
            return False

        if not self._writable:
            logger.warning("Binary opened in read-only mode, write may fail")

        if not self._validate_address_bounds(address, len(data), sections):
            logger.warning(f"Address 0x{address:x} is outside valid bounds, write rejected")
            return False

        hex_data = data.hex()
        write_success = False

        try:
            self._r2.cmd(f"wx {hex_data} @ 0x{address:x}")
            verify = self._r2.cmd(f"p8 {len(data)} @ 0x{address:x}")
            if verify:
                verify = verify.strip().lower()
                if verify == hex_data.lower():
                    write_success = True
        except Exception as e:
            logger.debug(f"Failed to write via r2 wx at 0x{address:x}: {e}")

        if not write_success:
            physical_offset = None
            if resolve_physical_offset_func:
                physical_offset = resolve_physical_offset_func(address)

            if physical_offset is None:
                logger.error(
                    f"Cannot write at 0x{address:x}: r2 write failed and "
                    f"physical offset could not be resolved (refusing to use "
                    f"virtual address as file offset)"
                )
                return False

            try:
                with open(self._path, "r+b") as f:
                    f.seek(physical_offset)
                    f.write(data)
                    f.flush()
                    f.seek(physical_offset)
                    written = f.read(len(data))
                    if written == data:
                        write_success = True
                        logger.debug(f"Wrote {len(data)} bytes at physical offset 0x{physical_offset:x}")
                    else:
                        logger.error(f"Write verification failed at 0x{address:x}")
            except Exception as e:
                logger.error(f"Failed to write bytes at 0x{address:x}: {e}")

        if write_success:
            self._mutation_counter += 1

        return write_success

    def write_instruction(
        self,
        address: int,
        instruction: bytes,
    ) -> bool:
        """
        Write assembled instruction at specified address.

        Args:
            address: Target address
            instruction: Pre-assembled instruction bytes

        Returns:
            True if successful
        """
        return self.write_bytes(address, instruction)

    def nop_fill(self, address: int, size: int) -> bool:
        """
        Fill a region with NOPs.

        Args:
            address: Start address
            size: Number of bytes to fill

        Returns:
            True if successful
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        # Default to x86 NOP - Binary.nop_fill handles architecture-specific NOPs
        nop_bytes = b"\x90" * size
        return self.write_bytes(address, nop_bytes)

    def save(self, output_path: Path | str | None = None) -> None:
        """
        Save modified binary to file.

        Args:
            output_path: Output file path. If None, changes are already written.

        Raises:
            RuntimeError: If binary path is not set
        """
        import shutil

        if self._path is None:
            raise RuntimeError("Binary path not set")

        if output_path and Path(output_path) != self._path:
            output_path = Path(output_path)
            shutil.copy2(self._path, output_path)
            logger.info(f"Copied binary to: {output_path}")
        else:
            logger.info(f"Changes already written to: {self._path}")

    def should_reload_for_batch(self, batch_size: int = 1000, low_memory: bool = False) -> bool:
        """
        Check if the r2 connection should be reloaded for batch processing.

        Args:
            batch_size: Number of mutations before reload
            low_memory: Whether low memory mode is enabled

        Returns:
            True if reload is needed
        """
        if not low_memory:
            return False
        return self._mutation_counter > 0 and self._mutation_counter % batch_size == 0
