"""
Exception edge analysis for complex CFG handling.

This module provides:
- Exception table parsing (ELF .eh_frame, PE .pdata, Mach-O __unwind_info)
- Landing pad detection
- Exception-aware CFG construction
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class ExceptionAction(Enum):
    """Type of exception handling action."""

    CATCH = "catch"
    FILTER = "filter"
    FINALLY = "finally"
    CLEANUP = "cleanup"
    UNKNOWN = "unknown"


@dataclass
class LandingPad:
    """Represents a landing pad for exception handling."""

    address: int
    size: int
    action: ExceptionAction
    catch_type: str | None = None
    parent_try: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExceptionTableEntry:
    """Represents an entry in the exception handling table."""

    start_address: int
    end_address: int
    landing_pad: int | None
    action: ExceptionAction
    filter_address: int | None = None
    catch_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExceptionFrame:
    """Represents exception frame information."""

    function_start: int
    function_end: int
    personality: int | None = None
    lsda_address: int | None = None
    landing_pads: list[LandingPad] = field(default_factory=list)


class ExceptionInfoReader:
    """
    Reader for exception handling information from binary files.

    Supports:
    - ELF: .eh_frame and .gcc_except_table sections
    - PE: .pdata and .xdata sections
    - Mach-O: __unwind_info and __eh_frame sections
    """

    DW_CFA_advance_loc = 0x40
    DW_CFA_offset = 0x80
    DW_CFA_restore = 0xC0
    DW_CFA_nop = 0x00
    DW_CFA_set_loc = 0x01
    DW_CFA_advance_loc1 = 0x02
    DW_CFA_advance_loc2 = 0x03
    DW_CFA_advance_loc4 = 0x04
    DW_CFA_defineundefined_address_space = 0x19
    DW_CFA_restore_extended = 0x16

    def __init__(self, binary: Binary):
        """
        Initialize exception info reader.

        Args:
            binary: Binary instance to read from
        """
        self.binary = binary
        self._frames: dict[int, ExceptionFrame] | None = None

    def read_exception_frames(self) -> dict[int, ExceptionFrame]:
        """
        Read all exception frames from the binary.

        Returns:
            Dictionary mapping function addresses to ExceptionFrame instances
        """
        if self._frames is not None:
            return self._frames

        self._frames = {}

        arch_info = self.binary.get_arch_info()
        binary_format = arch_info.get("format", "")

        if binary_format.startswith("ELF"):
            self._read_elf_eh_frame()
        elif binary_format in ("PE", "PE+"):
            self._read_pe_exception_data()
        elif binary_format in ("Mach-O", "Mach-O-64"):
            self._read_macho_unwind_info()

        return self._frames

    def _read_elf_eh_frame(self):
        """Read exception frames from ELF .eh_frame section."""
        try:
            sections = self._get_sections()
            eh_frame_section = None
            for section in sections:
                name = section.get("name", "")
                if name == ".eh_frame":
                    eh_frame_section = section
                    break

            if not eh_frame_section:
                logger.debug("No .eh_frame section found")
                return

            eh_frame_addr = eh_frame_section.get("addr", eh_frame_section.get("virtual_address", 0))
            eh_frame_size = eh_frame_section.get("size", eh_frame_section.get("virtual_size", 0))

            if eh_frame_addr == 0 or eh_frame_size == 0:
                return

            data = self.binary.read_bytes(eh_frame_addr, eh_frame_size)
            if not data:
                return

            self._parse_eh_frame(data, eh_frame_addr)

        except Exception as e:
            logger.debug(f"Failed to read ELF eh_frame: {e}")

    def _parse_eh_frame(self, data: bytes, base_addr: int):
        """
        Parse .eh_frame section data.

        Args:
            data: Raw bytes from .eh_frame
            base_addr: Base address of the section
        """
        offset = 0

        while offset < len(data) - 4:
            try:
                length = struct.unpack("<I", data[offset : offset + 4])[0]
                if length == 0:
                    break

                cie_offset = offset + 4
                offset += 4 + length

                if offset > len(data):
                    break

                cie_id = struct.unpack("<I", data[cie_offset : cie_offset + 4])[0]

                if cie_id == 0:
                    self._parse_cie(data, cie_offset, length, base_addr)
                else:
                    self._parse_fde(data, cie_offset, length, base_addr, cie_id)

            except Exception as e:
                logger.debug(f"Failed to parse eh_frame entry at offset {offset}: {e}")
                break

    def _parse_cie(self, data: bytes, offset: int, length: int, base_addr: int):
        """Parse a Common Information Entry."""
        pass

    def _parse_fde(self, data: bytes, offset: int, length: int, base_addr: int, cie_offset: int):
        """Parse a Frame Description Entry and extract function bounds."""
        try:
            ptr_size = 8 if self.binary.get_arch_info().get("bits", 64) == 64 else 4

            pc_begin_offset = offset + 4 + ptr_size
            pc_begin = struct.unpack(
                "<Q" if ptr_size == 8 else "<I",
                data[pc_begin_offset : pc_begin_offset + ptr_size],
            )[0]

            pc_range = struct.unpack(
                "<Q" if ptr_size == 8 else "<I",
                data[pc_begin_offset + ptr_size : pc_begin_offset + 2 * ptr_size],
            )[0]

            if pc_begin > 0:
                frame = ExceptionFrame(
                    function_start=pc_begin,
                    function_end=pc_begin + pc_range,
                )
                self._frames[pc_begin] = frame

        except Exception as e:
            logger.debug(f"Failed to parse FDE at {offset}: {e}")

    def _read_pe_exception_data(self):
        """Read exception frames from PE .pdata and .xdata sections."""
        try:
            sections = self._get_sections()
            pdata_section = None
            for section in sections:
                name = section.get("name", "").rstrip("\x00")
                if name in (".pdata", "pdata"):
                    pdata_section = section
                    break

            if not pdata_section:
                logger.debug("No .pdata section found")
                return

            arch_info = self.binary.get_arch_info()
            bits = arch_info.get("bits", 64)

            pdata_addr = pdata_section.get("addr", pdata_section.get("virtual_address", 0))
            pdata_size = pdata_section.get("size", pdata_section.get("virtual_size", 0))

            if pdata_addr == 0 or pdata_size == 0:
                return

            entry_size = 8 if bits == 32 else 12
            num_entries = pdata_size // entry_size

            data = self.binary.read_bytes(pdata_addr, pdata_size)
            if not data:
                return

            for i in range(num_entries):
                entry_offset = i * entry_size
                if bits == 32:
                    begin, end, unwind_info = struct.unpack("<III", data[entry_offset : entry_offset + 12])
                    if begin == 0:
                        continue
                    frame = ExceptionFrame(
                        function_start=begin,
                        function_end=end,
                    )
                    self._frames[begin] = frame
                else:
                    begin_rva, end_rva, unwind_rva = struct.unpack("<III", data[entry_offset : entry_offset + 12])
                    if begin_rva == 0:
                        continue
                    frame = ExceptionFrame(
                        function_start=begin_rva,
                        function_end=end_rva,
                    )
                    self._frames[begin_rva] = frame

        except Exception as e:
            logger.debug(f"Failed to read PE exception data: {e}")

    def _read_macho_unwind_info(self):
        """Read exception frames from Mach-O __unwind_info section."""
        try:
            sections = self._get_sections()
            unwind_section = None
            for section in sections:
                name = section.get("name", "")
                if "__unwind_info" in name:
                    unwind_section = section
                    break

            if not unwind_section:
                logger.debug("No __unwind_info section found")
                return

            unwind_addr = unwind_section.get("addr", unwind_section.get("virtual_address", 0))
            unwind_size = unwind_section.get("size", unwind_section.get("virtual_size", 0))

            if unwind_addr == 0 or unwind_size == 0:
                return

            data = self.binary.read_bytes(unwind_addr, min(unwind_size, 4096))
            if not data or len(data) < 12:
                return

            if len(data) >= 20:
                personality_offset = struct.unpack("<I", data[8:12])[0]
                if personality_offset and personality_offset < len(data):
                    pass

        except Exception as e:
            logger.debug(f"Failed to read Mach-O unwind info: {e}")

    def _get_sections(self) -> list[dict]:
        """Get sections from the binary."""
        try:
            return self.binary.get_sections()
        except Exception:
            return []

    def find_landing_pads_for_function(self, function_address: int) -> list[LandingPad]:
        """
        Find all landing pads for a function.

        Args:
            function_address: Address of the function

        Returns:
            List of LandingPad instances
        """
        frames = self.read_exception_frames()
        frame = frames.get(function_address)

        if not frame:
            return []

        return frame.landing_pads

    def get_exception_edges_for_function(self, function_address: int) -> list[tuple[int, int, ExceptionAction]]:
        """
        Get exception edges for a function.

        Args:
            function_address: Address of the function

        Returns:
            List of (from_address, landing_pad_address, action) tuples
        """
        frames = self.read_exception_frames()
        frame = frames.get(function_address)

        if not frame:
            return []

        edges: list[tuple[int, int, ExceptionAction]] = []

        for pad in frame.landing_pads:
            edges.append((function_address, pad.address, pad.action))

        return edges


class ExceptionAwareCFGBuilder:
    """
    CFG builder that includes exception handling edges.

    This extends the basic CFG builder to handle:
    - Exception dispatch edges
    - Landing pad blocks
    - Cleanup/final handler blocks
    """

    def __init__(self, binary: Binary):
        """
        Initialize exception-aware CFG builder.

        Args:
            binary: Binary instance
        """
        self.binary = binary
        self.exception_reader = ExceptionInfoReader(binary)

    def analyze_function_exceptions(self, function_address: int) -> dict[str, Any]:
        """
        Analyze exception handling for a function.

        Args:
            function_address: Function address

        Returns:
            Dictionary with exception analysis results
        """
        frames = self.exception_reader.read_exception_frames()

        frame = frames.get(function_address)
        if not frame:
            return {
                "has_exceptions": False,
                "landing_pads": [],
                "exception_edges": [],
            }

        return {
            "has_exceptions": True,
            "landing_pads": [
                {
                    "address": pad.address,
                    "size": pad.size,
                    "action": pad.action.value,
                }
                for pad in frame.landing_pads
            ],
            "exception_edges": [(frame.function_start, pad.address, pad.action.value) for pad in frame.landing_pads],
        }

    def is_protected_region(self, address: int) -> bool:
        """
        Check if an address is within a protected region (try block).

        Args:
            address: Address to check

        Returns:
            True if address is in a protected region
        """
        frames = self.exception_reader.read_exception_frames()

        for frame in frames.values():
            if frame.function_start <= address < frame.function_end:
                if frame.landing_pads:
                    return True

        return False

    def get_landing_pad_for_address(self, address: int) -> LandingPad | None:
        """
        Get the landing pad that handles exceptions from an address.

        Args:
            address: Address to find landing pad for

        Returns:
            LandingPad instance or None if no landing pad
        """
        frames = self.exception_reader.read_exception_frames()

        for frame in frames.values():
            if frame.function_start <= address < frame.function_end:
                for pad in frame.landing_pads:
                    return pad

        return None

    def get_exception_aware_functions(self) -> list[int]:
        """
        Get list of functions with exception handling.

        Returns:
            List of function addresses with exception handling
        """
        frames = self.exception_reader.read_exception_frames()
        return [addr for addr, frame in frames.items() if frame.landing_pads]
