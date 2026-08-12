"""Exception handling information reader."""

from __future__ import annotations

import logging
import struct
from typing import Any

from r2morph.analysis.exception_models import ExceptionAction, ExceptionFrame, LandingPad
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

_BITS_32 = 32
_BITS_64 = 64
_POINTER_SIZE_64_BYTES = 8
_PE_32_EXCEPTION_ENTRY_SIZE_BYTES = 8
_PE_64_EXCEPTION_ENTRY_SIZE_BYTES = 12
_MACHO_UNWIND_HEADER_SIZE_BYTES = 12


def _section_int(section: dict[str, Any], primary: str, fallback: str) -> int:
    value = section.get(primary, section.get(fallback, 0))
    return value if isinstance(value, int) else 0


class ExceptionInfoReader:
    """
    Reader for exception handling information from binary files.

    Supports:
    - ELF: .eh_frame and .gcc_except_table sections
    - PE: .pdata and .xdata sections
    - Mach-O: __unwind_info and __eh_frame sections
    """

    def __init__(self, binary: Binary):
        self.binary = binary
        self._frames: dict[int, ExceptionFrame] | None = None

    def read_exception_frames(self) -> dict[int, ExceptionFrame]:
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

    def _read_elf_eh_frame(self) -> None:
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

            eh_frame_addr = _section_int(eh_frame_section, "addr", "virtual_address")
            eh_frame_size = _section_int(eh_frame_section, "size", "virtual_size")

            if eh_frame_addr == 0 or eh_frame_size == 0:
                return

            data = self.binary.read_bytes(eh_frame_addr, eh_frame_size)
            if not data:
                return

            self._parse_eh_frame(data, eh_frame_addr)

        except Exception as e:
            logger.debug(f"Failed to read ELF eh_frame: {e}")

    def _parse_eh_frame(self, data: bytes, base_addr: int) -> None:
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

    def _parse_cie(self, data: bytes, offset: int, length: int, base_addr: int) -> None:
        """Parse a Common Information Entry.

        Intentional no-op: the current FDE parser uses fixed pointer sizes
        derived from the binary architecture instead of CIE augmentation
        and encoding fields, so no CIE state needs to be retained yet.
        When CIE-aware FDE parsing is added, this method must populate a
        per-CIE state dict that ``_parse_fde`` then consults.
        """
        return

    def _parse_fde(self, data: bytes, offset: int, length: int, base_addr: int, cie_offset: int) -> None:
        """Parse a Frame Description Entry and extract function bounds."""
        try:
            ptr_size = _POINTER_SIZE_64_BYTES if self.binary.get_arch_info().get("bits", _BITS_64) == _BITS_64 else 4

            pc_begin_offset = offset + 4 + ptr_size
            pc_begin = struct.unpack(
                "<Q" if ptr_size == _POINTER_SIZE_64_BYTES else "<I",
                data[pc_begin_offset : pc_begin_offset + ptr_size],
            )[0]

            pc_range = struct.unpack(
                "<Q" if ptr_size == _POINTER_SIZE_64_BYTES else "<I",
                data[pc_begin_offset + ptr_size : pc_begin_offset + 2 * ptr_size],
            )[0]

            if pc_begin > 0 and self._frames is not None:
                frame = ExceptionFrame(
                    function_start=pc_begin,
                    function_end=pc_begin + pc_range,
                )
                self._frames[pc_begin] = frame

        except Exception as e:
            logger.debug(f"Failed to parse FDE at {offset}: {e}")

    def _read_pe_exception_data(self) -> None:
        """Read exception frames from PE .pdata and .xdata sections."""
        if self._frames is None:
            self._frames = {}
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

            pdata_addr = _section_int(pdata_section, "addr", "virtual_address")
            pdata_size = _section_int(pdata_section, "size", "virtual_size")

            if pdata_addr == 0 or pdata_size == 0:
                return

            entry_size = _PE_32_EXCEPTION_ENTRY_SIZE_BYTES if bits == _BITS_32 else _PE_64_EXCEPTION_ENTRY_SIZE_BYTES
            num_entries = pdata_size // entry_size
            entry_parser = self._parse_pe32_entry if bits == _BITS_32 else self._parse_pe64_entry

            data = self.binary.read_bytes(pdata_addr, pdata_size)
            if not data:
                return

            for index in range(num_entries):
                entry_offset = index * entry_size
                if entry_offset + entry_size > len(data):
                    break
                frame = entry_parser(data[entry_offset : entry_offset + entry_size])
                if frame is not None:
                    self._frames[frame.function_start] = frame

        except Exception as e:
            logger.debug(f"Failed to read PE exception data: {e}")

    def _read_macho_unwind_info(self) -> None:
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

            unwind_addr = _section_int(unwind_section, "addr", "virtual_address")
            unwind_size = _section_int(unwind_section, "size", "virtual_size")

            if unwind_addr == 0 or unwind_size == 0:
                return

            data = self.binary.read_bytes(unwind_addr, min(unwind_size, 4096))
            if not data or len(data) < _MACHO_UNWIND_HEADER_SIZE_BYTES:
                return

            logger.debug(
                "Found Mach-O __unwind_info at 0x%x (%d bytes); detailed parsing not implemented",
                unwind_addr,
                unwind_size,
            )

        except (OSError, struct.error) as e:
            logger.debug("Failed to read Mach-O unwind info: %s", e)

    def _get_sections(self) -> list[dict[str, Any]]:
        """Get sections from the binary."""
        try:
            return self.binary.get_sections()
        except Exception:
            return []

    def find_landing_pads_for_function(self, function_address: int) -> list[LandingPad]:
        frames = self.read_exception_frames()
        frame = frames.get(function_address)
        if not frame:
            return []
        return frame.landing_pads

    def get_exception_edges_for_function(self, function_address: int) -> list[tuple[int, int, ExceptionAction]]:
        frames = self.read_exception_frames()
        frame = frames.get(function_address)
        if not frame:
            return []

        edges: list[tuple[int, int, ExceptionAction]] = []
        for pad in frame.landing_pads:
            edges.append((function_address, pad.address, pad.action))
        return edges

    @staticmethod
    def _parse_pe32_entry(entry: bytes) -> ExceptionFrame | None:
        begin, second = struct.unpack("<II", entry)
        if begin == 0:
            return None
        function_length = ((second >> 2) & 0x7FF) * 2 if second & 0x3 else 0
        return ExceptionFrame(function_start=begin, function_end=begin + function_length)

    @staticmethod
    def _parse_pe64_entry(entry: bytes) -> ExceptionFrame | None:
        begin_rva, end_rva, _unwind_rva = struct.unpack("<III", entry)
        if begin_rva == 0:
            return None
        return ExceptionFrame(function_start=begin_rva, function_end=end_rva)
