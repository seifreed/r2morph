"""Exception handling information reader."""

from __future__ import annotations

import logging
import struct

from r2morph.analysis.exception_models import ExceptionAction, ExceptionFrame, LandingPad
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


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
                if entry_offset + entry_size > len(data):
                    break
                if bits == 32:
                    begin, second = struct.unpack("<II", data[entry_offset : entry_offset + 8])
                    if begin == 0:
                        continue
                    if second & 0x3:
                        function_length = ((second >> 2) & 0x7FF) * 2
                        function_end = begin + function_length
                    else:
                        function_end = begin
                    self._frames[begin] = ExceptionFrame(
                        function_start=begin,
                        function_end=function_end,
                    )
                else:
                    begin_rva, end_rva, unwind_rva = struct.unpack("<III", data[entry_offset : entry_offset + 12])
                    if begin_rva == 0:
                        continue
                    self._frames[begin_rva] = ExceptionFrame(
                        function_start=begin_rva,
                        function_end=end_rva,
                    )

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

            unwind_addr = unwind_section.get("addr", unwind_section.get("virtual_address", 0))
            unwind_size = unwind_section.get("size", unwind_section.get("virtual_size", 0))

            if unwind_addr == 0 or unwind_size == 0:
                return

            data = self.binary.read_bytes(unwind_addr, min(unwind_size, 4096))
            if not data or len(data) < 12:
                return

            logger.debug(
                "Found Mach-O __unwind_info at 0x%x (%d bytes); detailed parsing not implemented",
                unwind_addr,
                unwind_size,
            )

        except (OSError, struct.error) as e:
            logger.debug("Failed to read Mach-O unwind info: %s", e)

    def _get_sections(self) -> list[dict]:
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
