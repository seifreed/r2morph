"""Exception handling information reader."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, replace
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
_DW_EH_PE_ABSPTR = 0x00
_DW_EH_PE_PCREL = 0x10
_DW_EH_PE_OMIT = 0xFF
_DW_EH_PE_UDATA2 = 0x02
_DW_EH_PE_UDATA4 = 0x03
_DW_EH_PE_UDATA8 = 0x04
_DW_EH_PE_SLEB128 = 0x09
_DW_EH_PE_SDATA2 = 0x0A
_DW_EH_PE_SDATA4 = 0x0B
_DW_EH_PE_SDATA8 = 0x0C
_MAX_EXCEPTION_SECTION_BYTES = 16 * 1024 * 1024
_MAX_LEB_SHIFT = 63
_WORD_BITS = 64
_MIN_EH_FRAME_ENTRY_LENGTH = 4
_EXTENDED_EH_FRAME_LENGTH = 0xFFFFFFFF
_EH_FRAME_LENGTH_FIELD_BYTES = 4
_DWARF64_LENGTH_FIELD_BYTES = 12
_DWARF64_CIE_ID_BYTES = 8


@dataclass(frozen=True)
class _CieInfo:
    """Pointer encodings needed to decode an ELF FDE and its LSDA."""

    pointer_encoding: int = _DW_EH_PE_ABSPTR
    lsda_encoding: int = _DW_EH_PE_OMIT
    personality: int | None = None
    has_z_augmentation: bool = False


@dataclass(frozen=True)
class _EncodedPointerContext:
    """Bounds and address context for one encoded pointer read."""

    end: int
    pointer_size: int
    field_address: int


@dataclass(frozen=True)
class _LsdaContext:
    """Encoding and address context for one LSDA call-site table."""

    end: int
    encoding: int
    pointer_size: int
    section_address: int
    base_address: int

    def with_base(self, base_address: int) -> _LsdaContext:
        return replace(self, base_address=base_address)


def _section_int(section: dict[str, Any], primary: str, fallback: str) -> int:
    value = section.get(primary, section.get(fallback, section.get("vaddr", 0)))
    return value if isinstance(value, int) else 0


def _read_uleb128(data: bytes, offset: int, end: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    while offset < end and shift <= _MAX_LEB_SHIFT:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    return None


def _read_sleb128(data: bytes, offset: int, end: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    byte = 0
    while offset < end and shift <= _MAX_LEB_SHIFT:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            if byte & 0x40 and shift < _WORD_BITS:
                value -= 1 << shift
            return value, offset
    return None


def _encoded_width(encoding: int, pointer_size: int) -> int | None:
    return {
        _DW_EH_PE_UDATA2: 2,
        _DW_EH_PE_UDATA4: 4,
        _DW_EH_PE_UDATA8: 8,
        _DW_EH_PE_SDATA2: 2,
        _DW_EH_PE_SDATA4: 4,
        _DW_EH_PE_SDATA8: 8,
        0x00: pointer_size,
    }.get(encoding & 0x0F)


def _read_encoded_pointer(
    data: bytes,
    offset: int,
    encoding: int,
    context: _EncodedPointerContext,
) -> tuple[int, int] | None:
    """Decode the bounded DWARF encodings used by ELF exception metadata."""
    if encoding == _DW_EH_PE_OMIT:
        return None
    application = encoding & 0x70
    if application not in (_DW_EH_PE_ABSPTR, _DW_EH_PE_PCREL):
        return None
    format_code = encoding & 0x0F
    if format_code == _DW_EH_PE_SLEB128:
        result = _read_sleb128(data, offset, context.end)
        if result is None:
            return None
        value, next_offset = result
    elif format_code == 0x01:
        result = _read_uleb128(data, offset, context.end)
        if result is None:
            return None
        value, next_offset = result
    else:
        width = _encoded_width(encoding, context.pointer_size)
        if width is None or offset + width > context.end:
            return None
        signed = format_code in (_DW_EH_PE_SDATA2, _DW_EH_PE_SDATA4, _DW_EH_PE_SDATA8)
        value = int.from_bytes(data[offset : offset + width], "little", signed=signed)
        next_offset = offset + width
    if application == _DW_EH_PE_PCREL:
        value += context.field_address
    return value, next_offset


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
        self._cies: dict[int, _CieInfo] = {}

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

        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Failed to read ELF eh_frame: %s", exc)

    def _parse_eh_frame(self, data: bytes, base_addr: int) -> None:
        offset = 0

        while offset + 4 <= len(data):
            try:
                entry_start = offset
                length = struct.unpack_from("<I", data, offset)[0]
                if length == 0:
                    break
                if length == _EXTENDED_EH_FRAME_LENGTH:
                    if offset + _DWARF64_LENGTH_FIELD_BYTES > len(data):
                        break
                    length = struct.unpack_from("<Q", data, offset + _EH_FRAME_LENGTH_FIELD_BYTES)[0]
                    length_field_bytes = _DWARF64_LENGTH_FIELD_BYTES
                    cie_id_bytes = _DWARF64_CIE_ID_BYTES
                else:
                    length_field_bytes = _EH_FRAME_LENGTH_FIELD_BYTES
                    cie_id_bytes = _EH_FRAME_LENGTH_FIELD_BYTES
                entry_end = offset + length_field_bytes + length
                if entry_end > len(data) or length < cie_id_bytes:
                    break
                content_start = offset + length_field_bytes
                cie_id = int.from_bytes(data[content_start : content_start + cie_id_bytes], "little")

                if cie_id == 0:
                    cie = self._parse_cie(data, content_start, cie_id_bytes, entry_end, base_addr)
                    if cie is not None:
                        self._cies[entry_start] = cie
                else:
                    cie_start = content_start - cie_id
                    self._parse_fde(
                        data,
                        (entry_start, length_field_bytes),
                        entry_end,
                        base_addr,
                        self._cies.get(cie_start),
                    )
                offset = entry_end

            except (IndexError, struct.error, ValueError) as exc:
                logger.debug("Failed to parse eh_frame entry at offset %d: %s", offset, exc)
                break

    def _parse_cie(
        self,
        data: bytes,
        content_start: int,
        cie_id_bytes: int,
        entry_end: int,
        base_addr: int,
    ) -> _CieInfo | None:
        """Parse CIE augmentation fields needed by x86-64 GCC exception tables."""
        header = self._read_cie_header(data, content_start, cie_id_bytes, entry_end)
        if header is None:
            return None
        cursor, augmentation = header
        if not augmentation.startswith("z"):
            return _CieInfo()
        return self._parse_cie_augmentation(data, cursor, entry_end, augmentation, base_addr)

    @staticmethod
    def _read_cie_header(
        data: bytes,
        content_start: int,
        cie_id_bytes: int,
        entry_end: int,
    ) -> tuple[int, str] | None:
        cursor = content_start + cie_id_bytes
        if cursor >= entry_end:
            return None
        cursor += 1
        augmentation_end = data.find(b"\0", cursor, entry_end)
        if augmentation_end < 0:
            return None
        augmentation = data[cursor:augmentation_end].decode("ascii", errors="ignore")
        cursor = augmentation_end + 1
        code_alignment = _read_uleb128(data, cursor, entry_end)
        if code_alignment is None:
            return None
        data_alignment = _read_sleb128(data, code_alignment[1], entry_end)
        if data_alignment is None:
            return None
        return_register = _read_uleb128(data, data_alignment[1], entry_end)
        if return_register is None:
            return None
        return return_register[1], augmentation

    def _parse_cie_augmentation(
        self,
        data: bytes,
        cursor: int,
        entry_end: int,
        augmentation: str,
        base_addr: int,
    ) -> _CieInfo | None:
        augmentation_length = _read_uleb128(data, cursor, entry_end)
        if augmentation_length is None:
            return None
        cursor = augmentation_length[1]
        augmentation_data_end = cursor + augmentation_length[0]
        if augmentation_data_end > entry_end:
            return None
        personality: int | None = None
        pointer_encoding = _DW_EH_PE_ABSPTR
        lsda_encoding = _DW_EH_PE_OMIT
        for marker in augmentation[1:]:
            if marker == "P":
                result = self._read_cie_personality(data, cursor, augmentation_data_end, base_addr)
                if result is None:
                    return None
                personality, cursor = result
            elif marker in ("L", "R"):
                if cursor >= augmentation_data_end:
                    return None
                if marker == "L":
                    lsda_encoding = data[cursor]
                else:
                    pointer_encoding = data[cursor]
                cursor += 1
            else:
                return None
        return _CieInfo(pointer_encoding, lsda_encoding, personality, True)

    def _read_cie_personality(
        self,
        data: bytes,
        cursor: int,
        end: int,
        base_addr: int,
    ) -> tuple[int | None, int] | None:
        if cursor >= end:
            return None
        encoding = data[cursor]
        cursor += 1
        if encoding == _DW_EH_PE_OMIT:
            return None, cursor
        result = _read_encoded_pointer(
            data,
            cursor,
            encoding,
            _EncodedPointerContext(end, self._pointer_size(), base_addr + cursor),
        )
        return None if result is None else result

    def _parse_fde(
        self,
        data: bytes,
        entry_layout: tuple[int, int],
        entry_end: int,
        base_addr: int,
        cie: _CieInfo | None,
    ) -> None:
        """Parse an FDE, including its augmentation pointer to an ELF LSDA."""
        pointer_size = self._pointer_size()
        cie_info = cie or _CieInfo()
        entry_start, length_field_bytes = entry_layout
        cie_id_bytes = (
            _DWARF64_CIE_ID_BYTES if length_field_bytes == _DWARF64_LENGTH_FIELD_BYTES else _EH_FRAME_LENGTH_FIELD_BYTES
        )
        content_start = entry_start + length_field_bytes
        cursor = content_start + cie_id_bytes
        initial = _read_encoded_pointer(
            data,
            cursor,
            cie_info.pointer_encoding,
            _EncodedPointerContext(entry_end, pointer_size, base_addr + cursor),
        )
        if initial is None:
            return
        pc_begin, cursor = initial
        range_encoding = cie_info.pointer_encoding & 0x0F
        pc_range_result = _read_encoded_pointer(
            data,
            cursor,
            range_encoding,
            _EncodedPointerContext(entry_end, pointer_size, base_addr + cursor),
        )
        if pc_range_result is None:
            return
        pc_range, cursor = pc_range_result
        lsda_address: int | None = None
        if cie_info.has_z_augmentation:
            augmentation_length = _read_uleb128(data, cursor, entry_end)
            if augmentation_length is None:
                return
            cursor = augmentation_length[1]
            augmentation_data_end = cursor + augmentation_length[0]
            if augmentation_data_end > entry_end:
                return
            if cie_info.lsda_encoding != _DW_EH_PE_OMIT and cursor < augmentation_data_end:
                lsda_result = _read_encoded_pointer(
                    data,
                    cursor,
                    cie_info.lsda_encoding,
                    _EncodedPointerContext(augmentation_data_end, pointer_size, base_addr + cursor),
                )
                if lsda_result is not None:
                    lsda_address = lsda_result[0]
        if pc_begin <= 0 or pc_range <= 0 or self._frames is None:
            return
        frame = ExceptionFrame(
            function_start=pc_begin,
            function_end=pc_begin + pc_range,
            personality=cie_info.personality,
            lsda_address=lsda_address,
        )
        if lsda_address is not None:
            self._parse_lsda(frame, lsda_address)
        self._frames[pc_begin] = frame

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

    def _pointer_size(self) -> int:
        return _POINTER_SIZE_64_BYTES if self.binary.get_arch_info().get("bits", _BITS_64) == _BITS_64 else 4

    def _read_section_for_address(self, address: int) -> tuple[bytes, int] | None:
        for section in self._get_sections():
            section_address = _section_int(section, "addr", "virtual_address")
            section_size = _section_int(section, "size", "virtual_size")
            if section_address <= address < section_address + section_size:
                if section_size <= 0 or section_size > _MAX_EXCEPTION_SECTION_BYTES:
                    return None
                data = self.binary.read_bytes(section_address, section_size)
                if not data:
                    return None
                return data, section_address
        return None

    def _parse_lsda(self, frame: ExceptionFrame, lsda_address: int) -> None:
        section = self._read_section_for_address(lsda_address)
        if section is None:
            return
        data, section_address = section
        cursor = lsda_address - section_address
        if cursor < 0 or cursor >= len(data):
            return
        try:
            header = self._read_lsda_header(data, cursor, section_address, frame)
            if header is None:
                return
            pads = self._read_lsda_call_sites(data, header, frame)
            frame.landing_pads.extend(pads)
        except (IndexError, ValueError, struct.error):
            logger.debug("Failed to parse LSDA at 0x%x", lsda_address)

    def _read_lsda_header(
        self,
        data: bytes,
        offset: int,
        section_address: int,
        frame: ExceptionFrame,
    ) -> tuple[int, int, int, _LsdaContext] | None:
        if offset >= len(data):
            return None
        lp_encoding = data[offset]
        cursor = offset + 1
        lp_start_result = self._read_lsda_lp_start(data, cursor, lp_encoding, section_address, frame)
        if lp_start_result is None:
            return None
        lp_start, cursor = lp_start_result
        type_cursor = self._skip_lsda_types(data, cursor)
        if type_cursor is None or type_cursor >= len(data):
            return None
        cursor = type_cursor
        call_site_encoding = data[cursor]
        call_site_length = _read_uleb128(data, cursor + 1, len(data))
        if call_site_length is None:
            return None
        call_site_start = call_site_length[1]
        call_site_end = call_site_start + call_site_length[0]
        if call_site_end > len(data):
            return None
        context = _LsdaContext(
            call_site_end,
            call_site_encoding,
            self._pointer_size(),
            section_address,
            frame.function_start,
        )
        return call_site_start, call_site_end, lp_start, context

    def _read_lsda_lp_start(
        self,
        data: bytes,
        offset: int,
        encoding: int,
        section_address: int,
        frame: ExceptionFrame,
    ) -> tuple[int, int] | None:
        if encoding == _DW_EH_PE_OMIT:
            return frame.function_start, offset
        result = _read_encoded_pointer(
            data,
            offset,
            encoding,
            _EncodedPointerContext(len(data), self._pointer_size(), section_address + offset),
        )
        return result

    @staticmethod
    def _skip_lsda_types(data: bytes, offset: int) -> int | None:
        if offset >= len(data):
            return None
        type_encoding = data[offset]
        if type_encoding == _DW_EH_PE_OMIT:
            return offset + 1
        type_offset = _read_uleb128(data, offset + 1, len(data))
        return None if type_offset is None else type_offset[1]

    @staticmethod
    def _read_lsda_offset(data: bytes, offset: int, context: _LsdaContext) -> tuple[int, int] | None:
        result = _read_encoded_pointer(
            data,
            offset,
            context.encoding,
            _EncodedPointerContext(context.end, context.pointer_size, context.section_address + offset),
        )
        if result is None:
            return None
        value, next_offset = result
        if context.encoding & 0x70 == _DW_EH_PE_ABSPTR:
            value += context.base_address
        return value, next_offset

    def _read_lsda_call_sites(
        self,
        data: bytes,
        header: tuple[int, int, int, _LsdaContext],
        frame: ExceptionFrame,
    ) -> list[LandingPad]:
        cursor, call_site_end, lp_start, context = header
        action_table_start = call_site_end
        pads: list[LandingPad] = []
        while cursor < call_site_end:
            site = self._read_lsda_call_site(data, cursor, context, frame, lp_start)
            if site is None:
                return []
            start, length, landing, action_index, cursor = site
            if landing == 0:
                continue
            pad = LandingPad(
                address=landing,
                size=max(1, length),
                action=self._lsda_action(data, action_table_start, action_index),
                metadata={
                    "call_site_start": frame.function_start + start,
                    "call_site_end": frame.function_start + start + length,
                    "action_index": action_index,
                },
            )
            existing = next((item for item in pads if item.address == landing), None)
            if existing is None:
                pads.append(pad)
            else:
                existing.metadata.setdefault("call_sites", []).append(pad.metadata)
        return pads

    def _read_lsda_call_site(
        self,
        data: bytes,
        offset: int,
        context: _LsdaContext,
        frame: ExceptionFrame,
        lp_start: int,
    ) -> tuple[int, int, int, int, int] | None:
        start = self._read_lsda_offset(data, offset, context.with_base(frame.function_start))
        if start is None:
            return None
        length = self._read_lsda_offset(data, start[1], context.with_base(0))
        if length is None:
            return None
        landing = self._read_lsda_offset(data, length[1], context.with_base(lp_start))
        if landing is None:
            return None
        action = _read_uleb128(data, landing[1], context.end)
        if action is None:
            return None
        return start[0], length[0], landing[0], action[0], action[1]

    @staticmethod
    def _lsda_action(data: bytes, action_start: int, action_index: int) -> ExceptionAction:
        if action_index == 0:
            return ExceptionAction.CLEANUP
        action_offset = action_start + action_index - 1
        first_filter = _read_sleb128(data, action_offset, len(data))
        if first_filter is None:
            return ExceptionAction.UNKNOWN
        if first_filter[0] > 0:
            return ExceptionAction.CATCH
        if first_filter[0] < 0:
            return ExceptionAction.FILTER
        return ExceptionAction.CLEANUP

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
