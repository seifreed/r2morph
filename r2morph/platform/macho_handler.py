"""
Mach-O format specific handling (macOS/iOS).
"""

import importlib
import logging
import struct
from pathlib import Path
from typing import Any

from r2morph.adapters.process import ProcessError, run_process
from r2morph.platform.macho_arch import MACHO_MAGICS_64, MAGIC_SIZE_BYTES, resolve_macho_arch
from r2morph.platform.macho_handler_repair import (
    fix_bind_symbols as repair_fix_bind_symbols,
)
from r2morph.platform.macho_handler_repair import (
    fix_load_commands as repair_fix_load_commands,
)
from r2morph.platform.macho_handler_repair import (
    fix_segment_permissions as repair_fix_segment_permissions,
)
from r2morph.platform.macho_handler_repair import (
    full_repair as repair_full_repair,
)
from r2morph.platform.macho_handler_repair import (
    repair_integrity as repair_repair_integrity,
)
from r2morph.platform.macho_handler_repair import (
    validate_integrity as repair_validate_integrity,
)

logger = logging.getLogger(__name__)

try:
    lief: Any = importlib.import_module("lief")
except ImportError:
    lief = None

LIEF_AVAILABLE = lief is not None

# Load-command type -> human-readable name (the subset the fallback parser
# reports; unknown commands are rendered as their hex value).
_MACHO_LOAD_COMMAND_NAMES = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0xB: "LC_DYSYMTAB",
    0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID",
    0x1D: "LC_CODE_SIGNATURE",
    0x21: "LC_DYLD_INFO_ONLY",
    0x2A: "LC_SOURCE_VERSION",
    0x32: "LC_BUILD_VERSION",
}

# LC_SEGMENT command type (32-bit) and LC_SEGMENT_64 (64-bit).
_LC_SEGMENT = 0x1
_LC_SEGMENT_64 = 0x19
_LOAD_COMMAND_HEADER_SIZE_BYTES = 8
_MAX_LOAD_COMMAND_SIZE_BYTES = 0x100000


class MachOHandler:
    """
    Handles Mach-O specific operations.

    - Load commands
    - Code signing
    - Fat binary handling
    """

    def __init__(self, binary_path: Path):
        """
        Initialize Mach-O handler.

        Args:
            binary_path: Path to Mach-O file
        """
        self.binary_path = binary_path

    def _parse_lief(self) -> Any:
        if lief is None:
            return None
        try:
            return lief.parse(str(self.binary_path))
        except Exception as e:
            logger.error(f"Failed to parse Mach-O with LIEF: {e}")
            return None

    def _parse_macho_basic(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Minimal Mach-O parser fallback when LIEF is unavailable.

        Returns:
            (load_commands, segments)
        """
        try:
            file_size = self.binary_path.stat().st_size
            with open(self.binary_path, "rb") as f:
                arch = resolve_macho_arch(f, file_size)
                if arch is None:
                    return [], []
                endian, offset, magic = arch

                is_64 = magic in MACHO_MAGICS_64
                header_size = 32 if is_64 else 28
                f.seek(offset + MAGIC_SIZE_BYTES)
                header = f.read(header_size - MAGIC_SIZE_BYTES)
                if len(header) != header_size - MAGIC_SIZE_BYTES:
                    return [], []
                # Only ncmds is needed; it is the 4th u32 of the mach_header and
                # sits at the same offset in the 32- and 64-bit layouts.
                ncmds = struct.unpack(endian + "I", header[12:16])[0]

                commands: list[dict[str, Any]] = []
                segments: list[dict[str, Any]] = []
                f.seek(offset + header_size)

                for _ in range(ncmds):
                    cmd_header = f.read(_LOAD_COMMAND_HEADER_SIZE_BYTES)
                    if len(cmd_header) != _LOAD_COMMAND_HEADER_SIZE_BYTES:
                        break
                    cmd, cmdsize = struct.unpack(endian + "II", cmd_header)
                    if cmdsize < _LOAD_COMMAND_HEADER_SIZE_BYTES:
                        break
                    if cmdsize > _MAX_LOAD_COMMAND_SIZE_BYTES:
                        logger.warning(f"Unusually large cmdsize: {cmdsize}, skipping")
                        f.seek(cmdsize - _LOAD_COMMAND_HEADER_SIZE_BYTES, 1)
                        continue
                    commands.append({"command": _MACHO_LOAD_COMMAND_NAMES.get(cmd, f"0x{cmd:08x}")})

                    if cmd not in (_LC_SEGMENT, _LC_SEGMENT_64):
                        f.seek(cmdsize - _LOAD_COMMAND_HEADER_SIZE_BYTES, 1)
                        continue

                    seg_header_size = 56 if cmd == _LC_SEGMENT else 72
                    seg_data = f.read(seg_header_size - _LOAD_COMMAND_HEADER_SIZE_BYTES)
                    if len(seg_data) == seg_header_size - _LOAD_COMMAND_HEADER_SIZE_BYTES:
                        segments.append(self._parse_macho_segment(seg_data, cmd, endian))
                    remaining = cmdsize - seg_header_size
                    if remaining > 0 and remaining < _MAX_LOAD_COMMAND_SIZE_BYTES:
                        f.seek(remaining, 1)
                    elif remaining < 0:
                        logger.warning(f"Invalid remaining size: {remaining}")
                        break

                return commands, segments
        except Exception as e:
            logger.error(f"Failed to parse Mach-O fallback: {e}")
            return [], []

    @staticmethod
    def _parse_macho_segment(seg_data: bytes, cmd: int, endian: str) -> dict[str, Any]:
        """Parse an LC_SEGMENT / LC_SEGMENT_64 command body into a segment dict.

        The two layouts share the same nine fields; LC_SEGMENT_64 widens
        vmaddr/vmsize/fileoff/filesize from 4 to 8 bytes.
        """
        fmt = endian + ("16sQQQQIIII" if cmd == _LC_SEGMENT_64 else "16sIIIIIIII")
        (
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            _maxprot,
            _initprot,
            _nsects,
            _flags,
        ) = struct.unpack(fmt, seg_data)
        return {
            "name": segname.split(b"\x00", 1)[0].decode("ascii", errors="ignore"),
            "virtual_address": vmaddr,
            "virtual_size": vmsize,
            "file_offset": fileoff,
            "file_size": filesize,
        }

    def _iter_macho_binaries(self, binary: Any) -> list[Any]:
        if lief is None or binary is None:
            return []
        if isinstance(binary, lief.MachO.Binary):
            return [binary]
        if isinstance(binary, lief.MachO.FatBinary):
            try:
                it: Any = binary.it_binaries
                return list(it)
            except Exception:
                return []
        return []

    def is_macho(self) -> bool:
        """Check if the binary is a Mach-O (fat or thin)."""
        if lief is not None:
            binary = self._parse_lief()
            return isinstance(binary, (lief.MachO.Binary, lief.MachO.FatBinary))

        try:
            with open(self.binary_path, "rb") as f:
                magic = f.read(4)
                return magic in [
                    b"\xfe\xed\xfa\xce",  # MH_MAGIC
                    b"\xce\xfa\xed\xfe",  # MH_CIGAM
                    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
                    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
                    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
                    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
                ]
        except Exception:
            return False

    def get_load_commands(self) -> list[dict[str, Any]]:
        """
        Get Mach-O load commands.

        Returns:
            List of load command dicts
        """
        logger.debug("Getting Mach-O load commands")
        if lief is None:
            commands, _segments = self._parse_macho_basic()
            return commands

        binary = self._parse_lief()
        lief_commands: list[dict[Any, Any]] = []
        for macho in self._iter_macho_binaries(binary):
            for cmd in getattr(macho, "commands", []):
                name = getattr(cmd, "command", None)
                if name is not None and hasattr(name, "name"):
                    name = name.name
                lief_commands.append({"command": str(name)})
        return lief_commands

    def get_segments(self) -> list[dict[str, Any]]:
        """Get Mach-O segments."""
        if lief is None:
            _commands, segments = self._parse_macho_basic()
            return segments

        binary = self._parse_lief()
        lief_segments: list[dict[Any, Any]] = []
        for macho in self._iter_macho_binaries(binary):
            for seg in getattr(macho, "segments", []):
                lief_segments.append(
                    {
                        "name": seg.name,
                        "virtual_address": getattr(seg, "virtual_address", 0),
                        "virtual_size": getattr(seg, "virtual_size", 0),
                        "file_offset": getattr(seg, "file_offset", 0),
                        "file_size": getattr(seg, "file_size", 0),
                    }
                )
        return lief_segments

    def validate(self) -> bool:
        """Validate Mach-O structure."""
        if not self.is_macho():
            return False
        if lief is None:
            return True
        binary = self._parse_lief()
        if binary is None:
            return False
        if isinstance(binary, lief.MachO.Binary):
            return True
        if isinstance(binary, lief.MachO.FatBinary):
            return len(self._iter_macho_binaries(binary)) > 0
        return False

    def _relocations_in_segments(self, binary: Any) -> bool:
        try:
            segments = list(getattr(binary, "segments", []))
            if not segments:
                return True
            for reloc in getattr(binary, "relocations", []):
                address = getattr(reloc, "address", None)
                if address is None:
                    continue
                in_segment = False
                for seg in segments:
                    vaddr = getattr(seg, "virtual_address", 0)
                    vsize = getattr(seg, "virtual_size", 0)
                    if vaddr <= address < vaddr + vsize:
                        in_segment = True
                        break
                if not in_segment:
                    return False
            return True
        except Exception:
            return False

    def validate_integrity(self) -> tuple[bool, str]:
        """Validate Mach-O layout integrity (load commands, offsets, and sizes)."""
        return repair_validate_integrity(self)

    def repair_integrity(
        self,
        entitlements: Path | None = None,
        hardened: bool = False,
        timestamp: bool = False,
        system_name: str | None = None,
    ) -> bool:
        """Best-effort repair of Mach-O integrity post-mutation."""
        return repair_repair_integrity(
            self,
            entitlements=entitlements,
            hardened=hardened,
            timestamp=timestamp,
            system_name=system_name,
        )

    def is_fat_binary(self) -> bool:
        """
        Check if binary is a fat (universal) binary.

        Returns:
            True if fat binary
        """
        try:
            with open(self.binary_path, "rb") as f:
                magic = f.read(4)

                return magic in [
                    b"\xca\xfe\xba\xbe",
                    b"\xbe\xba\xfe\xca",
                ]

        except Exception:
            return False

    def extract_architecture(self, arch: str, output_path: Path) -> bool:
        """
        Extract specific architecture from fat binary.

        Args:
            arch: Architecture (e.g., 'arm64', 'x86_64')
            output_path: Output path for thin binary

        Returns:
            True if successful
        """
        logger.info(f"Extracting {arch} from fat binary")

        try:
            result = run_process(["lipo", self.binary_path, "-thin", arch, "-output", output_path], timeout=30)

            return result.returncode == 0

        except ProcessError as e:
            logger.error(f"Failed to extract architecture: {e}")
            return False

    def create_fat_binary(self, thin_binaries: list[Path], output_path: Path) -> bool:
        """
        Create fat binary from multiple thin binaries.

        Args:
            thin_binaries: List of thin binary paths
            output_path: Output fat binary path

        Returns:
            True if successful
        """
        logger.info(f"Creating fat binary from {len(thin_binaries)} architectures")

        try:
            cmd: list[str | Path] = ["lipo", "-create", *thin_binaries, "-output", output_path]

            result = run_process(cmd, timeout=30)

            return result.returncode == 0

        except ProcessError as e:
            logger.error(f"Failed to create fat binary: {e}")
            return False

    def get_sections(self) -> list[dict[str, Any]]:
        """
        Get Mach-O sections from all segments.

        Returns:
            List of section dictionaries
        """
        binary = self._parse_lief()
        sections: list[dict[str, Any]] = []

        for macho in self._iter_macho_binaries(binary):
            for seg in getattr(macho, "segments", []):
                for sec in getattr(seg, "sections", []):
                    sections.append(
                        {
                            "name": getattr(sec, "name", ""),
                            "segment": getattr(seg, "name", ""),
                            "virtual_address": getattr(sec, "virtual_address", 0),
                            "virtual_size": getattr(sec, "size", 0),
                            "file_offset": getattr(sec, "offset", 0),
                            "file_size": getattr(sec, "size", 0),
                            "flags": getattr(sec, "flags", 0),
                        }
                    )

        if not sections:
            _commands, segments = self._parse_macho_basic()
            for seg in segments:
                sections.append(
                    {
                        "name": seg.get("name", ""),
                        "segment": seg.get("name", ""),
                        "virtual_address": seg.get("virtual_address", 0),
                        "virtual_size": seg.get("virtual_size", 0),
                        "file_offset": seg.get("file_offset", 0),
                        "file_size": seg.get("file_size", 0),
                        "flags": 0,
                    }
                )

        return sections

    def fix_load_commands(self) -> tuple[bool, list[str]]:
        """Fix Mach-O load commands after mutation."""
        return repair_fix_load_commands(self)

    def fix_bind_symbols(self) -> tuple[bool, list[str]]:
        """Fix bind symbol information after mutation."""
        return repair_fix_bind_symbols(self)

    def fix_segment_permissions(self) -> tuple[bool, list[str]]:
        """Fix segment permissions after mutation."""
        return repair_fix_segment_permissions(self)

    def full_repair(self, entitlements: Path | None = None) -> tuple[bool, list[str]]:
        """Full Mach-O repair after mutation."""
        return repair_full_repair(self, entitlements=entitlements)
