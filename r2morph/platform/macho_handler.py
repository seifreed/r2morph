"""
Mach-O format specific handling (macOS/iOS).
"""

import logging
import platform
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import lief
except Exception:  # pragma: no cover - optional dependency
    lief = None

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

    def _parse_lief(self):
        if lief is None:
            return None
        try:
            return lief.parse(str(self.binary_path))
        except Exception as e:
            logger.error(f"Failed to parse Mach-O with LIEF: {e}")
            return None

    def _parse_macho_basic(self) -> tuple[list[dict], list[dict]]:
        """
        Minimal Mach-O parser fallback when LIEF is unavailable.

        Returns:
            (load_commands, segments)
        """
        try:
            with open(self.binary_path, "rb") as f:
                magic_bytes = f.read(4)
                if len(magic_bytes) != 4:
                    return [], []
                le_magic = struct.unpack("<I", magic_bytes)[0]
                be_magic = struct.unpack(">I", magic_bytes)[0]

                macho_magics_le = {
                    0xFEEDFACE,
                    0xFEEDFACF,
                    0xCEFAEDFE,
                    0xCFFAEDFE,
                }
                fat_magics_be = {0xCAFEBABE, 0xCAFEBABF, 0xBEBAFECA, 0xBFBAFECA}

                endian = "<"
                offset = 0
                magic = le_magic

                if be_magic in fat_magics_be:
                    endian = ">" if be_magic in {0xCAFEBABE, 0xCAFEBABF} else "<"
                    f.seek(0)
                    magic = struct.unpack(endian + "I", f.read(4))[0]
                    if magic in {0xCAFEBABE, 0xBEBAFECA}:
                        nfat = struct.unpack(endian + "I", f.read(4))[0]
                        if nfat < 1:
                            return [], []
                        arch_data = f.read(20)
                        if len(arch_data) != 20:
                            return [], []
                        _, _, arch_offset, _, _ = struct.unpack(endian + "IIIII", arch_data)
                        offset = arch_offset
                    elif magic in {0xCAFEBABF, 0xBFBAFECA}:
                        nfat = struct.unpack(endian + "I", f.read(4))[0]
                        if nfat < 1:
                            return [], []
                        arch_data = f.read(32)
                        if len(arch_data) != 32:
                            return [], []
                        _, _, arch_offset, _, _, _ = struct.unpack(
                            endian + "IIQQII", arch_data
                        )
                        offset = arch_offset
                    else:
                        return [], []
                    f.seek(offset)
                    magic_bytes = f.read(4)
                    if len(magic_bytes) != 4:
                        return [], []
                    le_magic = struct.unpack("<I", magic_bytes)[0]
                    be_magic = struct.unpack(">I", magic_bytes)[0]
                    if le_magic in macho_magics_le:
                        endian = "<"
                        magic = le_magic
                    elif be_magic in macho_magics_le:
                        endian = ">"
                        magic = be_magic
                    else:
                        return [], []
                elif le_magic in macho_magics_le:
                    endian = "<"
                elif be_magic in macho_magics_le:
                    endian = ">"
                    magic = be_magic
                else:
                    return [], []

                is_64 = magic in {0xFEEDFACF, 0xCFFAEDFE}
                header_size = 32 if is_64 else 28
                f.seek(offset + 4)
                header = f.read(header_size - 4)
                if len(header) != header_size - 4:
                    return [], []
                if is_64:
                    (
                        _cputype,
                        _cpusubtype,
                        _filetype,
                        ncmds,
                        _sizeofcmds,
                        _flags,
                        _reserved,
                    ) = struct.unpack(endian + "IIIIIII", header)
                else:
                    (
                        _cputype,
                        _cpusubtype,
                        _filetype,
                        ncmds,
                        _sizeofcmds,
                        _flags,
                    ) = struct.unpack(endian + "IIIIII", header)

                commands: list[dict] = []
                segments: list[dict] = []
                cmd_offset = offset + header_size
                f.seek(cmd_offset)

                cmd_name_map = {
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

                for _ in range(ncmds):
                    cmd_header = f.read(8)
                    if len(cmd_header) != 8:
                        break
                    cmd, cmdsize = struct.unpack(endian + "II", cmd_header)
                    if cmdsize < 8:
                        break
                    name = cmd_name_map.get(cmd, f"0x{cmd:08x}")
                    commands.append({"command": name})

                    if cmd in {0x1, 0x19}:
                        seg_header_size = 56 if cmd == 0x1 else 72
                        seg_data = f.read(seg_header_size - 8)
                        if len(seg_data) == seg_header_size - 8:
                            if cmd == 0x1:
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
                                ) = struct.unpack(endian + "16sIIIIIIII", seg_data)
                            else:
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
                                ) = struct.unpack(endian + "16sQQQQIIII", seg_data)
                            segments.append(
                                {
                                    "name": segname.split(b"\x00", 1)[0].decode(
                                        "ascii", errors="ignore"
                                    ),
                                    "virtual_address": vmaddr,
                                    "virtual_size": vmsize,
                                    "file_offset": fileoff,
                                    "file_size": filesize,
                                }
                            )
                        remaining = cmdsize - seg_header_size
                        if remaining > 0:
                            f.seek(remaining, 1)
                    else:
                        f.seek(cmdsize - 8, 1)

                return commands, segments
        except Exception as e:
            logger.error(f"Failed to parse Mach-O fallback: {e}")
            return [], []

    def _iter_macho_binaries(self, binary):
        if lief is None or binary is None:
            return []
        if isinstance(binary, lief.MachO.Binary):
            return [binary]
        if isinstance(binary, lief.MachO.FatBinary):
            try:
                return list(binary.it_binaries)
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

    def get_load_commands(self) -> list[dict]:
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
        commands: list[dict] = []
        for macho in self._iter_macho_binaries(binary):
            for cmd in getattr(macho, "commands", []):
                name = getattr(cmd, "command", None)
                if name is not None and hasattr(name, "name"):
                    name = name.name
                commands.append({"command": str(name)})
        return commands

    def get_segments(self) -> list[dict]:
        """Get Mach-O segments."""
        if lief is None:
            _commands, segments = self._parse_macho_basic()
            return segments

        binary = self._parse_lief()
        segments: list[dict] = []
        for macho in self._iter_macho_binaries(binary):
            for seg in getattr(macho, "segments", []):
                segments.append(
                    {
                        "name": seg.name,
                        "virtual_address": getattr(seg, "virtual_address", 0),
                        "virtual_size": getattr(seg, "virtual_size", 0),
                        "file_offset": getattr(seg, "file_offset", 0),
                        "file_size": getattr(seg, "file_size", 0),
                    }
                )
        return segments

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

    def _relocations_in_segments(self, binary) -> bool:
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
        """
        Validate Mach-O layout integrity (load commands, offsets, and sizes).

        Returns:
            (ok, message)
        """
        if not self.is_macho():
            return False, "Not a Mach-O binary"
        if lief is None:
            return True, "LIEF not available for deep integrity checks"
        binary = self._parse_lief()
        if binary is None:
            return False, "Failed to parse Mach-O"
        ok, msg = lief.MachO.check_layout(binary)
        if not ok:
            return False, msg or "Mach-O layout invalid"
        if not self._relocations_in_segments(binary):
            return False, "Mach-O relocations out of segment bounds"
        return True, ""

    def repair_integrity(
        self,
        entitlements: Path | None = None,
        hardened: bool = False,
        timestamp: bool = False,
    ) -> bool:
        """
        Best-effort repair of Mach-O integrity post-mutation.

        This focuses on refreshing LC_CODE_SIGNATURE and re-signing the binary.
        LIEF builder is not available in this environment, so structural repairs
        are limited to re-signing.
        """
        if platform.system() != "Darwin":
            return False
        if not self.is_macho():
            return False
        try:
            from r2morph.platform.codesign import CodeSigner

            signer = CodeSigner()

            if lief is not None:
                binary = self._parse_lief()
                if binary is not None:
                    try:
                        if getattr(binary, "has_code_signature", False):
                            binary.remove_signature()
                        tmp_path = self.binary_path.with_suffix(
                            self.binary_path.suffix + ".repaired"
                        )
                        binary.write(str(tmp_path))
                        tmp_path.replace(self.binary_path)
                    except Exception as e:
                        logger.error(f"Failed to rewrite Mach-O with LIEF: {e}")

            signer.remove_signature(self.binary_path)
            return signer.sign_binary(
                self.binary_path,
                adhoc=True,
                entitlements=entitlements,
                hardened=hardened,
                timestamp=timestamp,
            )
        except Exception as e:
            logger.error(f"Failed to repair Mach-O signature: {e}")
            return False

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

        import subprocess

        try:
            result = subprocess.run(
                ["lipo", str(self.binary_path), "-thin", arch, "-output", str(output_path)],
                capture_output=True,
                timeout=30,
            )

            return result.returncode == 0

        except subprocess.SubprocessError as e:
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

        import subprocess

        try:
            cmd = (
                ["lipo", "-create"]
                + [str(p) for p in thin_binaries]
                + ["-output", str(output_path)]
            )

            result = subprocess.run(cmd, capture_output=True, timeout=30)

            return result.returncode == 0

        except subprocess.SubprocessError as e:
            logger.error(f"Failed to create fat binary: {e}")
            return False
