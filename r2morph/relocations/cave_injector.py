"""
Advanced code cave injection for binary mutation.

Provides capabilities beyond basic cave finding:
- Create new sections for code caves
- Extend existing sections
- Align code properly
- Handle cross-references
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder, CodeCave

logger = logging.getLogger(__name__)


class CaveType(Enum):
    """Type of code cave."""

    EXISTING = "existing"
    NEW_SECTION = "new_section"
    EXTENDED_SECTION = "extended_section"
    OVERLAY = "overlay"


class SectionPermissions(Enum):
    """Section permission flags."""

    READ = "r"
    WRITE = "w"
    EXECUTE = "x"
    READ_WRITE = "rw"
    READ_EXECUTE = "rx"
    READ_WRITE_EXECUTE = "rwx"


@dataclass
class CodeCaveAllocation:
    """Represents an allocated code cave."""

    address: int
    size: int
    cave_type: CaveType
    section_name: str
    allocated_bytes: bytes = field(default_factory=bytes)
    alignment: int = 16
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"CaveAllocation @ 0x{self.address:x} ({self.size} bytes, {self.cave_type.value})"


@dataclass
class CaveCreationOptions:
    """Options for creating new code caves."""

    name: str = ".cave"
    size: int = 0x1000
    permissions: SectionPermissions = SectionPermissions.READ_EXECUTE
    alignment: int = 0x1000
    fill_byte: int = 0x90


class CodeCaveInjector:
    """
    Advanced code cave injection with section creation capabilities.

    Provides:
    - Finding existing caves
    - Creating new sections
    - Extending existing sections
    - Proper alignment handling
    - Cross-reference patching
    """

    DEFAULT_ALIGNMENT = 16
    MIN_SECTION_SIZE = 0x200

    def __init__(self, binary: Binary, min_cave_size: int = 16) -> None:
        """
        Initialize the code cave injector.

        Args:
            binary: Binary instance
            min_cave_size: Minimum cave size to consider
        """
        self.binary = binary
        self.min_cave_size = min_cave_size
        self.cave_finder = CaveFinder(binary, min_cave_size)
        self._allocations: list[CodeCaveAllocation] = []
        self._created_sections: dict[str, int] = {}

    def find_executable_caves(self, min_size: int | None = None) -> list[CodeCave]:
        """Find all executable code caves."""
        min_sz = min_size or self.min_cave_size
        self.cave_finder.min_size = min_sz
        return self.cave_finder.find_caves()

    def find_cave_for_code(self, code_size: int, require_executable: bool = True) -> CodeCave | None:
        """
        Find a suitable cave for code insertion.

        Args:
            code_size: Size of code to insert
            require_executable: Whether cave must be in executable section

        Returns:
            CodeCave or None if not found
        """
        caves = self.find_executable_caves(code_size)

        for cave in sorted(caves, key=lambda c: c.size):
            if cave.size >= code_size:
                if require_executable and not cave.is_executable:
                    continue
                return cave

        return None

    def allocate_from_cave(self, cave: CodeCave, size: int, alignment: int = DEFAULT_ALIGNMENT) -> CodeCaveAllocation:
        """
        Allocate space from an existing cave.

        Args:
            cave: Cave to allocate from
            size: Size needed
            alignment: Required alignment

        Returns:
            CodeCaveAllocation
        """
        aligned_addr = self._align_address(cave.address, alignment)
        aligned_size = size + (aligned_addr - cave.address)

        if aligned_size > cave.size:
            raise ValueError(f"Cannot allocate {aligned_size} bytes from {cave.size} byte cave (after alignment)")

        allocation = CodeCaveAllocation(
            address=aligned_addr,
            size=size,
            cave_type=CaveType.EXISTING,
            section_name=cave.section,
            alignment=alignment,
        )

        cave.address += aligned_size
        cave.size -= aligned_size

        self._allocations.append(allocation)
        return allocation

    def create_cave_section(
        self,
        options: CaveCreationOptions | None = None,
    ) -> CodeCaveAllocation | None:
        """
        Create a new section as a code cave.

        Args:
            options: Cave creation options

        Returns:
            CodeCaveAllocation or None if not possible
        """
        opts = options or CaveCreationOptions()

        arch_info = self.binary.get_arch_info()
        binary_format = arch_info.get("format", "")

        if binary_format.startswith("ELF"):
            return self._create_elf_section(opts)
        elif binary_format in ("PE", "PE+"):
            return self._create_pe_section(opts)
        elif binary_format in ("Mach-O", "Mach-O-64"):
            return self._create_macho_section(opts)
        else:
            logger.warning(f"Unsupported binary format for section creation: {binary_format}")
            return None

    def _create_elf_section(self, options: CaveCreationOptions) -> CodeCaveAllocation | None:
        """Create a new ELF section using lief via ELFHandler.add_section."""
        try:
            from r2morph.platform.elf_handler import ELFHandler

            section_size = max(options.size, self.MIN_SECTION_SIZE)
            flags = 0x6 if options.executable else 0x2
            if options.executable:
                flags = 0x6  # SHF_ALLOC | SHF_EXECINSTR

            handler = ELFHandler(self.binary.path)
            vaddr = handler.add_section(options.name, section_size, flags=flags)
            if vaddr is None:
                logger.error(f"ELFHandler.add_section failed for '{options.name}'")
                return None

            self._created_sections[options.name] = vaddr

            allocation = CodeCaveAllocation(
                address=vaddr,
                size=section_size,
                cave_type=CaveType.NEW_SECTION,
                section_name=options.name,
                alignment=options.alignment,
                metadata={"format": "ELF"},
            )

            logger.info(f"Created ELF section '{options.name}' at 0x{vaddr:x} ({section_size} bytes)")
            self._allocations.append(allocation)
            return allocation

        except Exception as e:
            logger.error(f"Failed to create ELF section: {e}")
            return None

    def _create_pe_section(self, options: CaveCreationOptions) -> CodeCaveAllocation | None:
        """Create a new PE section using lief via PEHandler.add_section."""
        try:
            import lief
        except ImportError:
            logger.error("lief required for PE section creation")
            return None

        try:
            section_size = max(options.size, self.MIN_SECTION_SIZE)
            characteristics = 0x60000020  # CODE | EXECUTE | READ
            if not options.executable:
                characteristics = 0xC0000040  # INITIALIZED_DATA | READ | WRITE

            parsed = lief.parse(str(self.binary.path))
            if parsed is None or not isinstance(parsed, lief.PE.Binary):
                logger.error("Failed to parse PE binary with lief")
                return None

            section = lief.PE.Section(options.name[:8])
            section.content = list(bytes(section_size))
            section.characteristics = characteristics
            section.virtual_size = section_size

            parsed.add_section(section)
            parsed.write(str(self.binary.path))

            added = parsed.get_section(options.name[:8])
            vaddr = added.virtual_address if added else 0
            if vaddr == 0:
                logger.error(f"PE section '{options.name}' added but vaddr is 0")
                return None

            self._created_sections[options.name] = vaddr

            allocation = CodeCaveAllocation(
                address=vaddr,
                size=section_size,
                cave_type=CaveType.NEW_SECTION,
                section_name=options.name,
                alignment=0x1000,
                metadata={"format": "PE"},
            )

            logger.info(f"Created PE section '{options.name}' at 0x{vaddr:x} ({section_size} bytes)")
            self._allocations.append(allocation)
            return allocation

        except Exception as e:
            logger.error(f"Failed to create PE section: {e}")
            return None

    def _create_macho_section(self, options: CaveCreationOptions) -> CodeCaveAllocation | None:
        """Create a new Mach-O section in __TEXT segment using lief."""
        try:
            import lief
        except ImportError:
            logger.error("lief required for Mach-O section creation")
            return None

        try:
            section_size = max(options.size, self.MIN_SECTION_SIZE)
            parsed = lief.parse(str(self.binary.path))
            if parsed is None:
                logger.error("Failed to parse Mach-O binary with lief")
                return None

            macho = parsed
            if isinstance(parsed, lief.MachO.FatBinary):
                macho = parsed.at(0)
            if not isinstance(macho, lief.MachO.Binary):
                logger.error("Parsed binary is not Mach-O")
                return None

            section = lief.MachO.Section(options.name, list(bytes(section_size)))
            section.alignment = 4  # 2^4 = 16-byte alignment

            text_segment = macho.get_segment("__TEXT")
            if text_segment is None:
                logger.error("No __TEXT segment found in Mach-O")
                return None

            added = text_segment.add_section(section)
            macho.write(str(self.binary.path))

            vaddr = added.virtual_address if added else 0
            if vaddr == 0:
                logger.error(f"Mach-O section '{options.name}' added but vaddr is 0")
                return None

            self._created_sections[options.name] = vaddr

            allocation = CodeCaveAllocation(
                address=vaddr,
                size=section_size,
                cave_type=CaveType.NEW_SECTION,
                section_name=options.name,
                alignment=0x4000,
                metadata={"format": "Mach-O"},
            )

            logger.info(f"Created Mach-O section '{options.name}' at 0x{vaddr:x} ({section_size} bytes)")
            self._allocations.append(allocation)
            return allocation

        except Exception as e:
            logger.error(f"Failed to create Mach-O section: {e}")
            return None

    def extend_section(
        self,
        section_name: str,
        additional_size: int,
    ) -> CodeCaveAllocation | None:
        """
        Extend an existing section to create more space.

        Args:
            section_name: Name of section to extend
            additional_size: Size to add

        Returns:
            CodeCaveAllocation or None
        """
        sections = self.binary.get_sections()
        target_section = None

        for section in sections:
            if section.get("name") == section_name:
                target_section = section
                break

        if not target_section:
            logger.warning(f"Section {section_name} not found")
            return None

        section_addr = target_section.get("vaddr", 0)
        section_size = target_section.get("vsize", 0)

        new_space_addr = section_addr + section_size
        aligned_addr = self._align_address(new_space_addr, self.DEFAULT_ALIGNMENT)

        allocation = CodeCaveAllocation(
            address=aligned_addr,
            size=additional_size,
            cave_type=CaveType.EXTENDED_SECTION,
            section_name=section_name,
            alignment=self.DEFAULT_ALIGNMENT,
            metadata={"original_section_size": section_size},
        )

        self._allocations.append(allocation)
        logger.info(f"Planned extension of {section_name} by {additional_size} bytes")
        return allocation

    def insert_code(
        self,
        code_bytes: bytes,
        preferred_section: str | None = None,
        alignment: int = DEFAULT_ALIGNMENT,
        allow_section_creation: bool = False,
    ) -> CodeCaveAllocation | None:
        """
        Insert code into the binary, finding or creating space as needed.

        Args:
            code_bytes: Code to insert
            preferred_section: Preferred section name
            alignment: Required alignment
            allow_section_creation: Whether to create new section if needed

        Returns:
            CodeCaveAllocation or None
        """
        needed_size = len(code_bytes) + alignment

        cave = self.find_cave_for_code(needed_size, require_executable=True)

        if cave:
            return self._insert_into_cave(cave, code_bytes, alignment)

        if preferred_section:
            cave = self._find_cave_in_section(preferred_section, needed_size)
            if cave:
                return self._insert_into_cave(cave, code_bytes, alignment)

        if allow_section_creation:
            options = CaveCreationOptions(
                name=".text.cave",
                size=max(needed_size * 2, 0x1000),
                permissions=SectionPermissions.READ_EXECUTE,
            )
            allocation = self.create_cave_section(options)
            if allocation:
                allocation.allocated_bytes = code_bytes
                return allocation

        logger.warning(f"Could not find or create space for {len(code_bytes)} bytes of code")
        return None

    def _insert_into_cave(self, cave: CodeCave, code_bytes: bytes, alignment: int) -> CodeCaveAllocation | None:
        """Insert code into an existing cave."""
        allocation = self.allocate_from_cave(cave, len(code_bytes), alignment)
        allocation.allocated_bytes = code_bytes

        if not self.binary.write_bytes(allocation.address, code_bytes):
            logger.error(f"Failed to inject {len(code_bytes)} bytes at 0x{allocation.address:x}")
            return None
        logger.info(f"Injected {len(code_bytes)} bytes at 0x{allocation.address:x}")

        return allocation

    def _find_cave_in_section(self, section_name: str, min_size: int) -> CodeCave | None:
        """Find a cave in a specific section."""
        caves = self.cave_finder.find_caves()
        for cave in caves:
            if cave.section == section_name and cave.size >= min_size:
                return cave
        return None

    def _align_address(self, address: int, alignment: int) -> int:
        """Align an address to the specified boundary."""
        if alignment <= 1:
            return address
        return (address + alignment - 1) & ~(alignment - 1)

    def get_allocations(self) -> list[CodeCaveAllocation]:
        """Get all allocations made."""
        return self._allocations.copy()

    def get_total_injected_size(self) -> int:
        """Get total size of all injected code."""
        return sum(a.size for a in self._allocations)

    def get_created_sections(self) -> dict[str, int]:
        """Get addresses of created sections."""
        return self._created_sections.copy()

    def clear_allocations(self) -> None:
        """Clear all allocation tracking."""
        self._allocations.clear()
        self._created_sections.clear()

    def inject_with_trampolines(
        self,
        code_bytes: bytes,
        trampoline_sites: list[int],
        original_destinations: list[int],
        preferred_section: str | None = None,
    ) -> CodeCaveAllocation | None:
        """
        Inject code with trampoline connections.

        Args:
            code_bytes: Code to inject
            trampoline_sites: Addresses where trampolines should be placed
            original_destinations: Original addresses to trampoline to
            preferred_section: Preferred section for injection

        Returns:
            CodeCaveAllocation or None
        """
        arch_info = self.binary.get_arch_info()
        arch = arch_info.get("arch", "")
        bits = arch_info.get("bits", 64)

        allocation = self.insert_code(
            code_bytes,
            preferred_section=preferred_section,
            allow_section_creation=True,
        )

        if not allocation:
            return None

        trampolines_written = 0
        for i, site in enumerate(trampoline_sites):
            if i >= len(original_destinations):
                break

            dest = original_destinations[i]
            allocation.address + (i * self._get_jmp_size(bits))

            jmp_bytes = self._create_trampoline_jump(site, dest, arch, bits)

            if jmp_bytes:
                if self.binary.write_bytes(site, jmp_bytes):
                    trampolines_written += 1
                    logger.debug(f"Wrote trampoline at 0x{site:x} -> 0x{dest:x}")
                else:
                    logger.warning(f"Failed to write trampoline at 0x{site:x}")

        if trampolines_written < len(trampoline_sites):
            logger.warning(f"Only wrote {trampolines_written}/{len(trampoline_sites)} trampolines")

        allocation.metadata["trampolines_written"] = trampolines_written
        return allocation

    def _get_jmp_size(self, bits: int) -> int:
        """Get size of a jump instruction."""
        return 5 if bits == 64 else 5

    def _create_trampoline_jump(self, from_addr: int, to_addr: int, arch: str, bits: int) -> bytes | None:
        """
        Create a jump instruction for trampolining.

        Args:
            from_addr: Address of the jump instruction
            to_addr: Target address
            arch: Architecture (x86, x86_64, arm, arm64)
            bits: Bit width (32 or 64)

        Returns:
            Jump instruction bytes or None if jump is out of range
        """
        if "x86" in arch or arch == "x86_64":
            relative_offset = to_addr - (from_addr + 5)

            # Validate that offset fits in signed 32-bit integer
            if relative_offset < -2147483648 or relative_offset > 2147483647:
                logger.error(
                    f"Jump offset out of range: from=0x{from_addr:x} to=0x{to_addr:x}, offset={relative_offset}"
                )
                return None

            return b"\xe9" + relative_offset.to_bytes(4, "little", signed=True)

        return None
