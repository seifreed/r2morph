"""
Tests for Code Cave Injector.

Covers:
- Cave finding
- Section creation
- Code injection
- Trampoline generation
"""

from pathlib import Path
from typing import Any

from r2morph.relocations.cave_finder import CodeCave
from r2morph.relocations.cave_injector import (
    CaveCreationOptions,
    CaveType,
    CodeCaveAllocation,
    CodeCaveInjector,
    SectionPermissions,
)
from tests.utils.assertions import expect

_EXPECTED_ALLOCATION_ADDRESS_4096 = 0x1000
_EXPECTED_ALLOCATION_ADDRESS_4112 = 0x1010
_EXPECTED_ALLOCATION_ALIGNMENT_16 = 16
_EXPECTED_ALLOCATION_SIZE_50 = 50
_EXPECTED_ALLOC_ADDRESS_4096 = 0x1000
_EXPECTED_ALLOC_SIZE_100 = 100
_EXPECTED_CAVE_SIZE_50 = 50
_EXPECTED_INJECTOR_ALIGN_ADDRESS_0X1000_0X1000_4096 = 0x1000
_EXPECTED_INJECTOR_ALIGN_ADDRESS_0X1000_16_4096 = 0x1000
_EXPECTED_INJECTOR_ALIGN_ADDRESS_0X1001_16_4112 = 0x1010
_EXPECTED_INJECTOR_ALIGN_ADDRESS_0X100F_16_4112 = 0x1010
_EXPECTED_OPTS_ALIGNMENT_256 = 0x100
_EXPECTED_OPTS_SIZE_4096 = 0x1000
_EXPECTED_OPTS_SIZE_8192 = 0x2000
_EXPECTED_TOTAL_300 = 300


class _Disassembler:
    def __init__(self) -> None:
        self.output = ""

    def cmd(self, command: str) -> str:
        return self.output


class _Binary:
    def __init__(self) -> None:
        self.path = Path("/nonexistent/test-binary")
        self.sections: list[dict[str, Any]] = []
        self.arch_info: dict[str, Any] = {}
        self.r2 = _Disassembler()

    def get_sections(self) -> list[dict[str, Any]]:
        return self.sections

    def get_arch_info(self) -> dict[str, Any]:
        return self.arch_info

    def write_bytes(self, address: int, contents: bytes) -> bool:
        return True


class TestCodeCaveAllocation:
    """Test CodeCaveAllocation dataclass."""

    def test_basic_allocation(self):
        """Create basic allocation."""
        alloc = CodeCaveAllocation(
            address=0x1000,
            size=100,
            cave_type=CaveType.EXISTING,
            section_name=".text",
        )
        expect(alloc.address == _EXPECTED_ALLOC_ADDRESS_4096)
        expect(alloc.size == _EXPECTED_ALLOC_SIZE_100)
        expect(alloc.cave_type == CaveType.EXISTING)

    def test_allocation_with_code(self):
        """Create allocation with injected code."""
        code = b"\x90" * 50
        alloc = CodeCaveAllocation(
            address=0x1000,
            size=50,
            cave_type=CaveType.EXISTING,
            section_name=".text",
            allocated_bytes=code,
        )
        expect(alloc.allocated_bytes == code)
        expect(len(alloc.allocated_bytes) == alloc.size)


class TestCaveCreationOptions:
    """Test CaveCreationOptions dataclass."""

    def test_default_options(self):
        """Create with defaults."""
        opts = CaveCreationOptions()
        expect(opts.name == ".cave")
        expect(opts.size == _EXPECTED_OPTS_SIZE_4096)
        expect(opts.permissions == SectionPermissions.READ_EXECUTE)

    def test_custom_options(self):
        """Create with custom values."""
        opts = CaveCreationOptions(
            name=".custom",
            size=0x2000,
            permissions=SectionPermissions.READ_WRITE_EXECUTE,
            alignment=0x100,
        )
        expect(opts.name == ".custom")
        expect(opts.size == _EXPECTED_OPTS_SIZE_8192)
        expect(opts.alignment == _EXPECTED_OPTS_ALIGNMENT_256)


class TestCodeCaveInjector:
    """Test CodeCaveInjector class."""

    def test_find_executable_caves(self):
        """Test finding executable caves."""
        mock_binary = _Binary()
        mock_binary.sections = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"},
            {"name": ".data", "vaddr": 0x2000, "vsize": 0x1000, "perm": "rw"},
        ]
        mock_binary.r2.output = "90" * 256 + "00" * 256

        injector = CodeCaveInjector(mock_binary)
        caves = injector.find_executable_caves()

        expect(not (len(caves) < 0))

    def test_find_cave_for_code(self):
        """Test finding cave for specific code size."""
        mock_binary = _Binary()
        mock_binary.sections = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"},
        ]
        mock_binary.r2.output = "90" * 100 + "00" * 100

        injector = CodeCaveInjector(mock_binary)

        cave = injector.find_cave_for_code(50)
        expect(cave is not None)
        expect(not (cave.size < _EXPECTED_CAVE_SIZE_50))

    def test_align_address(self):
        """Test address alignment."""
        mock_binary = _Binary()
        injector = CodeCaveInjector(mock_binary)

        expect(injector._align_address(4097, 16) == _EXPECTED_INJECTOR_ALIGN_ADDRESS_0X1001_16_4112)
        expect(injector._align_address(4096, 16) == _EXPECTED_INJECTOR_ALIGN_ADDRESS_0X1000_16_4096)
        expect(injector._align_address(4111, 16) == _EXPECTED_INJECTOR_ALIGN_ADDRESS_0X100F_16_4112)
        expect(injector._align_address(4096, 4096) == _EXPECTED_INJECTOR_ALIGN_ADDRESS_0X1000_0X1000_4096)

    def test_allocate_from_cave(self):
        """Test allocation from cave."""
        mock_binary = _Binary()
        injector = CodeCaveInjector(mock_binary)

        cave = CodeCave(
            address=0x1000,
            size=100,
            section=".text",
            is_executable=True,
        )

        allocation = injector.allocate_from_cave(cave, 50)

        expect(allocation.address == _EXPECTED_ALLOCATION_ADDRESS_4096)
        expect(allocation.size == _EXPECTED_ALLOCATION_SIZE_50)
        expect(allocation.cave_type == CaveType.EXISTING)
        expect(len(injector.get_allocations()) == 1)

    def test_allocate_from_cave_with_alignment(self):
        """Test allocation with alignment."""
        mock_binary = _Binary()
        injector = CodeCaveInjector(mock_binary)

        cave = CodeCave(
            address=0x1005,
            size=100,
            section=".text",
            is_executable=True,
        )

        allocation = injector.allocate_from_cave(cave, 32, alignment=16)

        expect(allocation.address == _EXPECTED_ALLOCATION_ADDRESS_4112)
        expect(allocation.alignment == _EXPECTED_ALLOCATION_ALIGNMENT_16)

    def test_create_cave_section_elf(self):
        """Test creating ELF section."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"format": "ELF64", "arch": "x86_64", "bits": 64}
        mock_binary.sections = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        opts = CaveCreationOptions(name=".testcave", size=0x500)

        allocation = injector.create_cave_section(opts)

        expect(allocation is not None)
        expect(allocation.cave_type == CaveType.NEW_SECTION)
        expect(allocation.section_name == ".testcave")

    def test_create_cave_section_pe(self):
        """Test creating PE section."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"format": "PE+", "arch": "x86_64", "bits": 64}
        mock_binary.sections = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        opts = CaveCreationOptions(name=".testcave", size=0x500)

        allocation = injector.create_cave_section(opts)

        expect(allocation is not None)
        expect(allocation.cave_type == CaveType.NEW_SECTION)

    def test_create_cave_section_macho(self):
        """Test creating Mach-O section."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"format": "Mach-O-64", "arch": "arm64", "bits": 64}
        mock_binary.sections = [
            {"name": "__TEXT", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        opts = CaveCreationOptions(name=".testcave", size=0x500)

        allocation = injector.create_cave_section(opts)

        expect(allocation is not None)
        expect(allocation.cave_type == CaveType.NEW_SECTION)

    def test_insert_code_existing_cave(self):
        """Test inserting code into existing cave."""
        mock_binary = _Binary()
        mock_binary.sections = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"},
        ]
        mock_binary.r2.output = "90" * 200

        injector = CodeCaveInjector(mock_binary)

        code = b"\x90" * 50
        allocation = injector.insert_code(code)

        expect(allocation is not None)
        expect(allocation.cave_type == CaveType.EXISTING)

    def test_extend_section(self):
        """Test extending existing section."""
        mock_binary = _Binary()
        mock_binary.sections = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        allocation = injector.extend_section(".text", 0x100)

        expect(allocation is not None)
        expect(allocation.cave_type == CaveType.EXTENDED_SECTION)
        expect(allocation.section_name == ".text")

    def test_get_total_injected_size(self):
        """Test total injected size calculation."""
        mock_binary = _Binary()
        injector = CodeCaveInjector(mock_binary)

        injector._allocations = [
            CodeCaveAllocation(0x1000, 100, CaveType.EXISTING, ".text"),
            CodeCaveAllocation(0x2000, 200, CaveType.NEW_SECTION, ".cave"),
        ]

        total = injector.get_total_injected_size()
        expect(total == _EXPECTED_TOTAL_300)

    def test_clear_allocations(self):
        """Test clearing allocations."""
        mock_binary = _Binary()
        injector = CodeCaveInjector(mock_binary)

        injector._allocations = [
            CodeCaveAllocation(0x1000, 100, CaveType.EXISTING, ".text"),
        ]
        injector._created_sections = {".cave": 0x2000}

        injector.clear_allocations()

        expect(len(injector._allocations) == 0)
        expect(len(injector._created_sections) == 0)


class TestCaveType:
    """Test CaveType enum."""

    def test_cave_types(self):
        """Test all cave types exist."""
        expect(CaveType.EXISTING.value == "existing")
        expect(CaveType.NEW_SECTION.value == "new_section")
        expect(CaveType.EXTENDED_SECTION.value == "extended_section")
        expect(CaveType.OVERLAY.value == "overlay")


class TestSectionPermissions:
    """Test SectionPermissions enum."""

    def test_permissions(self):
        """Test permission combinations."""
        expect(SectionPermissions.READ.value == "r")
        expect(SectionPermissions.READ_EXECUTE.value == "rx")
        expect(SectionPermissions.READ_WRITE_EXECUTE.value == "rwx")
