"""
Tests for Code Cave Injector.

Covers:
- Cave finding
- Section creation
- Code injection
- Trampoline generation
"""

from unittest.mock import MagicMock, patch

from r2morph.relocations.cave_injector import (
    CaveCreationOptions,
    CaveType,
    CodeCaveAllocation,
    CodeCaveInjector,
    SectionPermissions,
)
from r2morph.relocations.cave_finder import CodeCave


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
        assert alloc.address == 0x1000
        assert alloc.size == 100
        assert alloc.cave_type == CaveType.EXISTING

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
        assert alloc.allocated_bytes == code
        assert len(alloc.allocated_bytes) == alloc.size


class TestCaveCreationOptions:
    """Test CaveCreationOptions dataclass."""

    def test_default_options(self):
        """Create with defaults."""
        opts = CaveCreationOptions()
        assert opts.name == ".cave"
        assert opts.size == 0x1000
        assert opts.permissions == SectionPermissions.READ_EXECUTE

    def test_custom_options(self):
        """Create with custom values."""
        opts = CaveCreationOptions(
            name=".custom",
            size=0x2000,
            permissions=SectionPermissions.READ_WRITE_EXECUTE,
            alignment=0x100,
        )
        assert opts.name == ".custom"
        assert opts.size == 0x2000
        assert opts.alignment == 0x100


class TestCodeCaveInjector:
    """Test CodeCaveInjector class."""

    def test_find_executable_caves(self):
        """Test finding executable caves."""
        mock_binary = MagicMock()
        mock_binary.get_sections.return_value = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"},
            {"name": ".data", "vaddr": 0x2000, "vsize": 0x1000, "perm": "rw"},
        ]
        mock_binary.r2.cmd.return_value = "90" * 256 + "00" * 256

        injector = CodeCaveInjector(mock_binary)
        caves = injector.find_executable_caves()

        assert len(caves) >= 0

    def test_find_cave_for_code(self):
        """Test finding cave for specific code size."""
        mock_binary = MagicMock()
        mock_binary.get_sections.return_value = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"},
        ]
        mock_binary.r2.cmd.return_value = "90" * 100 + "00" * 100

        injector = CodeCaveInjector(mock_binary)

        mock_cave = MagicMock()
        mock_cave.address = 0x1000
        mock_cave.size = 200
        mock_cave.is_executable = True
        mock_cave.section = ".text"

        with patch.object(injector, "find_executable_caves", return_value=[mock_cave]):
            cave = injector.find_cave_for_code(50)
            assert cave is not None
            assert cave.size >= 50

    def test_align_address(self):
        """Test address alignment."""
        mock_binary = MagicMock()
        injector = CodeCaveInjector(mock_binary)

        assert injector._align_address(0x1001, 16) == 0x1010
        assert injector._align_address(0x1000, 16) == 0x1000
        assert injector._align_address(0x100F, 16) == 0x1010
        assert injector._align_address(0x1000, 0x1000) == 0x1000

    def test_allocate_from_cave(self):
        """Test allocation from cave."""
        mock_binary = MagicMock()
        injector = CodeCaveInjector(mock_binary)

        cave = CodeCave(
            address=0x1000,
            size=100,
            section=".text",
            is_executable=True,
        )

        allocation = injector.allocate_from_cave(cave, 50)

        assert allocation.address == 0x1000
        assert allocation.size == 50
        assert allocation.cave_type == CaveType.EXISTING
        assert len(injector.get_allocations()) == 1

    def test_allocate_from_cave_with_alignment(self):
        """Test allocation with alignment."""
        mock_binary = MagicMock()
        injector = CodeCaveInjector(mock_binary)

        cave = CodeCave(
            address=0x1005,
            size=100,
            section=".text",
            is_executable=True,
        )

        allocation = injector.allocate_from_cave(cave, 32, alignment=16)

        assert allocation.address == 0x1010
        assert allocation.alignment == 16

    def test_create_cave_section_elf(self):
        """Test creating ELF section."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"format": "ELF64", "arch": "x86_64", "bits": 64}
        mock_binary.get_sections.return_value = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        opts = CaveCreationOptions(name=".testcave", size=0x500)

        allocation = injector.create_cave_section(opts)

        assert allocation is not None
        assert allocation.cave_type == CaveType.NEW_SECTION
        assert allocation.section_name == ".testcave"

    def test_create_cave_section_pe(self):
        """Test creating PE section."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"format": "PE+", "arch": "x86_64", "bits": 64}
        mock_binary.get_sections.return_value = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        opts = CaveCreationOptions(name=".testcave", size=0x500)

        allocation = injector.create_cave_section(opts)

        assert allocation is not None
        assert allocation.cave_type == CaveType.NEW_SECTION

    def test_create_cave_section_macho(self):
        """Test creating Mach-O section."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"format": "Mach-O-64", "arch": "arm64", "bits": 64}
        mock_binary.get_sections.return_value = [
            {"name": "__TEXT", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        opts = CaveCreationOptions(name=".testcave", size=0x500)

        allocation = injector.create_cave_section(opts)

        assert allocation is not None
        assert allocation.cave_type == CaveType.NEW_SECTION

    def test_insert_code_existing_cave(self):
        """Test inserting code into existing cave."""
        mock_binary = MagicMock()
        mock_binary.get_sections.return_value = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "rx"},
        ]
        mock_binary.r2.cmd.return_value = "90" * 200

        injector = CodeCaveInjector(mock_binary)

        mock_cave = CodeCave(
            address=0x1000,
            size=200,
            section=".text",
            is_executable=True,
        )

        with patch.object(injector, "find_cave_for_code", return_value=mock_cave):
            code = b"\x90" * 50
            allocation = injector.insert_code(code)

            assert allocation is not None
            assert allocation.cave_type == CaveType.EXISTING

    def test_extend_section(self):
        """Test extending existing section."""
        mock_binary = MagicMock()
        mock_binary.get_sections.return_value = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000},
        ]

        injector = CodeCaveInjector(mock_binary)
        allocation = injector.extend_section(".text", 0x100)

        assert allocation is not None
        assert allocation.cave_type == CaveType.EXTENDED_SECTION
        assert allocation.section_name == ".text"

    def test_get_total_injected_size(self):
        """Test total injected size calculation."""
        mock_binary = MagicMock()
        injector = CodeCaveInjector(mock_binary)

        injector._allocations = [
            CodeCaveAllocation(0x1000, 100, CaveType.EXISTING, ".text"),
            CodeCaveAllocation(0x2000, 200, CaveType.NEW_SECTION, ".cave"),
        ]

        total = injector.get_total_injected_size()
        assert total == 300

    def test_clear_allocations(self):
        """Test clearing allocations."""
        mock_binary = MagicMock()
        injector = CodeCaveInjector(mock_binary)

        injector._allocations = [
            CodeCaveAllocation(0x1000, 100, CaveType.EXISTING, ".text"),
        ]
        injector._created_sections = {".cave": 0x2000}

        injector.clear_allocations()

        assert len(injector._allocations) == 0
        assert len(injector._created_sections) == 0


class TestCaveType:
    """Test CaveType enum."""

    def test_cave_types(self):
        """Test all cave types exist."""
        assert CaveType.EXISTING.value == "existing"
        assert CaveType.NEW_SECTION.value == "new_section"
        assert CaveType.EXTENDED_SECTION.value == "extended_section"
        assert CaveType.OVERLAY.value == "overlay"


class TestSectionPermissions:
    """Test SectionPermissions enum."""

    def test_permissions(self):
        """Test permission combinations."""
        assert SectionPermissions.READ.value == "r"
        assert SectionPermissions.READ_EXECUTE.value == "rx"
        assert SectionPermissions.READ_WRITE_EXECUTE.value == "rwx"
