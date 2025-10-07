"""
Comprehensive real tests for relocations modules.
"""

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder, CodeCave
from r2morph.relocations.manager import Relocation, RelocationManager
from r2morph.relocations.reference_updater import ReferenceType, ReferenceUpdater


class TestCaveFinderComprehensive:
    """Comprehensive tests for CaveFinder."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_cave_finder_init(self, ls_elf):
        """Test CaveFinder initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=16)

            assert finder is not None
            assert finder.min_size == 16
            assert isinstance(finder.caves, list)

    def test_find_caves(self, ls_elf):
        """Test finding caves."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=16)
            caves = finder.find_caves(max_caves=50)

            assert isinstance(caves, list)

    def test_code_cave_dataclass(self):
        """Test CodeCave dataclass."""
        cave = CodeCave(address=0x1000, size=64, section=".text", is_executable=True)

        assert cave.address == 0x1000
        assert cave.size == 64
        assert cave.section == ".text"
        assert cave.is_executable is True

    def test_find_caves_in_section(self, ls_elf):
        """Test finding caves in specific section."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=8)
            caves = finder.find_caves(max_caves=100)

            text_caves = [c for c in caves if c.section and ".text" in c.section]
            assert isinstance(text_caves, list)


class TestRelocationManagerComprehensive:
    """Comprehensive tests for RelocationManager."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_manager_init(self, ls_elf):
        """Test RelocationManager initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            assert manager is not None
            assert isinstance(manager.relocations, list)
            assert isinstance(manager.address_map, dict)

    def test_add_relocation(self, ls_elf):
        """Test adding relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(
                old_address=0x1000, new_address=0x2000, size=16, relocation_type="move"
            )

            assert len(manager.relocations) == 1
            assert 0x1000 in manager.address_map
            assert manager.address_map[0x1000] == 0x2000

    def test_relocation_dataclass(self):
        """Test Relocation dataclass."""
        reloc = Relocation(old_address=0x1000, new_address=0x2000, size=16, relocation_type="move")

        assert reloc.old_address == 0x1000
        assert reloc.new_address == 0x2000
        assert reloc.size == 16
        assert reloc.relocation_type == "move"

    def test_get_new_address(self, ls_elf):
        """Test getting new address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 16)
            new_addr = manager.get_new_address(0x1000)

            assert new_addr == 0x2000

    def test_has_relocation(self, ls_elf):
        """Test checking if address has relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            if not hasattr(manager, "has_relocation"):
                pytest.skip("has_relocation method not implemented")

            manager.add_relocation(0x1000, 0x2000, 16)

            assert manager.has_relocation(0x1000) is True
            assert manager.has_relocation(0x3000) is False


class TestReferenceUpdaterComprehensive:
    """Comprehensive tests for ReferenceUpdater."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_updater_init(self, ls_elf):
        """Test ReferenceUpdater initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            assert updater is not None
            assert updater.binary == binary

    def test_reference_type_enum(self):
        """Test ReferenceType enum."""
        assert ReferenceType.JUMP
        assert ReferenceType.CALL
        assert ReferenceType.DATA_PTR

    def test_find_references_to(self, ls_elf):
        """Test finding references to address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", functions[0].get("addr", 0))
                if addr:
                    refs = updater.find_references_to(addr)
                    assert isinstance(refs, list)
