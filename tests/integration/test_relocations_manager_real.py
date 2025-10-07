"""
Real integration tests for RelocationManager using dataset binaries.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.manager import Relocation, RelocationManager


class TestRelocationManagerReal:
    """Real tests for RelocationManager."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_manager_initialization(self, ls_elf):
        """Test RelocationManager initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            assert manager.binary == binary
            assert isinstance(manager.relocations, list)
            assert len(manager.relocations) == 0
            assert isinstance(manager.address_map, dict)
            assert len(manager.address_map) == 0

    def test_add_relocation(self, ls_elf):
        """Test adding a relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            assert len(manager.relocations) == 1
            assert manager.relocations[0].old_address == 0x1000
            assert manager.relocations[0].new_address == 0x2000
            assert manager.relocations[0].size == 64
            assert manager.relocations[0].relocation_type == "move"

    def test_relocation_dataclass(self):
        """Test Relocation dataclass."""
        reloc = Relocation(0x1000, 0x2000, 128, "move")

        assert reloc.old_address == 0x1000
        assert reloc.new_address == 0x2000
        assert reloc.size == 128
        assert reloc.relocation_type == "move"
        assert reloc.offset() == 0x1000

    def test_relocation_negative_offset(self):
        """Test Relocation with negative offset."""
        reloc = Relocation(0x2000, 0x1000, 64, "move")

        assert reloc.offset() == -0x1000

    def test_get_new_address_exact_match(self, ls_elf):
        """Test getting new address with exact match."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            new_addr = manager.get_new_address(0x1000)
            assert new_addr == 0x2000

    def test_get_new_address_within_range(self, ls_elf):
        """Test getting new address within relocated range."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 128, "move")

            # Address within relocated range
            new_addr = manager.get_new_address(0x1020)
            assert new_addr == 0x2020

    def test_get_new_address_not_relocated(self, ls_elf):
        """Test getting new address for non-relocated address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            new_addr = manager.get_new_address(0x3000)
            assert new_addr is None

    def test_multiple_relocations(self, ls_elf):
        """Test adding multiple relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x5000, 64, "move")
            manager.add_relocation(0x2000, 0x6000, 128, "move")
            manager.add_relocation(0x3000, 0x7000, 256, "copy")

            assert len(manager.relocations) == 3
            assert len(manager.address_map) == 3

    def test_find_all_xrefs(self, ls_elf, tmp_path):
        """Test finding all cross-references."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_xrefs_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            xrefs = manager._find_all_xrefs()
            assert isinstance(xrefs, list)

    def test_update_all_references(self, ls_elf, tmp_path):
        """Test updating all references."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_update_refs_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            # Add a relocation
            functions = binary.get_functions()
            if len(functions) > 0:
                func_addr = functions[0].get("offset", functions[0].get("addr", 0))
                if func_addr:
                    manager.add_relocation(func_addr, func_addr + 0x1000, 128, "move")

            # Try to update references (may or may not find any)
            updated = manager.update_all_references()
            assert isinstance(updated, int)
            assert updated >= 0

    def test_address_map_consistency(self, ls_elf):
        """Test that address_map stays consistent with relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            manager.add_relocation(0x3000, 0x4000, 128, "move")

            assert 0x1000 in manager.address_map
            assert 0x3000 in manager.address_map
            assert manager.address_map[0x1000] == 0x2000
            assert manager.address_map[0x3000] == 0x4000

    def test_relocation_types(self, ls_elf):
        """Test different relocation types."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            manager.add_relocation(0x3000, 0x4000, 128, "copy")
            manager.add_relocation(0x5000, 0x6000, 256, "expand")

            assert manager.relocations[0].relocation_type == "move"
            assert manager.relocations[1].relocation_type == "copy"
            assert manager.relocations[2].relocation_type == "expand"

    def test_has_relocation(self, ls_elf):
        """Test checking if address has relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            # Check if has relocation using get_new_address
            assert manager.get_new_address(0x1000) is not None
            assert manager.get_new_address(0x9000) is None
