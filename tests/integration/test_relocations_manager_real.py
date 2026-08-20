"""
Real integration tests for RelocationManager using dataset binaries.
"""

import importlib.util
import shutil
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph.core.binary import Binary
from r2morph.relocations.manager import Relocation, RelocationManager

_EXPECTED_LEN_MANAGER_ADDRESS_MAP_3 = 3
_EXPECTED_LEN_MANAGER_RELOCATIONS_3 = 3
_EXPECTED_MANAGER_ADDRESS_MAP_0X1000_8192 = 0x2000
_EXPECTED_MANAGER_ADDRESS_MAP_0X3000_16384 = 0x4000
_EXPECTED_MANAGER_ADDRESS_MAP_12288 = 0x3000
_EXPECTED_MANAGER_ADDRESS_MAP_4096 = 0x1000
_EXPECTED_MANAGER_RELOCATIONS_0_NEW_ADDRESS_8192 = 0x2000
_EXPECTED_MANAGER_RELOCATIONS_0_OLD_ADDRESS_4096 = 0x1000
_EXPECTED_MANAGER_RELOCATIONS_0_SIZE_64 = 64
_EXPECTED_NEW_ADDR_8192 = 0x2000
_EXPECTED_NEW_ADDR_8224 = 0x2020
_EXPECTED_RELOC_NEW_ADDRESS_8192 = 0x2000
_EXPECTED_RELOC_OFFSET_4096 = 0x1000
_EXPECTED_RELOC_OFFSET_NEG__4096 = -0x1000
_EXPECTED_RELOC_OLD_ADDRESS_4096 = 0x1000
_EXPECTED_RELOC_SIZE_128 = 128


class TestRelocationManagerReal:
    """Real tests for RelocationManager."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_manager_initialization(self, ls_elf):
        """Test RelocationManager initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            expect(manager.binary == binary)
            expect(isinstance(manager.relocations, list))
            expect(len(manager.relocations) == 0)
            expect(isinstance(manager.address_map, dict))
            expect(len(manager.address_map) == 0)

    def test_add_relocation(self, ls_elf):
        """Test adding a relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            expect(len(manager.relocations) == 1)
            expect(manager.relocations[0].old_address == _EXPECTED_MANAGER_RELOCATIONS_0_OLD_ADDRESS_4096)
            expect(manager.relocations[0].new_address == _EXPECTED_MANAGER_RELOCATIONS_0_NEW_ADDRESS_8192)
            expect(manager.relocations[0].size == _EXPECTED_MANAGER_RELOCATIONS_0_SIZE_64)
            expect(manager.relocations[0].relocation_type == "move")

    def test_relocation_dataclass(self):
        """Test Relocation dataclass."""
        reloc = Relocation(0x1000, 0x2000, 128, "move")

        expect(reloc.old_address == _EXPECTED_RELOC_OLD_ADDRESS_4096)
        expect(reloc.new_address == _EXPECTED_RELOC_NEW_ADDRESS_8192)
        expect(reloc.size == _EXPECTED_RELOC_SIZE_128)
        expect(reloc.relocation_type == "move")
        expect(reloc.offset() == _EXPECTED_RELOC_OFFSET_4096)

    def test_relocation_negative_offset(self):
        """Test Relocation with negative offset."""
        reloc = Relocation(0x2000, 0x1000, 64, "move")

        expect(reloc.offset() == _EXPECTED_RELOC_OFFSET_NEG__4096)

    def test_get_new_address_exact_match(self, ls_elf):
        """Test getting new address with exact match."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            new_addr = manager.get_new_address(0x1000)
            expect(new_addr == _EXPECTED_NEW_ADDR_8192)

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
            expect(new_addr == _EXPECTED_NEW_ADDR_8224)

    def test_get_new_address_not_relocated(self, ls_elf):
        """Test getting new address for non-relocated address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            new_addr = manager.get_new_address(0x3000)
            expect(not (new_addr is not None))

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

            expect(len(manager.relocations) == _EXPECTED_LEN_MANAGER_RELOCATIONS_3)
            expect(len(manager.address_map) == _EXPECTED_LEN_MANAGER_ADDRESS_MAP_3)

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
            expect(isinstance(xrefs, list))

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
            expect(isinstance(updated, int))
            expect(not (updated < 0))

    def test_address_map_consistency(self, ls_elf):
        """Test that address_map stays consistent with relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            manager.add_relocation(0x3000, 0x4000, 128, "move")

            expect(not (_EXPECTED_MANAGER_ADDRESS_MAP_4096 not in manager.address_map))
            expect(not (_EXPECTED_MANAGER_ADDRESS_MAP_12288 not in manager.address_map))
            expect(manager.address_map[4096] == _EXPECTED_MANAGER_ADDRESS_MAP_0X1000_8192)
            expect(manager.address_map[12288] == _EXPECTED_MANAGER_ADDRESS_MAP_0X3000_16384)

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

            expect(manager.relocations[0].relocation_type == "move")
            expect(manager.relocations[1].relocation_type == "copy")
            expect(manager.relocations[2].relocation_type == "expand")

    def test_has_relocation(self, ls_elf):
        """Test checking if address has relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")

            # Check if has relocation using get_new_address
            expect(manager.get_new_address(0x1000) is not None)
            expect(not (manager.get_new_address(0x9000) is not None))
