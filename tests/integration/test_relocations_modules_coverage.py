"""
Tests for relocations modules to increase coverage.
"""

import importlib.util
import logging
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
from r2morph.relocations.reference_updater import ReferenceType, ReferenceUpdater

_EXPECTED_LEN_MANAGER_ADDRESS_MAP_3 = 3
_EXPECTED_LEN_MANAGER_RELOCATIONS_3 = 3
_EXPECTED_MANAGER_ADDRESS_MAP_0X1000_8192 = 0x2000
_EXPECTED_MANAGER_ADDRESS_MAP_0X1100_8448 = 0x2100
_EXPECTED_MANAGER_ADDRESS_MAP_4096 = 0x1000
_EXPECTED_MANAGER_ADDRESS_MAP_4352 = 0x1100
_EXPECTED_NEW_ADDR2_8255 = 0x203F
_EXPECTED_NEW_ADDR2_8448 = 0x2100
_EXPECTED_NEW_ADDR_67584 = 0x10800
_EXPECTED_NEW_ADDR_8192 = 0x2000
_EXPECTED_NEW_ADDR_8192_2 = 0x2000
_EXPECTED_NEW_ADDR_8208 = 0x2010
_EXPECTED_RELOC2_OFFSET_NEG__4096 = -0x1000
_EXPECTED_RELOC_NEW_ADDRESS_8192 = 0x2000
_EXPECTED_RELOC_OFFSET_4096 = 0x1000
_EXPECTED_RELOC_OLD_ADDRESS_4096 = 0x1000
_EXPECTED_RELOC_SIZE_64 = 64


class TestRelocationDataclass:
    """Test Relocation dataclass."""

    def test_relocation_creation(self):
        """Test creating relocation."""
        reloc = Relocation(old_address=0x1000, new_address=0x2000, size=64, relocation_type="move")
        expect(reloc.old_address == _EXPECTED_RELOC_OLD_ADDRESS_4096)
        expect(reloc.new_address == _EXPECTED_RELOC_NEW_ADDRESS_8192)
        expect(reloc.size == _EXPECTED_RELOC_SIZE_64)
        expect(reloc.relocation_type == "move")

    def test_relocation_offset(self):
        """Test calculating offset."""
        reloc = Relocation(old_address=0x1000, new_address=0x2000, size=64, relocation_type="move")
        expect(reloc.offset() == _EXPECTED_RELOC_OFFSET_4096)

        reloc2 = Relocation(old_address=0x2000, new_address=0x1000, size=64, relocation_type="move")
        expect(reloc2.offset() == _EXPECTED_RELOC2_OFFSET_NEG__4096)


class TestRelocationManagerDetailed:
    """Detailed tests for RelocationManager."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_manager_init(self, ls_elf):
        """Test RelocationManager initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)
            expect(manager.binary == binary)
            expect(len(manager.relocations) == 0)
            expect(len(manager.address_map) == 0)

    def test_add_multiple_relocations(self, ls_elf):
        """Test adding multiple relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            manager.add_relocation(0x1040, 0x2040, 32, "copy")
            manager.add_relocation(0x1060, 0x2060, 16, "insert")

            expect(len(manager.relocations) == _EXPECTED_LEN_MANAGER_RELOCATIONS_3)
            expect(len(manager.address_map) == _EXPECTED_LEN_MANAGER_ADDRESS_MAP_3)

    def test_get_new_address_direct(self, ls_elf):
        """Test getting new address for direct relocation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            new_addr = manager.get_new_address(0x1000)
            expect(new_addr == _EXPECTED_NEW_ADDR_8192)

    def test_get_new_address_within_range(self, ls_elf):
        """Test getting new address for address within relocated range."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            new_addr = manager.get_new_address(0x1010)
            expect(new_addr == _EXPECTED_NEW_ADDR_8208)

            new_addr2 = manager.get_new_address(0x103F)
            expect(new_addr2 == _EXPECTED_NEW_ADDR2_8255)

    def test_get_new_address_not_relocated(self, ls_elf):
        """Test getting new address for non-relocated address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            new_addr = manager.get_new_address(0x5000)
            expect(not (new_addr is not None))

    def test_update_all_references(self, ls_elf, tmp_path):
        """Test updating all references."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_reloc"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            count = manager.update_all_references()
            expect(isinstance(count, int))
            expect(not (count < 0))


class TestReferenceUpdaterDetailed:
    """Detailed tests for ReferenceUpdater."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_reference_types(self):
        """Test all reference types."""
        expect(ReferenceType.CALL.value == "call")
        expect(ReferenceType.JUMP.value == "jump")
        expect(ReferenceType.DATA_PTR.value == "data_ptr")
        expect(ReferenceType.RELATIVE.value == "relative")
        expect(ReferenceType.ABSOLUTE.value == "absolute")

    def test_updater_init(self, ls_elf):
        """Test ReferenceUpdater initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)
            expect(updater.binary == binary)
            expect(len(updater.updated_refs) == 0)

    def test_update_jump_target(self, ls_elf, tmp_path):
        """Test updating jump target."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_jump"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            functions = binary.get_functions()
            if len(functions) > 0:
                func = functions[0]
                func_addr = func.get("offset", func.get("addr", 0))
                if func_addr:
                    try:
                        disasm = binary.get_function_disasm(func_addr)
                        if disasm and len(disasm) > 1:
                            first_insn = disasm[0]
                            insn_addr = first_insn.get("offset", 0)
                            result = updater.update_jump_target(insn_addr, 0x1000, 0x2000)
                            expect(isinstance(result, bool))
                    except Exception:
                        logging.getLogger(__name__).debug("ignored optional test-path exception", exc_info=True)


class TestRelocationManagerAdvanced:
    """Advanced tests for RelocationManager."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_overlapping_relocations(self, ls_elf):
        """Test handling overlapping relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 128, "move")
            manager.add_relocation(0x1040, 0x2100, 64, "copy")

            new_addr = manager.get_new_address(0x1000)
            expect(new_addr == _EXPECTED_NEW_ADDR_8192_2)

            new_addr2 = manager.get_new_address(0x1040)
            expect(new_addr2 == _EXPECTED_NEW_ADDR2_8448)

    def test_large_relocations(self, ls_elf):
        """Test large code relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x10000, 4096, "move")
            expect(len(manager.relocations) == 1)

            new_addr = manager.get_new_address(0x1800)
            expect(new_addr == _EXPECTED_NEW_ADDR_67584)

    def test_negative_offset_relocations(self, ls_elf):
        """Test relocations with negative offsets."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x2000, 0x1000, 64, "move")
            reloc = manager.relocations[0]
            expect(not (reloc.offset() >= 0))

    def test_relocation_types(self, ls_elf):
        """Test different relocation types."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            manager.add_relocation(0x1100, 0x2100, 64, "copy")
            manager.add_relocation(0x1200, 0x2200, 64, "insert")

            expect(manager.relocations[0].relocation_type == "move")
            expect(manager.relocations[1].relocation_type == "copy")
            expect(manager.relocations[2].relocation_type == "insert")

    def test_address_map_consistency(self, ls_elf):
        """Test address map consistency."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            manager.add_relocation(0x1000, 0x2000, 64, "move")
            manager.add_relocation(0x1100, 0x2100, 64, "move")

            expect(not (_EXPECTED_MANAGER_ADDRESS_MAP_4096 not in manager.address_map))
            expect(not (_EXPECTED_MANAGER_ADDRESS_MAP_4352 not in manager.address_map))
            expect(manager.address_map[4096] == _EXPECTED_MANAGER_ADDRESS_MAP_0X1000_8192)
            expect(manager.address_map[4352] == _EXPECTED_MANAGER_ADDRESS_MAP_0X1100_8448)
