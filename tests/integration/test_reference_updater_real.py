"""
Real integration tests for ReferenceUpdater using dataset binaries.
"""

import shutil
from pathlib import Path

import pytest
import importlib.util

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)



from r2morph.core.binary import Binary
from r2morph.relocations.reference_updater import ReferenceType, ReferenceUpdater


class TestReferenceUpdaterReal:
    """Real tests for ReferenceUpdater."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "macho_arm64"

    def test_updater_initialization(self, ls_elf):
        """Test ReferenceUpdater initialization with real binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            assert updater.binary == binary
            assert isinstance(updater.updated_refs, set)
            assert len(updater.updated_refs) == 0

    def test_find_references_to_function(self, ls_elf):
        """Test finding references to a function."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Get first function
            functions = binary.get_functions()
            if len(functions) > 1:
                target_addr = functions[1].get("offset", functions[1].get("addr", 0))
                if target_addr:
                    refs = updater.find_references_to(target_addr)
                    assert isinstance(refs, list)

    def test_find_references_to_main(self, ls_elf):
        """Test finding references to main function."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Find main function
            functions = binary.get_functions()
            main_addr = None
            for func in functions:
                if func.get("name") == "main":
                    main_addr = func.get("offset", func.get("addr", 0))
                    break

            if main_addr:
                refs = updater.find_references_to(main_addr)
                assert isinstance(refs, list)

    def test_update_jump_target_real(self, ls_elf, tmp_path):
        """Test updating jump target with real binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_jump_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Find a function with jumps
            functions = binary.get_functions()
            for func in functions[:10]:
                func_addr = func.get("offset", func.get("addr", 0))
                if not func_addr:
                    continue

                disasm = binary.get_function_disasm(func_addr)
                for insn in disasm:
                    if insn.get("type") in ["jmp", "cjmp"]:
                        jump_addr = insn.get("offset")
                        jump_target = insn.get("jump", 0)

                        if jump_addr and jump_target:
                            # Try to update (may fail if instruction can't be modified)
                            result = updater.update_jump_target(
                                jump_addr, jump_target, jump_target + 10
                            )
                            # Just check it doesn't crash
                            assert isinstance(result, bool)
                            return  # Test one jump and exit

    def test_update_call_target_real(self, ls_elf, tmp_path):
        """Test updating call target with real binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_call_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Find a function with calls
            functions = binary.get_functions()
            for func in functions[:10]:
                func_addr = func.get("offset", func.get("addr", 0))
                if not func_addr:
                    continue

                disasm = binary.get_function_disasm(func_addr)
                for insn in disasm:
                    if insn.get("type") == "call":
                        call_addr = insn.get("offset")
                        call_target = insn.get("jump", 0)

                        if call_addr and call_target:
                            # Try to update (may fail if instruction can't be modified)
                            result = updater.update_call_target(
                                call_addr, call_target, call_target + 10
                            )
                            # Just check it doesn't crash
                            assert isinstance(result, bool)
                            return  # Test one call and exit

    def test_update_data_pointer_with_arch_detection(self, ls_elf, tmp_path):
        """Test updating data pointer with automatic arch detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_ptr_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Get architecture info
            arch_info = binary.get_arch_info()
            arch_info["bits"] // 8

            # Try to update a data pointer (will likely fail, but shouldn't crash)
            # Using an address in the binary
            test_addr = 0x1000
            result = updater.update_data_pointer(test_addr, 0x0, 0x1000)
            assert isinstance(result, bool)

    def test_update_data_pointer_with_size(self, ls_elf, tmp_path):
        """Test updating data pointer with explicit size."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_ptr_size_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Try with explicit pointer size
            test_addr = 0x1000
            result = updater.update_data_pointer(test_addr, 0x0, 0x1000, ptr_size=8)
            assert isinstance(result, bool)

    def test_update_all_references_to(self, ls_elf, tmp_path):
        """Test updating all references to an address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_all_refs_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Find a function that's called
            functions = binary.get_functions()
            if len(functions) > 5:
                target_addr = functions[5].get("offset", functions[5].get("addr", 0))
                if target_addr:
                    # Try to update all references
                    updated_count = updater.update_all_references_to(
                        target_addr, target_addr + 0x100
                    )
                    assert isinstance(updated_count, int)
                    assert updated_count >= 0

    def test_reference_type_enum(self):
        """Test ReferenceType enum."""
        assert ReferenceType.CALL.value == "call"
        assert ReferenceType.JUMP.value == "jump"
        assert ReferenceType.DATA_PTR.value == "data_ptr"
        assert ReferenceType.RELATIVE.value == "relative"
        assert ReferenceType.ABSOLUTE.value == "absolute"

    def test_updated_refs_tracking(self, ls_elf, tmp_path):
        """Test that updated_refs set tracks updates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_refs_tracking_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            initial_count = len(updater.updated_refs)
            assert initial_count == 0

            # Try some updates (they may fail, but that's okay)
            test_addr = 0x1000
            updater.update_jump_target(test_addr, 0x2000, 0x3000)
            updater.update_call_target(test_addr + 0x10, 0x2000, 0x3000)
            updater.update_data_pointer(test_addr + 0x20, 0x0, 0x1000)

            # Check that updated_refs is still a set
            assert isinstance(updater.updated_refs, set)

    def test_macos_binary_references(self, ls_macos, tmp_path):
        """Test reference updates with macOS binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        # Copy binary to tmp_path
        temp_binary = tmp_path / "ls_macos_refs_test"
        shutil.copy(ls_macos, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Find references to main
            functions = binary.get_functions()
            main_addr = None
            for func in functions:
                if func.get("name") == "main" or func.get("name") == "_main":
                    main_addr = func.get("offset", func.get("addr", 0))
                    break

            if main_addr:
                refs = updater.find_references_to(main_addr)
                assert isinstance(refs, list)

    def test_find_references_empty(self, ls_elf):
        """Test finding references to non-existent address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Try to find references to a likely non-existent address
            refs = updater.find_references_to(0xDEADBEEF)
            assert isinstance(refs, list)

    def test_update_jump_invalid_address(self, ls_elf, tmp_path):
        """Test updating jump at invalid address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_invalid_jump_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Try to update jump at invalid address
            result = updater.update_jump_target(0xDEADBEEF, 0x1000, 0x2000)
            assert result is False

    def test_update_call_invalid_address(self, ls_elf, tmp_path):
        """Test updating call at invalid address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_invalid_call_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Try to update call at invalid address
            result = updater.update_call_target(0xDEADBEEF, 0x1000, 0x2000)
            assert result is False

    def test_update_pointer_invalid_address(self, ls_elf, tmp_path):
        """Test updating pointer at invalid address."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_invalid_ptr_test"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            # Try to update pointer at invalid address
            result = updater.update_data_pointer(0xDEADBEEF, 0x0, 0x1000)
            assert result is False