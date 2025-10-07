"""
Real integration tests for NopInsertionPass using dataset binaries.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass


class TestNopInsertionPassReal:
    """Real tests for NopInsertionPass."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_nop_insertion_basic(self, ls_elf, tmp_path):
        """Test basic NOP insertion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_basic"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 5, "probability": 1.0})

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_nop_insertion_creative_nops(self, ls_elf, tmp_path):
        """Test NOP insertion with creative NOPs."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_creative"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(
                config={"max_nops_per_function": 3, "probability": 1.0, "use_creative_nops": True}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_nop_insertion_low_probability(self, ls_elf, tmp_path):
        """Test NOP insertion with low probability."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_low_prob"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 5, "probability": 0.1})

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_nop_insertion_max_nops(self, ls_elf, tmp_path):
        """Test NOP insertion with different max NOPs."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        for max_nops in [1, 3, 5, 10]:
            temp_binary = tmp_path / f"ls_nop_max{max_nops}"
            shutil.copy(ls_elf, temp_binary)

            with Binary(temp_binary, writable=True) as binary:
                binary.analyze()

                pass_obj = NopInsertionPass(
                    config={"max_nops_per_function": max_nops, "probability": 1.0}
                )

                result = pass_obj.apply(binary)
                assert isinstance(result, dict)

    def test_nop_insertion_force_different(self, ls_elf, tmp_path):
        """Test NOP insertion with force_different flag."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_force"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(
                config={
                    "max_nops_per_function": 5,
                    "probability": 1.0,
                    "force_different": True,
                }
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_nop_insertion_single_function(self, ls_elf, tmp_path):
        """Test NOP insertion on single function."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_single"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 3, "probability": 1.0})

            # Get first function
            functions = binary.get_functions()
            if len(functions) > 0:
                func = functions[0]
                func_addr = func.get("offset", func.get("addr", 0))

                if func_addr:
                    result = pass_obj.apply(binary)
                    assert isinstance(result, dict)

    def test_nop_insertion_zero_probability(self, ls_elf, tmp_path):
        """Test NOP insertion with zero probability."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_zero"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 5, "probability": 0.0})

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert result.get("mutations_applied", 0) == 0

    def test_nop_insertion_with_analysis(self, ls_elf, tmp_path):
        """Test NOP insertion with full analysis."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_analyzed"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 5, "probability": 0.5})

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_nop_insertion_multiple_runs(self, ls_elf, tmp_path):
        """Test NOP insertion multiple times."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_multiple"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0})

            # Run multiple times
            for _i in range(3):
                result = pass_obj.apply(binary)
                assert isinstance(result, dict)
