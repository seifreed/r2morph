"""
Unit tests for MemoryManager (real binaries required).
"""

import importlib.util
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph.core.binary import Binary
from r2morph.core.memory_manager import MemoryManager

_EXPECTED_MANAGER_BATCH_SIZE_3 = 3
_EXPECTED_MANAGER_BATCH_SIZE_5 = 5


class TestMemoryManager:
    """Tests for MemoryManager."""

    def test_counter_and_batch_size(self):
        manager = MemoryManager(batch_size=3)
        expect(manager.mutation_count == 0)
        expect(manager.batch_size == _EXPECTED_MANAGER_BATCH_SIZE_3)

        manager.batch_size = 5
        expect(manager.batch_size == _EXPECTED_MANAGER_BATCH_SIZE_5)

    def test_track_mutation_no_low_memory(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_mm"
        temp_binary.write_bytes(test_file.read_bytes())

        manager = MemoryManager(batch_size=1)
        with Binary(temp_binary, writable=True) as binary:
            binary._low_memory = False
            manager.track_mutation(binary)

        expect(manager.mutation_count == 0)

    def test_track_mutation_with_low_memory(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_mm_low"
        temp_binary.write_bytes(test_file.read_bytes())

        manager = MemoryManager(batch_size=1)
        with Binary(temp_binary, writable=True) as binary:
            binary._low_memory = True
            manager.track_mutation(binary)

        expect(manager.mutation_count == 1)

    def test_force_reload(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_mm_reload"
        temp_binary.write_bytes(test_file.read_bytes())

        manager = MemoryManager(batch_size=1)
        with Binary(temp_binary, writable=True) as binary:
            binary._low_memory = True
            manager.force_reload(binary)

        expect(manager.mutation_count == 0)
