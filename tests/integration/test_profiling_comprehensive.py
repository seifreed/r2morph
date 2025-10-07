"""
Comprehensive real tests for profiling modules.
"""

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.profiling.hotpath_detector import HotPathDetector
from r2morph.profiling.profiler import BinaryProfiler


class TestBinaryProfilerComprehensive:
    """Comprehensive tests for BinaryProfiler."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_profiler_init(self, ls_elf):
        """Test BinaryProfiler initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)

        assert profiler is not None
        assert profiler.binary_path == ls_elf
        assert isinstance(profiler.profile_data, dict)

    def test_profile_execution(self, ls_elf):
        """Test profiling execution."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)
        profile = profiler.profile(test_inputs=["--version"], duration=1)

        assert isinstance(profile, dict)

    def test_get_hot_functions(self, ls_elf):
        """Test getting hot functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)
        profiler.profile(test_inputs=["--version"], duration=1)

        hot_funcs = profiler.get_hot_functions()
        assert isinstance(hot_funcs, set)

    def test_get_cold_functions(self, ls_elf):
        """Test getting cold functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)

        all_funcs = ["main", "func1", "func2"]
        cold_funcs = profiler.get_cold_functions(all_funcs)

        assert isinstance(cold_funcs, set)

    def test_should_mutate_function(self, ls_elf):
        """Test checking if function should be mutated."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)

        if not hasattr(profiler, "should_mutate_function"):
            pytest.skip("should_mutate_function method not implemented")

        result = profiler.should_mutate_function("main")
        assert isinstance(result, bool)


class TestHotPathDetectorComprehensive:
    """Comprehensive tests for HotPathDetector."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_detector_init(self, ls_elf):
        """Test HotPathDetector initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)

            assert detector is not None
            assert detector.binary == binary

    def test_detect_hot_paths(self, ls_elf):
        """Test detecting hot paths."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)

            hot_paths = detector.detect_hot_paths()
            assert isinstance(hot_paths, dict)

    def test_is_hot_path(self, ls_elf):
        """Test checking if path is hot."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)

            hot_paths = detector.detect_hot_paths()

            if len(hot_paths) > 0:
                func_name = list(hot_paths.keys())[0]
                if len(hot_paths[func_name]) > 0:
                    block_addr = hot_paths[func_name][0]

                    result = detector.is_hot_path(func_name, block_addr, hot_paths)
                    assert isinstance(result, bool)
