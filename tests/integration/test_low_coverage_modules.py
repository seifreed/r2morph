"""
Comprehensive tests for modules with low coverage using real binaries.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.profiling.hotpath_detector import HotPathDetector
from r2morph.profiling.profiler import BinaryProfiler
from r2morph.session import MorphSession


class TestControlFlowFlatteningReal:
    """Real tests for ControlFlowFlatteningPass."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_flatten_basic(self, ls_elf, tmp_path):
        """Test basic control flow flattening."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_flatten"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = ControlFlowFlatteningPass(
                config={"max_functions_to_flatten": 1, "probability": 1.0}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_flatten_multiple_functions(self, ls_elf, tmp_path):
        """Test flattening multiple functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_flatten_multi"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = ControlFlowFlatteningPass(
                config={"max_functions_to_flatten": 3, "probability": 1.0}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_flatten_low_probability(self, ls_elf, tmp_path):
        """Test flattening with low probability."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_flatten_low"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = ControlFlowFlatteningPass(
                config={"max_functions_to_flatten": 2, "probability": 0.1}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)


class TestDeadCodeInjectionReal:
    """Real tests for DeadCodeInjectionPass."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_inject_basic(self, ls_elf, tmp_path):
        """Test basic dead code injection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_dead_basic"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = DeadCodeInjectionPass(
                config={"max_injections_per_function": 5, "probability": 1.0}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_inject_different_patterns(self, ls_elf, tmp_path):
        """Test different dead code patterns."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_dead_patterns"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = DeadCodeInjectionPass(
                config={"max_injections_per_function": 10, "probability": 0.8}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_inject_aggressive(self, ls_elf, tmp_path):
        """Test aggressive dead code injection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_dead_aggressive"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = DeadCodeInjectionPass(
                config={"max_injections_per_function": 15, "probability": 0.9}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)


class TestOpaquePredicatesReal:
    """Real tests for OpaquePredicatePass."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_opaque_basic(self, ls_elf, tmp_path):
        """Test basic opaque predicate insertion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_opaque_basic"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = OpaquePredicatePass(
                config={"max_predicates_per_function": 3, "probability": 1.0}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_opaque_multiple_types(self, ls_elf, tmp_path):
        """Test multiple opaque predicate types."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_opaque_multi"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = OpaquePredicatePass(
                config={"max_predicates_per_function": 5, "probability": 0.8}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_opaque_complex(self, ls_elf, tmp_path):
        """Test complex opaque predicates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_opaque_complex"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = OpaquePredicatePass(
                config={"max_predicates_per_function": 2, "probability": 1.0}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)


class TestNopInsertionDetailed:
    """Detailed tests for NopInsertionPass."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_nop_standard(self, ls_elf, tmp_path):
        """Test standard NOP insertion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_std"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = NopInsertionPass(
                config={"max_nops_per_function": 10, "probability": 1.0, "use_creative_nops": False}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_nop_creative(self, ls_elf, tmp_path):
        """Test creative NOP insertion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_nop_creative"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            pass_obj = NopInsertionPass(
                config={"max_nops_per_function": 10, "probability": 1.0, "use_creative_nops": True}
            )
            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_nop_force_different(self, ls_elf, tmp_path):
        """Test NOP insertion with force_different."""
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

    def test_nop_various_counts(self, ls_elf, tmp_path):
        """Test NOP insertion with various counts."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        for count in [1, 5, 10, 20]:
            temp_binary = tmp_path / f"ls_nop_count{count}"
            shutil.copy(ls_elf, temp_binary)

            with Binary(temp_binary, writable=True) as binary:
                binary.analyze()
                pass_obj = NopInsertionPass(
                    config={"max_nops_per_function": count, "probability": 1.0}
                )
                result = pass_obj.apply(binary)
                assert isinstance(result, dict)


class TestProfilingReal:
    """Real tests for profiling modules."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_profiler_basic(self, ls_elf, tmp_path):
        """Test basic profiling."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_profile"
        shutil.copy(ls_elf, temp_binary)
        temp_binary.chmod(0o755)

        profiler = BinaryProfiler(temp_binary)
        result = profiler.profile(duration=1)
        assert isinstance(result, dict)

    def test_profiler_hot_functions(self, ls_elf, tmp_path):
        """Test identifying hot functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_hot"
        shutil.copy(ls_elf, temp_binary)
        temp_binary.chmod(0o755)

        profiler = BinaryProfiler(temp_binary)
        profiler.profile(duration=1)
        hot_funcs = profiler.get_hot_functions()
        assert isinstance(hot_funcs, set)

    def test_profiler_cold_functions(self, ls_elf, tmp_path):
        """Test identifying cold functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_cold"
        shutil.copy(ls_elf, temp_binary)
        temp_binary.chmod(0o755)

        profiler = BinaryProfiler(temp_binary)
        profiler.profile(duration=1)
        cold_funcs = profiler.get_cold_functions(["func1", "func2"])
        assert isinstance(cold_funcs, set)

    def test_hotpath_detector(self, ls_elf):
        """Test hotpath detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)
            hot_paths = detector.detect_hot_paths()
            assert isinstance(hot_paths, dict)

    def test_hotpath_is_hot(self, ls_elf):
        """Test checking if path is hot."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)
            hot_paths = detector.detect_hot_paths()

            # Get first function
            functions = binary.get_functions()
            if len(functions) > 0 and hot_paths:
                func_name = list(hot_paths.keys())[0]
                block_addr = hot_paths[func_name][0] if hot_paths[func_name] else 0
                if block_addr:
                    is_hot = detector.is_hot_path(func_name, block_addr, hot_paths)
                    assert isinstance(is_hot, bool)


class TestSessionReal:
    """Real tests for MorphSession."""

    def test_session_creation(self, tmp_path):
        """Test session creation."""
        session = MorphSession(tmp_path)
        # Session dir is created with timestamp
        assert session.session_dir.parent == tmp_path
        assert session.session_dir.exists()

    def test_session_start(self, tmp_path, ls_elf):
        """Test session start."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session = MorphSession(tmp_path)
        working_copy = session.start(ls_elf)
        assert working_copy.exists()
        assert session.current_binary == working_copy

    def test_session_checkpoint(self, tmp_path, ls_elf):
        """Test creating checkpoints."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session = MorphSession(tmp_path)
        session.start(ls_elf)
        session.checkpoint("test_checkpoint", "Test checkpoint")
        checkpoints = session.list_checkpoints()
        assert len(checkpoints) >= 2  # initial + test_checkpoint

    def test_session_finalize(self, tmp_path, ls_elf):
        """Test finalizing session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session = MorphSession(tmp_path)
        session.start(ls_elf)
        output = tmp_path / "output.bin"
        result = session.finalize(output)
        assert result is True
        assert output.exists()

    def test_session_cleanup(self, tmp_path, ls_elf):
        """Test session cleanup."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session = MorphSession(tmp_path)
        session.start(ls_elf)
        session_dir = session.session_dir
        session.cleanup()
        # Session dir should be cleaned up
        assert not session_dir.exists()

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"
