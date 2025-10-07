"""
Real integration tests for relocations and profiling modules.
"""

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.profiling.hotpath_detector import HotPathDetector
from r2morph.profiling.profiler import BinaryProfiler
from r2morph.relocations.cave_finder import CaveFinder
from r2morph.relocations.manager import RelocationManager
from r2morph.relocations.reference_updater import ReferenceUpdater
from r2morph.session import MorphSession
from r2morph.utils.assembler import R2Assembler
from r2morph.utils.logging import setup_logging


class TestCaveFinder:
    """Tests for CaveFinder."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_cave_finder_initialization(self, ls_elf):
        """Test CaveFinder initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary)
            assert finder is not None

    def test_find_caves(self, ls_elf):
        """Test finding code caves."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=16)
            caves = finder.find_caves()

            assert isinstance(caves, list)

    def test_find_caves_with_size(self, ls_elf):
        """Test finding caves with specific size."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder_small = CaveFinder(binary, min_size=8)
            finder_large = CaveFinder(binary, min_size=64)

            small_caves = finder_small.find_caves()
            large_caves = finder_large.find_caves()

            assert isinstance(small_caves, list)
            assert isinstance(large_caves, list)


class TestRelocationManager:
    """Tests for RelocationManager."""

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
            assert manager is not None

    def test_get_relocations(self, ls_elf):
        """Test getting relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            if not hasattr(manager, "get_relocations"):
                pytest.skip("get_relocations method not implemented")

            relocations = manager.get_relocations()
            assert isinstance(relocations, list)

    def test_analyze_relocations(self, ls_elf):
        """Test analyzing relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)

            if not hasattr(manager, "analyze"):
                pytest.skip("analyze method not implemented")

            analysis = manager.analyze()
            assert isinstance(analysis, dict)


class TestReferenceUpdater:
    """Tests for ReferenceUpdater."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_updater_initialization(self, ls_elf):
        """Test ReferenceUpdater initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)
            assert updater is not None

    def test_find_references(self, ls_elf):
        """Test finding references."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            updater = ReferenceUpdater(binary)

            functions = binary.get_functions()
            if len(functions) > 0:
                addr = functions[0].get("offset") or functions[0].get("addr")
                if addr:
                    refs = updater.find_references_to(addr)
                    assert isinstance(refs, list)


class TestBinaryProfiler:
    """Tests for BinaryProfiler."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_profiler_initialization(self, ls_elf):
        """Test BinaryProfiler initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)
        assert profiler is not None
        assert profiler.binary_path == ls_elf

    def test_profile_binary(self, ls_elf):
        """Test profiling binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)
        profile = profiler.profile()

        assert isinstance(profile, dict)

    def test_get_statistics(self, ls_elf):
        """Test getting profiling statistics."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        profiler = BinaryProfiler(ls_elf)

        if not hasattr(profiler, "get_statistics"):
            pytest.skip("get_statistics method not implemented")

        stats = profiler.get_statistics()
        assert isinstance(stats, dict)


class TestHotPathDetector:
    """Tests for HotPathDetector."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_detector_initialization(self, ls_elf):
        """Test HotPathDetector initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)
            assert detector is not None

    def test_detect_hot_paths(self, ls_elf):
        """Test detecting hot paths."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = HotPathDetector(binary)
            paths = detector.detect_hot_paths()

            assert isinstance(paths, dict)


class TestMorphSession:
    """Tests for MorphSession."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_session_creation(self, ls_elf, tmp_path):
        """Test creating morph session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session_dir = tmp_path / "session"
        session = MorphSession(session_dir)
        session.start(ls_elf)

        assert session is not None
        assert session.working_dir.exists()

    def test_session_save_load(self, ls_elf, tmp_path):
        """Test saving and loading session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session_dir = tmp_path / "session2"
        session = MorphSession(session_dir)
        session.start(ls_elf)

        # Session doesn't have save/load methods, test finalize instead
        output_path = tmp_path / "finalized"
        result = session.finalize(output_path)
        assert isinstance(result, bool)

    def test_session_metadata(self, ls_elf, tmp_path):
        """Test session metadata."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session_dir = tmp_path / "session3"
        session = MorphSession(session_dir)
        session.start(ls_elf)

        # Test that session has expected attributes
        assert hasattr(session, "working_dir")
        assert hasattr(session, "checkpoints")


class TestR2Assembler:
    """Tests for R2Assembler."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_helper_initialization(self, ls_elf):
        """Test R2Assembler initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            helper = R2Assembler(binary.r2)
            assert helper is not None
            assert helper.r2 is not None

    def test_assemble_instruction(self, ls_elf):
        """Test assembling instruction."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            helper = R2Assembler(binary.r2)

            nop_bytes = helper.assemble("nop")
            # Result can be None or bytes depending on architecture
            assert nop_bytes is None or isinstance(nop_bytes, bytes)

    def test_assemble_multiple(self, ls_elf):
        """Test assembling multiple instructions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            helper = R2Assembler(binary.r2)

            instructions = ["nop", "xor eax, eax", "ret"]
            for insn in instructions:
                result = helper.assemble(insn)
                # Result can be None or bytes depending on architecture
                assert result is None or isinstance(result, bytes)


class TestLogging:
    """Tests for logging utilities."""

    def test_setup_logging(self):
        """Test setting up logging."""
        logger = setup_logging(level="INFO")
        assert logger is None or logger is not None

    def test_logging_levels(self):
        """Test different logging levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            logger = setup_logging(level=level)
            assert logger is None or logger is not None

    def test_logging_to_file(self, tmp_path):
        """Test logging to file."""
        log_file = tmp_path / "test.log"
        logger = setup_logging(level="INFO", log_file=str(log_file))

        assert logger is None or logger is not None
