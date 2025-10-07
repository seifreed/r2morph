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
            finder = CaveFinder(binary)
            caves = finder.find_caves(min_size=16)

            assert isinstance(caves, list)

    def test_find_caves_with_size(self, ls_elf):
        """Test finding caves with specific size."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary)

            small_caves = finder.find_caves(min_size=8)
            large_caves = finder.find_caves(min_size=64)

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
            relocations = manager.get_relocations()

            assert isinstance(relocations, list)

    def test_analyze_relocations(self, ls_elf):
        """Test analyzing relocations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            manager = RelocationManager(binary)
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
                    refs = updater.find_references(addr)
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

        with Binary(ls_elf) as binary:
            binary.analyze()
            profiler = BinaryProfiler(binary)
            assert profiler is not None

    def test_profile_binary(self, ls_elf):
        """Test profiling binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            profiler = BinaryProfiler(binary)
            profile = profiler.profile()

            assert isinstance(profile, dict)

    def test_get_statistics(self, ls_elf):
        """Test getting profiling statistics."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            profiler = BinaryProfiler(binary)
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
            paths = detector.detect()

            assert isinstance(paths, list)


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
        session = MorphSession.create(ls_elf, session_dir)

        assert session is not None
        assert session_dir.exists()

    def test_session_save_load(self, ls_elf, tmp_path):
        """Test saving and loading session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session_dir = tmp_path / "session2"
        session = MorphSession.create(ls_elf, session_dir)
        session.save()

        loaded = MorphSession.load(session_dir)
        assert loaded is not None

    def test_session_metadata(self, ls_elf, tmp_path):
        """Test session metadata."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        session_dir = tmp_path / "session3"
        session = MorphSession.create(ls_elf, session_dir)

        metadata = session.get_metadata()
        assert isinstance(metadata, dict)


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
            helper = R2Assembler(binary)
            assert helper is not None

    def test_assemble_instruction(self, ls_elf):
        """Test assembling instruction."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            helper = R2Assembler(binary)

            nop_bytes = helper.assemble("nop")
            assert isinstance(nop_bytes, bytes)
            assert len(nop_bytes) > 0

    def test_assemble_multiple(self, ls_elf):
        """Test assembling multiple instructions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            helper = R2Assembler(binary)

            instructions = ["nop", "xor eax, eax", "ret"]
            for insn in instructions:
                result = helper.assemble(insn)
                assert isinstance(result, bytes)


class TestLogging:
    """Tests for logging utilities."""

    def test_setup_logging(self):
        """Test setting up logging."""
        logger = setup_logging(level="INFO")
        assert logger is not None

    def test_logging_levels(self):
        """Test different logging levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            logger = setup_logging(level=level)
            assert logger is not None

    def test_logging_to_file(self, tmp_path):
        """Test logging to file."""
        log_file = tmp_path / "test.log"
        logger = setup_logging(level="INFO", log_file=str(log_file))

        assert logger is not None
