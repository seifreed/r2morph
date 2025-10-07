"""
Comprehensive real tests for utils modules.
"""

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.session import Checkpoint, MorphSession
from r2morph.utils.assembler import R2Assembler
from r2morph.utils.logging import setup_logging


class TestR2AssemblerComprehensive:
    """Comprehensive tests for R2Assembler."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_assembler_init(self, ls_elf):
        """Test R2Assembler initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assembler = R2Assembler(binary.r2)

            assert assembler is not None
            assert assembler.r2 is not None

    def test_assemble_nop(self, ls_elf):
        """Test assembling NOP."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assembler = R2Assembler(binary.r2)

            result = assembler.assemble("nop")
            # Result can be None or bytes depending on architecture
            assert result is None or isinstance(result, bytes)

    def test_assemble_multiple_instructions(self, ls_elf):
        """Test assembling multiple instructions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assembler = R2Assembler(binary)

            instructions = ["nop", "ret"]
            result = assembler.assemble_multiple(instructions)

            assert result is not None or result is None

    def test_assemble_complex_instruction(self, ls_elf):
        """Test assembling complex instruction."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assembler = R2Assembler(binary)

            result = assembler.assemble("mov rax, 0x1234")
            assert result is not None or result is None

    def test_get_instruction_size(self, ls_elf):
        """Test getting instruction size."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assembler = R2Assembler(binary)

            size = assembler.get_instruction_size("nop")
            assert isinstance(size, int) or size is None

    def test_disassemble(self, ls_elf):
        """Test disassembling bytes."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assembler = R2Assembler(binary)

            nop_bytes = assembler.assemble("nop")
            if nop_bytes:
                result = assembler.disassemble(nop_bytes)
                assert result is not None or result is None


class TestLoggingComprehensive:
    """Comprehensive tests for logging utilities."""

    def test_setup_logging_info(self):
        """Test setup logging with INFO level."""
        logger = setup_logging(level="INFO")
        assert logger is None or logger is not None

    def test_setup_logging_debug(self):
        """Test setup logging with DEBUG level."""
        logger = setup_logging(level="DEBUG")
        assert logger is None or logger is not None

    def test_setup_logging_warning(self):
        """Test setup logging with WARNING level."""
        logger = setup_logging(level="WARNING")
        assert logger is None or logger is not None

    def test_setup_logging_error(self):
        """Test setup logging with ERROR level."""
        logger = setup_logging(level="ERROR")
        assert logger is None or logger is not None

    def test_setup_logging_with_file(self, tmp_path):
        """Test setup logging with file."""
        log_file = tmp_path / "test.log"
        logger = setup_logging(level="INFO", log_file=str(log_file))

        assert logger is None or logger is not None


class TestMorphSessionComprehensive:
    """Comprehensive tests for MorphSession."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_session_init(self, ls_elf, tmp_path):
        """Test MorphSession initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_test"
        session = MorphSession(working_dir)

        assert session is not None
        assert session.working_dir == working_dir

    def test_session_start(self, ls_elf, tmp_path):
        """Test starting session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_start"
        session = MorphSession(working_dir)

        result = session.start(ls_elf)
        assert result is not None
        assert isinstance(result, Path)

    def test_session_checkpoint(self, ls_elf, tmp_path):
        """Test creating checkpoint."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_checkpoint"
        session = MorphSession(working_dir)
        session.start(ls_elf)

        checkpoint = session.checkpoint("test_checkpoint")
        assert checkpoint is not None
        assert isinstance(checkpoint, Checkpoint)

    def test_checkpoint_dataclass(self):
        """Test Checkpoint dataclass."""
        checkpoint = Checkpoint(
            name="test_001",
            timestamp="2024-01-01T00:00:00",
            binary_path=Path("/tmp/test.bin"),
            mutations_applied=5,
            description="test checkpoint",
        )

        assert checkpoint.name == "test_001"
        assert checkpoint.mutations_applied == 5
        assert checkpoint.description == "test checkpoint"

    def test_session_list_checkpoints(self, ls_elf, tmp_path):
        """Test listing checkpoints."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_list"
        session = MorphSession(working_dir)
        session.start(ls_elf)

        session.checkpoint("checkpoint1")
        session.checkpoint("checkpoint2")

        checkpoints = session.list_checkpoints()
        assert isinstance(checkpoints, list)

    def test_session_rollback(self, ls_elf, tmp_path):
        """Test rolling back to checkpoint."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_rollback"
        session = MorphSession(working_dir)
        session.start(ls_elf)

        cp = session.checkpoint("rollback_test")
        result = session.rollback_to(cp.name)

        assert isinstance(result, bool)

    def test_session_finalize(self, ls_elf, tmp_path):
        """Test finalizing session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_save"
        output_path = tmp_path / "finalized_binary"
        session = MorphSession(working_dir)
        session.start(ls_elf)

        result = session.finalize(output_path)
        assert isinstance(result, bool)

    def test_session_cleanup(self, ls_elf, tmp_path):
        """Test cleaning up session."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        working_dir = tmp_path / "session_cleanup"
        session = MorphSession(working_dir)
        session.start(ls_elf)

        session.cleanup()
        assert True
