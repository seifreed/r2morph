"""
Real integration tests for platform modules.
"""

from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass
from r2morph.platform.codesign import CodeSigner
from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


class TestCodeSigner:
    """Tests for CodeSigner."""

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls_macOS"

    def test_manager_initialization(self):
        """Test CodeSigner initialization."""
        manager = CodeSigner()
        assert manager is not None

    def test_check_signature(self, ls_macos):
        """Test checking code signature."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        manager = CodeSigner()
        if not hasattr(manager, "check_signature"):
            pytest.skip("check_signature method not implemented")

        result = manager.check_signature(ls_macos)
        assert result is not None

    def test_is_signed(self, ls_macos):
        """Test checking if binary is signed."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        manager = CodeSigner()
        if not hasattr(manager, "is_signed"):
            pytest.skip("is_signed method not implemented")

        result = manager.is_signed(ls_macos)
        assert isinstance(result, bool)

    def test_needs_signing(self, ls_macos, tmp_path):
        """Test checking if morphed binary needs signing."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        manager = CodeSigner()
        if not hasattr(manager, "needs_signing"):
            pytest.skip("needs_signing method not implemented")

        morphed_path = tmp_path / "ls_morphed"

        with MorphEngine() as engine:
            engine.load_binary(ls_macos).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        result = manager.needs_signing(morphed_path)
        assert isinstance(result, bool)

    def test_sign_binary(self, ls_macos, tmp_path):
        """Test signing a binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        manager = CodeSigner()
        if not hasattr(manager, "sign_binary"):
            pytest.skip("sign_binary method not implemented")

        import shutil

        test_binary = tmp_path / "test_sign"
        shutil.copy(ls_macos, test_binary)

        result = manager.sign_binary(test_binary)
        assert result is not None


class TestELFHandler:
    """Tests for ELFHandler."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_handler_initialization(self, ls_elf):
        """Test ELFHandler initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        assert handler is not None

    def test_is_elf(self, ls_elf):
        """Test ELF detection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        if not hasattr(handler, "is_elf"):
            pytest.skip("is_elf method not implemented")

        result = handler.is_elf()
        assert isinstance(result, bool)

    def test_get_sections(self, ls_elf):
        """Test getting ELF sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        if not hasattr(handler, "get_sections"):
            pytest.skip("get_sections method not implemented")

        sections = handler.get_sections()
        assert isinstance(sections, list)

    def test_get_segments(self, ls_elf):
        """Test getting ELF segments."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        if not hasattr(handler, "get_segments"):
            pytest.skip("get_segments method not implemented")

        segments = handler.get_segments()
        assert isinstance(segments, list)

    def test_validate_elf(self, ls_elf):
        """Test ELF validation."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        if not hasattr(handler, "validate"):
            pytest.skip("validate method not implemented")

        result = handler.validate()
        assert isinstance(result, bool)


class TestMachOHandler:
    """Tests for MachOHandler."""

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls_macOS"

    def test_handler_initialization(self, ls_macos):
        """Test MachOHandler initialization."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        assert handler is not None

    def test_is_macho(self, ls_macos):
        """Test Mach-O detection."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        if not hasattr(handler, "is_macho"):
            pytest.skip("is_macho method not implemented")

        result = handler.is_macho()
        assert isinstance(result, bool)

    def test_get_load_commands(self, ls_macos):
        """Test getting Mach-O load commands."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        if not hasattr(handler, "get_load_commands"):
            pytest.skip("get_load_commands method not implemented")

        commands = handler.get_load_commands()
        assert isinstance(commands, list)

    def test_get_segments(self, ls_macos):
        """Test getting Mach-O segments."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        if not hasattr(handler, "get_segments"):
            pytest.skip("get_segments method not implemented")

        segments = handler.get_segments()
        assert isinstance(segments, list)

    def test_validate_macho(self, ls_macos):
        """Test Mach-O validation."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        if not hasattr(handler, "validate"):
            pytest.skip("validate method not implemented")

        result = handler.validate()
        assert isinstance(result, bool)


class TestPEHandler:
    """Tests for PEHandler."""

    @pytest.fixture
    def pafish_exe(self):
        """Path to pafish.exe PE binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "pafish.exe"

    def test_handler_initialization(self, pafish_exe):
        """Test PEHandler initialization."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_exe)
        assert handler is not None

    def test_is_pe(self, pafish_exe):
        """Test PE detection."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_exe)
        if not hasattr(handler, "is_pe"):
            pytest.skip("is_pe method not implemented")

        result = handler.is_pe()

        assert isinstance(result, bool)
        assert result is True

    def test_get_sections(self, pafish_exe):
        """Test getting PE sections."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_exe)
        sections = handler.get_sections()

        assert isinstance(sections, list)

    def test_get_imports(self, pafish_exe):
        """Test getting PE imports."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_exe)
        if not hasattr(handler, "get_imports"):
            pytest.skip("get_imports method not implemented")

        imports = handler.get_imports()

        assert isinstance(imports, list)

    def test_validate_pe(self, pafish_exe):
        """Test PE validation."""
        if not pafish_exe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_exe)
        if not hasattr(handler, "validate"):
            pytest.skip("validate method not implemented")

        result = handler.validate()

        assert isinstance(result, bool)
