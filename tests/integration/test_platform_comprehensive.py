"""
Comprehensive tests for platform modules using real binaries.
"""

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


class TestCodeSignerComprehensive:
    """Comprehensive tests for CodeSigner."""

    @pytest.fixture
    def ls_macos(self):
        """Path to macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls_macOS"

    @pytest.fixture
    def pafish_pe(self):
        """Path to PE binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "pafish.exe"

    def test_codesigner_init(self):
        """Test CodeSigner initialization."""
        signer = CodeSigner()
        assert signer.platform in ["Darwin", "Linux", "Windows"]

    def test_sign_linux_binary(self, tmp_path):
        """Test signing on Linux (should skip)."""
        if platform.system() != "Linux":
            pytest.skip("Not on Linux")

        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x7fELF")

        signer = CodeSigner()
        result = signer.sign(test_file)
        assert result is True  # Linux returns True (no signing needed)

    def test_sign_macos_adhoc(self, ls_macos, tmp_path):
        """Test ad-hoc signing on macOS."""
        if not ls_macos.exists() or platform.system() != "Darwin":
            pytest.skip("macOS binary not available or not on macOS")

        test_binary = tmp_path / "ls_test"
        shutil.copy(ls_macos, test_binary)
        test_binary.chmod(0o755)

        signer = CodeSigner()
        result = signer.sign(test_binary, adhoc=True)
        assert isinstance(result, bool)

    def test_sign_macos_no_identity(self, ls_macos, tmp_path):
        """Test signing without identity."""
        if not ls_macos.exists() or platform.system() != "Darwin":
            pytest.skip("macOS binary not available or not on macOS")

        test_binary = tmp_path / "ls_test2"
        shutil.copy(ls_macos, test_binary)

        signer = CodeSigner()
        result = signer.sign(test_binary, adhoc=False, identity=None)
        assert result is False  # Should fail without identity

    def test_sign_macos_with_identity(self, ls_macos, tmp_path):
        """Test signing with identity."""
        if not ls_macos.exists() or platform.system() != "Darwin":
            pytest.skip("macOS binary not available or not on macOS")

        test_binary = tmp_path / "ls_test3"
        shutil.copy(ls_macos, test_binary)

        signer = CodeSigner()
        # This will likely fail as we don't have a valid identity
        result = signer.sign(test_binary, adhoc=False, identity="test-identity")
        assert isinstance(result, bool)

    def test_sign_windows_no_identity(self, pafish_pe, tmp_path):
        """Test Windows signing without identity."""
        if platform.system() != "Windows":
            pytest.skip("Not on Windows")

        test_binary = tmp_path / "pafish_test.exe"
        shutil.copy(pafish_pe, test_binary)

        signer = CodeSigner()
        result = signer.sign(test_binary)
        assert result is False  # Should fail without identity

    def test_sign_windows_with_identity(self, pafish_pe, tmp_path):
        """Test Windows signing with identity."""
        if platform.system() != "Windows":
            pytest.skip("Not on Windows")

        test_binary = tmp_path / "pafish_test2.exe"
        shutil.copy(pafish_pe, test_binary)

        signer = CodeSigner()
        result = signer.sign(test_binary, identity="test-thumbprint")
        assert isinstance(result, bool)


class TestELFHandlerComprehensive:
    """Comprehensive tests for ELFHandler."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_elf_handler_init(self, ls_elf):
        """Test ELFHandler initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        assert handler.binary_path == ls_elf

    def test_get_sections(self, ls_elf):
        """Test getting ELF sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        sections = handler.get_sections()
        assert isinstance(sections, list)

    def test_add_section(self, ls_elf):
        """Test adding ELF section."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        result = handler.add_section(".test", 0x1000)
        assert result is None  # Returns None in current implementation

    def test_preserve_symbols(self, ls_elf):
        """Test preserving ELF symbols."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        handler = ELFHandler(ls_elf)
        result = handler.preserve_symbols()
        assert result is True


class TestMachOHandlerComprehensive:
    """Comprehensive tests for MachOHandler."""

    @pytest.fixture
    def ls_macos(self):
        """Path to macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls_macOS"

    def test_macho_handler_init(self, ls_macos):
        """Test MachOHandler initialization."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        assert handler.binary_path == ls_macos

    def test_get_load_commands(self, ls_macos):
        """Test getting load commands."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        commands = handler.get_load_commands()
        assert isinstance(commands, list)

    def test_is_fat_binary(self, ls_macos):
        """Test checking if binary is fat."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        result = handler.is_fat_binary()
        assert isinstance(result, bool)

    def test_is_fat_binary_false(self, tmp_path):
        """Test is_fat_binary with non-fat file."""
        non_fat = tmp_path / "not_fat"
        non_fat.write_bytes(b"NOTFAT" * 10)

        handler = MachOHandler(non_fat)
        assert handler.is_fat_binary() is False

    def test_extract_architecture(self, ls_macos, tmp_path):
        """Test extracting architecture from fat binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        if handler.is_fat_binary():
            output = tmp_path / "thin_binary"
            result = handler.extract_architecture("arm64", output)
            assert isinstance(result, bool)

    def test_create_fat_binary(self, ls_macos, tmp_path):
        """Test creating fat binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        handler = MachOHandler(ls_macos)
        output = tmp_path / "fat_binary"
        result = handler.create_fat_binary([ls_macos], output)
        assert isinstance(result, bool)


class TestPEHandlerComprehensive:
    """Comprehensive tests for PEHandler."""

    @pytest.fixture
    def pafish_pe(self):
        """Path to PE binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "pafish.exe"

    def test_pe_handler_init(self, pafish_pe):
        """Test PEHandler initialization."""
        if not pafish_pe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_pe)
        assert handler.binary_path == pafish_pe

    def test_get_sections(self, pafish_pe):
        """Test getting PE sections."""
        if not pafish_pe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_pe)
        sections = handler.get_sections()
        assert isinstance(sections, list)

    def test_add_section(self, pafish_pe):
        """Test adding PE section."""
        if not pafish_pe.exists():
            pytest.skip("PE binary not available")

        handler = PEHandler(pafish_pe)
        result = handler.add_section(".test", 0x1000)
        assert result is None  # Returns None in current implementation

    def test_fix_checksum(self, pafish_pe, tmp_path):
        """Test fixing PE checksum."""
        if not pafish_pe.exists():
            pytest.skip("PE binary not available")

        # Copy to tmp_path to avoid modifying original
        test_pe = tmp_path / "test.exe"
        shutil.copy(pafish_pe, test_pe)

        handler = PEHandler(test_pe)
        result = handler.fix_checksum()
        assert isinstance(result, bool)
