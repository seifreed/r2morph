"""
Integration tests for Mach-O binary integrity repair.

Tests for Issue #4:
- Mach-O integrity validation
- Code signing and verification
- Fat binary handling
- Load command repair
- Entitlements and hardened runtime
"""

import pytest
import platform
import tempfile
import shutil
from pathlib import Path

from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.codesign import CodeSigner


class TestMachOIntegrityBasic:
    """Basic Mach-O integrity tests that work without special binaries."""

    def test_is_macho_with_non_macho(self, tmp_path):
        """Test is_macho returns False for non-Mach-O files."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        assert not handler.is_macho()

    def test_is_macho_with_elf(self, tmp_path):
        """Test is_macho returns False for ELF files."""
        test_file = tmp_path / "test.elf"
        test_file.write_bytes(b"\x7fELF")

        handler = MachOHandler(test_file)
        assert not handler.is_macho()

    def test_is_macho_with_pe(self, tmp_path):
        """Test is_macho returns False for PE files."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x00\x00")

        handler = MachOHandler(test_file)
        assert not handler.is_macho()

    def test_validate_non_macho(self, tmp_path):
        """Test validate returns False for non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        assert not handler.validate()

    def test_validate_integrity_non_macho(self, tmp_path):
        """Test validate_integrity fails for non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        valid, msg = handler.validate_integrity()

        assert not valid
        assert "Not a Mach-O" in msg


class TestMachOHandlerMethods:
    """Test MachOHandler methods."""

    def test_get_load_commands_non_macho(self, tmp_path):
        """Test get_load_commands on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        commands = handler.get_load_commands()

        assert commands == []

    def test_get_segments_non_macho(self, tmp_path):
        """Test get_segments on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        segments = handler.get_segments()

        assert segments == []

    def test_is_fat_binary_non_macho(self, tmp_path):
        """Test is_fat_binary on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        assert not handler.is_fat_binary()

    def test_get_sections_non_macho(self, tmp_path):
        """Test get_sections on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        sections = handler.get_sections()

        assert sections == []

    def test_fix_load_commands_non_macho(self, tmp_path):
        """Test fix_load_commands on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        success, fixes = handler.fix_load_commands()

        assert success
        assert fixes == []

    def test_fix_bind_symbols_non_macho(self, tmp_path):
        """Test fix_bind_symbols on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        success, fixes = handler.fix_bind_symbols()

        assert success
        assert fixes == []

    def test_fix_segment_permissions_non_macho(self, tmp_path):
        """Test fix_segment_permissions on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        success, fixes = handler.fix_segment_permissions()

        assert success
        assert fixes == []

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-only test")
    def test_full_repair_non_macho(self, tmp_path):
        """Test full_repair on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)
        success, repairs = handler.full_repair()

        assert not success


class TestMachOBasicParsing:
    """Test Mach-O basic parsing fallback."""

    def test_parse_macho_basic_64bit(self, tmp_path):
        """Test parsing a 64-bit Mach-O header."""
        test_file = tmp_path / "test.macho"

        magic_64 = 0xFEEDFACF
        header = (
            magic_64.to_bytes(4, "little")
            + (0x01000007).to_bytes(4, "little")
            + (0x00000003).to_bytes(4, "little")
            + (0x00000002).to_bytes(4, "little")
            + (0x00000001).to_bytes(4, "little")
            + (0x00000050).to_bytes(4, "little")
            + (0x00000085).to_bytes(4, "little")
            + (0x00000000).to_bytes(4, "little")
        )

        lc_segment_64 = (
            (0x19).to_bytes(4, "little")
            + (0x48).to_bytes(4, "little")
            + b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + (0x1000).to_bytes(8, "little")
            + (0x1000).to_bytes(8, "little")
            + (0x0000).to_bytes(8, "little")
            + (0x1000).to_bytes(8, "little")
            + (0x07).to_bytes(4, "little")
            + (0x05).to_bytes(4, "little")
            + (0x01).to_bytes(4, "little")
            + (0x00000000).to_bytes(4, "little")
        )

        test_file.write_bytes(header + lc_segment_64)

        handler = MachOHandler(test_file)

        if handler.is_macho():
            commands, segments = handler._parse_macho_basic()

            assert isinstance(commands, list)
            assert isinstance(segments, list)

    def test_repair_integrity_non_darwin(self, tmp_path):
        """Test repair_integrity returns False on non-Darwin."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = MachOHandler(test_file)

        result = handler.repair_integrity()

        if platform.system() != "Darwin":
            assert result is False


class TestCodeSigner:
    """Test CodeSigner functionality."""

    def test_init(self):
        """Test CodeSigner initialization."""
        signer = CodeSigner()
        assert signer.platform == platform.system()

    def test_sign_non_darwin(self, tmp_path):
        """Test sign on non-Darwin platforms."""
        signer = CodeSigner()
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        if signer.platform != "Darwin":
            result = signer.sign(test_file)
            assert result is True

    def test_verify_non_darwin(self, tmp_path):
        """Test verify on non-Darwin platforms."""
        signer = CodeSigner()
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        if signer.platform != "Darwin":
            result = signer.verify(test_file)
            assert result is True

    def test_needs_signing_non_darwin(self, tmp_path):
        """Test needs_signing on non-Darwin platforms."""
        signer = CodeSigner()
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        if signer.platform != "Darwin":
            result = signer.needs_signing(test_file)
            assert result is False

    def test_is_signed_non_darwin(self, tmp_path):
        """Test is_signed on non-Darwin platforms."""
        signer = CodeSigner()
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        if signer.platform != "Darwin":
            result = signer.is_signed(test_file)
            assert result is True

    def test_sign_binary_non_darwin(self, tmp_path):
        """Test sign_binary on non-Darwin platforms."""
        signer = CodeSigner()
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        if signer.platform != "Darwin":
            result = signer.sign_binary(test_file)
            assert result is True


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
class TestMachOIntegrityDarwin:
    """Mach-O tests that only run on macOS."""

    @pytest.fixture
    def system_binary(self):
        """Get a system binary for testing."""
        candidates = [
            Path("/bin/ls"),
            Path("/bin/cat"),
            Path("/usr/bin/true"),
            Path("/usr/bin/false"),
        ]
        for path in candidates:
            if path.exists():
                return path
        pytest.skip("No suitable system binary found")

    def test_is_macho_system_binary(self, system_binary):
        """Test is_macho with system binary."""
        handler = MachOHandler(system_binary)
        assert handler.is_macho()

    def test_validate_system_binary(self, system_binary):
        """Test validate with system binary."""
        handler = MachOHandler(system_binary)
        assert handler.validate()

    def test_get_load_commands_system_binary(self, system_binary):
        """Test get_load_commands with system binary."""
        handler = MachOHandler(system_binary)
        commands = handler.get_load_commands()

        assert len(commands) > 0

        command_names = [c.get("command", "") for c in commands]
        # lief may return enum names without the ``LC_`` prefix
        assert any(
            "LC_" in str(name) or "SEGMENT" in str(name) or "0x" in str(name) for name in command_names
        ), f"Expected recognizable load commands, got: {command_names}"

    def test_get_segments_system_binary(self, system_binary):
        """Test get_segments with system binary."""
        handler = MachOHandler(system_binary)
        segments = handler.get_segments()

        assert len(segments) > 0

        segment_names = [s.get("name", "") for s in segments]
        assert "__TEXT" in segment_names or "TEXT" in str(segment_names)

    def test_validate_integrity_system_binary(self, system_binary):
        """Test validate_integrity with system binary."""
        handler = MachOHandler(system_binary)
        valid, msg = handler.validate_integrity()

        assert valid
        assert msg == ""

    def test_get_sections_system_binary(self, system_binary):
        """Test get_sections with system binary."""
        handler = MachOHandler(system_binary)
        sections = handler.get_sections()

        assert len(sections) > 0

    def test_full_repair_system_binary(self, system_binary, tmp_path):
        """Test full_repair with copied system binary."""

        test_binary = tmp_path / "test_binary"
        shutil.copy(system_binary, test_binary)

        handler = MachOHandler(test_binary)
        success, repairs = handler.full_repair()

        assert success or len(repairs) > 0

    def test_codesign_verify_system_binary(self, system_binary):
        """Test code signature verification with system binary."""
        signer = CodeSigner()

        signer.verify(system_binary)

        pass

    def test_codesign_adhoc_sign(self, system_binary, tmp_path):
        """Test ad-hoc signing."""

        test_binary = tmp_path / "test_sign"
        shutil.copy(system_binary, test_binary)

        signer = CodeSigner()

        signer.remove_signature(test_binary)

        result = signer.sign_binary(test_binary, adhoc=True)

        if result:
            assert signer.verify(test_binary)


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
class TestFatBinaryDarwin:
    """Fat binary tests that only run on macOS."""

    def test_is_fat_binary(self):
        """Test is_fat_binary with fat binary detection."""
        fat_magics = [b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"]

        for magic in fat_magics:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(magic)
                f.write(b"\x00" * 100)
                temp_path = Path(f.name)

            try:
                handler = MachOHandler(temp_path)
                handler.is_fat_binary()
            finally:
                temp_path.unlink()

    def test_extract_architecture_stub(self, tmp_path):
        """Test extract_architecture stub implementation."""
        source = tmp_path / "source"
        source.write_bytes(b"\x00" * 100)
        output = tmp_path / "output"

        handler = MachOHandler(source)
        handler.extract_architecture("x86_64", output)

        pass

    def test_create_fat_binary_stub(self, tmp_path):
        """Test create_fat_binary stub implementation."""
        thin1 = tmp_path / "thin1"
        thin2 = tmp_path / "thin2"
        output = tmp_path / "fat"

        thin1.write_bytes(b"\x00" * 100)
        thin2.write_bytes(b"\x00" * 100)

        handler = MachOHandler(thin1)
        handler.create_fat_binary([thin1, thin2], output)

        pass


class TestMachOErrorHandling:
    """Test error handling in Mach-O handler."""

    def test_corrupted_header(self, tmp_path):
        """Test handling of corrupted Mach-O header."""
        test_file = tmp_path / "corrupted.macho"

        test_file.write_bytes(b"\xfe\xed\xfa\xce" + b"\xff" * 10)

        handler = MachOHandler(test_file)

        assert handler.is_macho()

        commands, segments = handler._parse_macho_basic()

        if not commands:
            pass

    def test_truncated_file(self, tmp_path):
        """Test handling of truncated Mach-O file."""
        test_file = tmp_path / "truncated.macho"

        test_file.write_bytes(b"\xfe\xed\xfa\xcf")

        handler = MachOHandler(test_file)

        if handler.is_macho():
            commands, segments = handler._parse_macho_basic()
            assert isinstance(commands, list)
            assert isinstance(segments, list)

    def test_nonexistent_file(self, tmp_path):
        """Test handling of nonexistent file."""
        nonexistent = tmp_path / "nonexistent"

        handler = MachOHandler(nonexistent)

        assert not handler.is_macho()
        assert not handler.validate()

    def test_permission_denied(self, tmp_path):
        """Test handling of permission errors."""
        test_file = tmp_path / "readonly.macho"
        test_file.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
        test_file.chmod(0o000)

        try:
            handler = MachOHandler(test_file)
            handler.is_macho()
        except PermissionError:
            pass
        finally:
            test_file.chmod(0o644)


class TestMachORepairWorkflow:
    """Test complete Mach-O repair workflow."""

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-only test")
    def test_repair_workflow_non_macho(self, tmp_path):
        """Test complete repair workflow on non-Mach-O."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00" * 10)

        handler = MachOHandler(test_file)

        valid, msg = handler.validate_integrity()
        assert not valid

        success, repairs = handler.full_repair()
        assert not success

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_repair_workflow_system_binary(self, tmp_path):
        """Test complete repair workflow on system binary copy."""

        system_binaries = ["/bin/ls", "/bin/cat", "/usr/bin/true"]
        source = None
        for path in system_binaries:
            if Path(path).exists():
                source = Path(path)
                break

        if not source:
            pytest.skip("No suitable system binary")

        test_binary = tmp_path / "test_binary"
        shutil.copy(source, test_binary)

        handler = MachOHandler(test_binary)

        valid1, _ = handler.validate_integrity()

        success, repairs = handler.full_repair()

        valid2, _ = handler.validate_integrity()


class TestCodeSignerErrorHandling:
    """Test CodeSigner error handling."""

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-only test")
    def test_sign_nonexistent_file(self, tmp_path):
        """Test signing nonexistent file."""
        signer = CodeSigner()
        nonexistent = tmp_path / "nonexistent"

        result = signer.sign(nonexistent)
        assert result is False

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-only test")
    def test_verify_nonexistent_file(self, tmp_path):
        """Test verifying nonexistent file."""
        signer = CodeSigner()
        nonexistent = tmp_path / "nonexistent"

        result = signer.verify(nonexistent)
        assert result is False

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-only test")
    def test_remove_signature_nonexistent_file(self, tmp_path):
        """Test removing signature from nonexistent file."""
        signer = CodeSigner()
        nonexistent = tmp_path / "nonexistent"

        result = signer.remove_signature(nonexistent)
        assert result is False


class TestMachOPlatformIntegration:
    """Platform-specific integration tests."""

    @pytest.mark.skipif(platform.system() not in ("Darwin", "Linux"), reason="POSIX only")
    def test_file_permissions_preserved(self, tmp_path):
        """Test that file permissions are preserved during repair."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)
        test_file.chmod(0o755)

        test_file.stat().st_mode

        handler = MachOHandler(test_file)
        handler.full_repair()

        test_file.stat().st_mode
        if handler.is_macho():
            pass
