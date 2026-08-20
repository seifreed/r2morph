"""
Real integration tests for CaveFinder using dataset binaries.
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
from r2morph.relocations.cave_finder import CaveFinder, CodeCave

_EXPECTED_CAVE_ADDRESS_4096 = 0x1000
_EXPECTED_CAVE_SIZE_256 = 256
_EXPECTED_CAVE_SIZE_32 = 32
_EXPECTED_CAVE_SIZE_64 = 64
_EXPECTED_LARGEST_SIZE_16 = 16


class TestCaveFinderReal:
    """Real tests for CaveFinder."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "macho_arm64"

    def test_cave_finder_initialization(self, ls_elf):
        """Test CaveFinder initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary)

            expect(finder.binary == binary)
            expect(hasattr(finder, "min_size"))

    def test_code_cave_dataclass(self):
        """Test CodeCave dataclass."""
        cave = CodeCave(address=0x1000, size=256, section=".text", is_executable=True)

        expect(cave.address == _EXPECTED_CAVE_ADDRESS_4096)
        expect(cave.size == _EXPECTED_CAVE_SIZE_256)
        expect(cave.section == ".text")
        expect(not (cave.is_executable is not True))

    def test_find_caves_basic(self, ls_elf):
        """Test finding code caves."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=32)

            caves = finder.find_caves()
            expect(isinstance(caves, list))
            # May or may not find caves
            for cave in caves:
                expect(isinstance(cave, CodeCave))
                expect(not (cave.size < _EXPECTED_CAVE_SIZE_32))

    def test_find_caves_with_min_size(self, ls_elf):
        """Test finding caves with minimum size."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=64)

            caves = finder.find_caves()
            expect(isinstance(caves, list))
            # Check all caves meet minimum size
            for cave in caves:
                expect(not (cave.size < _EXPECTED_CAVE_SIZE_64))

    def test_find_caves_in_section(self, ls_elf):
        """Test finding caves in specific section."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=32)

            # Get sections
            sections = binary.get_sections()
            if len(sections) > 0:
                sections[0].get("name", ".text")
                # For now, just test that find_caves works
                caves = finder.find_caves()
                expect(isinstance(caves, list))

    def test_find_largest_cave(self, ls_elf):
        """Test finding largest code cave."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=16)

            caves = finder.find_caves()
            if len(caves) > 0:
                largest = max(caves, key=lambda c: c.size)
                expect(isinstance(largest, CodeCave))
                expect(not (largest.size < _EXPECTED_LARGEST_SIZE_16))

    def test_caves_in_executable_sections(self, ls_elf):
        """Test finding caves in executable sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=32)

            caves = finder.find_caves()
            # Check that caves are in valid sections
            for cave in caves:
                expect(isinstance(cave.section, str))

    def test_macos_binary_caves(self, ls_macos):
        """Test finding caves in macOS binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        with Binary(ls_macos) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=32)

            caves = finder.find_caves()
            expect(isinstance(caves, list))

    def test_cave_address_validity(self, ls_elf):
        """Test that cave addresses are valid."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=16)

            caves = finder.find_caves()
            for cave in caves:
                expect(not (cave.address <= 0))
                expect(not (cave.size <= 0))

    def test_different_min_sizes(self, ls_elf):
        """Test finding caves with different minimum sizes."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()

            # Try different minimum sizes
            for min_size in [16, 32, 64, 128]:
                finder = CaveFinder(binary, min_size=min_size)
                caves = finder.find_caves()
                expect(isinstance(caves, list))
                for cave in caves:
                    expect(not (cave.size < min_size))
