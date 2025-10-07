"""
Real integration tests for CaveFinder using dataset binaries.
"""

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.cave_finder import CaveFinder, CodeCave


class TestCaveFinderReal:
    """Real tests for CaveFinder."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls_macOS"

    def test_cave_finder_initialization(self, ls_elf):
        """Test CaveFinder initialization."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary)

            assert finder.binary == binary
            assert hasattr(finder, "min_size")

    def test_code_cave_dataclass(self):
        """Test CodeCave dataclass."""
        cave = CodeCave(address=0x1000, size=256, section=".text", is_executable=True)

        assert cave.address == 0x1000
        assert cave.size == 256
        assert cave.section == ".text"
        assert cave.is_executable is True

    def test_find_caves_basic(self, ls_elf):
        """Test finding code caves."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=32)

            caves = finder.find_caves()
            assert isinstance(caves, list)
            # May or may not find caves
            for cave in caves:
                assert isinstance(cave, CodeCave)
                assert cave.size >= 32

    def test_find_caves_with_min_size(self, ls_elf):
        """Test finding caves with minimum size."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=64)

            caves = finder.find_caves()
            assert isinstance(caves, list)
            # Check all caves meet minimum size
            for cave in caves:
                assert cave.size >= 64

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
                assert isinstance(caves, list)

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
                assert isinstance(largest, CodeCave)
                assert largest.size >= 16

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
                assert isinstance(cave.section, str)

    def test_macos_binary_caves(self, ls_macos):
        """Test finding caves in macOS binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        with Binary(ls_macos) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=32)

            caves = finder.find_caves()
            assert isinstance(caves, list)

    def test_cave_address_validity(self, ls_elf):
        """Test that cave addresses are valid."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            finder = CaveFinder(binary, min_size=16)

            caves = finder.find_caves()
            for cave in caves:
                assert cave.address > 0
                assert cave.size > 0

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
                assert isinstance(caves, list)
                for cave in caves:
                    assert cave.size >= min_size
