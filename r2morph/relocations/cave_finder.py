"""
Find code caves (unused space) in binaries for code insertion.
"""

import logging
from dataclasses import dataclass

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


@dataclass
class CodeCave:
    """Represents a code cave (unused space in binary)."""

    address: int
    size: int
    section: str
    is_executable: bool

    def __str__(self) -> str:
        exec_str = "RX" if self.is_executable else "R-"
        return f"Cave @ 0x{self.address:x} ({self.size} bytes, {self.section}, {exec_str})"


class CaveFinder:
    """
    Finds code caves in binaries for inserting new code.

    Code caves are sequences of unused bytes (typically NOPs or zeros)
    that can be repurposed for new code.
    """

    def __init__(self, binary: Binary, min_size: int = 10):
        """
        Initialize cave finder.

        Args:
            binary: Binary instance
            min_size: Minimum cave size to detect
        """
        self.binary = binary
        self.min_size = min_size
        self.caves: list[CodeCave] = []

    def find_caves(self, max_caves: int = 100) -> list[CodeCave]:
        """
        Find all code caves in the binary.

        Args:
            max_caves: Maximum number of caves to find

        Returns:
            List of CodeCave objects
        """
        logger.info(f"Searching for code caves (min size: {self.min_size})")

        self.caves = []

        sections = self.binary.get_sections()

        for section in sections:
            section_name = section.get("name", "")
            section_addr = section.get("vaddr", 0)
            section_size = section.get("vsize", 0)
            section_perm = section.get("perm", "")

            if "x" not in section_perm.lower():
                continue

            logger.debug(f"Scanning section {section_name} for caves")

            caves = self._find_caves_in_range(
                section_addr, section_size, section_name, is_executable=True
            )

            self.caves.extend(caves)

            if len(self.caves) >= max_caves:
                break

        logger.info(f"Found {len(self.caves)} code caves")
        return self.caves

    def _find_caves_in_range(
        self, start_addr: int, size: int, section_name: str, is_executable: bool
    ) -> list[CodeCave]:
        """
        Find caves in a specific address range.

        Args:
            start_addr: Start address
            size: Size of range
            section_name: Section name
            is_executable: Whether section is executable

        Returns:
            List of caves found
        """
        caves = []

        try:
            data_hex = self.binary.r2.cmd(f"p8 {size} @ 0x{start_addr:x}")
            data = bytes.fromhex(data_hex.strip())
        except Exception as e:
            logger.error(f"Failed to read section {section_name}: {e}")
            return caves

        current_cave_start = None
        current_cave_size = 0

        for i, byte in enumerate(data):
            if byte in [0x90, 0x00]:
                if current_cave_start is None:
                    current_cave_start = i
                current_cave_size += 1
            else:
                if current_cave_start is not None and current_cave_size >= self.min_size:
                    cave = CodeCave(
                        address=start_addr + current_cave_start,
                        size=current_cave_size,
                        section=section_name,
                        is_executable=is_executable,
                    )
                    caves.append(cave)

                current_cave_start = None
                current_cave_size = 0

        if current_cave_start is not None and current_cave_size >= self.min_size:
            cave = CodeCave(
                address=start_addr + current_cave_start,
                size=current_cave_size,
                section=section_name,
                is_executable=is_executable,
            )
            caves.append(cave)

        return caves

    def find_cave_for_size(self, needed_size: int) -> CodeCave | None:
        """
        Find a cave that can fit the needed size.

        Args:
            needed_size: Size needed

        Returns:
            CodeCave or None
        """
        if not self.caves:
            self.find_caves()

        sorted_caves = sorted(self.caves, key=lambda c: c.size, reverse=True)

        for cave in sorted_caves:
            if cave.size >= needed_size and cave.is_executable:
                logger.debug(f"Found cave for {needed_size} bytes: {cave}")
                return cave

        logger.warning(f"No cave found for {needed_size} bytes")
        return None

    def allocate_cave(self, cave: CodeCave, size: int) -> tuple[int, int]:
        """
        Allocate space from a cave.

        Args:
            cave: Cave to allocate from
            size: Size to allocate

        Returns:
            Tuple of (address, size) allocated
        """
        if size > cave.size:
            raise ValueError(f"Cannot allocate {size} bytes from {cave.size} byte cave")

        allocated_addr = cave.address
        allocated_size = size

        cave.address += size
        cave.size -= size

        if cave.size < self.min_size:
            self.caves.remove(cave)

        logger.debug(f"Allocated {allocated_size} bytes at 0x{allocated_addr:x}")

        return allocated_addr, allocated_size

    def insert_code_in_cave(
        self, code_bytes: bytes, preferred_section: str | None = None
    ) -> int | None:
        """
        Insert code into a suitable cave.

        Args:
            code_bytes: Code to insert
            preferred_section: Preferred section name

        Returns:
            Address where code was inserted, or None
        """
        needed_size = len(code_bytes)

        if preferred_section:
            for cave in self.caves:
                if cave.section == preferred_section and cave.size >= needed_size:
                    addr, _ = self.allocate_cave(cave, needed_size)
                    self.binary.write_bytes(addr, code_bytes)
                    logger.info(
                        f"Inserted {needed_size} bytes at 0x{addr:x} in {preferred_section}"
                    )
                    return addr

        cave = self.find_cave_for_size(needed_size)
        if cave:
            addr, _ = self.allocate_cave(cave, needed_size)
            self.binary.write_bytes(addr, code_bytes)
            logger.info(f"Inserted {needed_size} bytes at 0x{addr:x}")
            return addr

        return None
