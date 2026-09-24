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

    def __init__(self, binary: Binary, min_size: int = 10, *, protect_nop_instructions: bool = False):
        """
        Initialize cave finder.

        Args:
            binary: Binary instance
            min_size: Minimum cave size to detect
        """
        self.binary = binary
        self.min_size = min_size
        self.protect_nop_instructions = protect_nop_instructions
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
        instruction_ranges = self._instruction_ranges()
        if instruction_ranges is None:
            logger.warning("Unable to validate executable instruction boundaries; refusing code caves")
            return self.caves

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
                section_addr,
                section_size,
                section_name,
                is_executable=True,
                instruction_ranges=instruction_ranges,
            )

            self.caves.extend(caves)

            if len(self.caves) >= max_caves:
                break

        logger.info(f"Found {len(self.caves)} code caves")
        return self.caves

    def _instruction_ranges(self) -> tuple[tuple[int, int], ...] | None:
        """Return sorted executable instruction ranges for cave validation."""
        get_functions = getattr(self.binary, "get_functions", None)
        get_function_disasm = getattr(self.binary, "get_function_disasm", None)
        if not callable(get_functions) or not callable(get_function_disasm):
            return ()
        try:
            r2 = getattr(self.binary, "r2", None)
            command_json = getattr(r2, "cmdj", None)
            functions = command_json("aflj") if callable(command_json) else None
            if not isinstance(functions, list):
                functions = get_functions()
            ranges: list[tuple[int, int]] = []
            for function in functions:
                function_address = function.get("offset", function.get("addr"))
                if not isinstance(function_address, int):
                    continue
                for instruction in get_function_disasm(function_address):
                    address = instruction.get("addr", instruction.get("offset"))
                    size = instruction.get("size")
                    mnemonic = str(instruction.get("disasm", "")).split(maxsplit=1)[0].lower()
                    if (
                        (self.protect_nop_instructions or mnemonic != "nop" or size != 1)
                        and isinstance(address, int)
                        and isinstance(size, int)
                        and size > 0
                    ):
                        ranges.append((address, address + size))
        except (BrokenPipeError, OSError, RuntimeError, ValueError) as error:
            logger.warning("Failed to disassemble executable ranges for cave validation: %s", error)
            return None
        return tuple(sorted(set(ranges)))

    def _find_caves_in_range(
        self,
        start_addr: int,
        size: int,
        section_name: str,
        is_executable: bool,
        instruction_ranges: tuple[tuple[int, int], ...] = (),
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
        caves: list[CodeCave] = []

        if self.binary.r2 is None:
            raise RuntimeError("Binary disassembler is not open")
        try:
            data_hex = self.binary.r2.cmd(f"p8 {size} @ 0x{start_addr:x}")
            if data_hex is None:
                logger.error(f"r2 returned None for cave scan at 0x{start_addr:x}")
                return caves
            data_hex = data_hex.strip()
            if not data_hex:
                return caves
            try:
                data = bytes.fromhex(data_hex)
            except ValueError as e:
                logger.error(f"Failed to parse hex data at 0x{start_addr:x}: {e}")
                return caves
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

        return [cave for cave in caves if not self._overlaps_instruction(cave, instruction_ranges)]

    @staticmethod
    def _overlaps_instruction(cave: CodeCave, instruction_ranges: tuple[tuple[int, int], ...]) -> bool:
        """Reject byte runs that begin or end inside an executable instruction."""
        cave_end = cave.address + cave.size
        for instruction_start, instruction_end in instruction_ranges:
            if instruction_end <= cave.address:
                continue
            if instruction_start >= cave_end:
                break
            return True
        return False

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
            if not self.caves:
                logger.warning(f"No caves found in binary for {needed_size} bytes")

        if not self.caves:
            return None

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

        Creates a reduced-size replacement cave in the list rather than
        mutating the original object, so external references stay consistent.

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

        remaining_size = cave.size - size
        remaining_addr = cave.address + size

        # Remove the original cave from the list
        try:
            self.caves.remove(cave)
        except ValueError:
            logger.debug("Cave already removed from available caves")

        # If there's enough space left, add a new cave for the remainder
        if remaining_size >= self.min_size:
            remainder = CodeCave(
                address=remaining_addr,
                size=remaining_size,
                section=cave.section,
                is_executable=cave.is_executable,
            )
            self.caves.append(remainder)

        logger.debug(f"Allocated {allocated_size} bytes at 0x{allocated_addr:x}")

        return allocated_addr, allocated_size

    def insert_code_in_cave(self, code_bytes: bytes, preferred_section: str | None = None) -> int | None:
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
                    if not self.binary.write_bytes(addr, code_bytes):
                        logger.error(f"Failed to write {needed_size} bytes at 0x{addr:x}")
                        return None
                    logger.info(f"Inserted {needed_size} bytes at 0x{addr:x} in {preferred_section}")
                    return addr

        found_cave = self.find_cave_for_size(needed_size)
        if found_cave:
            addr, _ = self.allocate_cave(found_cave, needed_size)
            if not self.binary.write_bytes(addr, code_bytes):
                logger.error(f"Failed to write {needed_size} bytes at 0x{addr:x}")
                return None
            logger.info(f"Inserted {needed_size} bytes at 0x{addr:x}")
            return addr

        return None
