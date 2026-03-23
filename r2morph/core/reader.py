"""
Binary reader service for reading data from binary files.

Extracted from Binary class following Single Responsibility Principle.
Handles all read operations: bytes, functions, disassembly, sections, etc.
"""

from __future__ import annotations


import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from r2morph.adapters.disassembler import DisassemblerInterface

logger = logging.getLogger(__name__)


class BinaryReader:
    """
    Service for reading data from binary executables through r2pipe.

    Handles all read operations:
    - Raw bytes reading
    - Function enumeration and disassembly
    - Basic block extraction
    - Section enumeration
    - Architecture info
    """

    def __init__(self, r2: "DisassemblerInterface | None"):
        """
        Initialize BinaryReader.

        Args:
            r2: Disassembler connection (r2pipe or DisassemblerInterface)
        """
        self._r2: "DisassemblerInterface | None" = r2

    def set_r2(self, r2: "DisassemblerInterface | None") -> None:
        """Update the disassembler connection after reload."""
        self._r2 = r2

    def read_bytes(self, address: int, size: int) -> bytes:
        """
        Read bytes from the binary at a virtual address.

        Args:
            address: Target virtual address
            size: Number of bytes to read

        Returns:
            Bytes read from the binary. Returns empty bytes on failure.
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        if size <= 0:
            return b""

        MAX_READ_SIZE = 100 * 1024 * 1024  # 100MB
        if size > MAX_READ_SIZE:
            logger.warning(f"Truncating large read request: {size} -> {MAX_READ_SIZE}")
            size = MAX_READ_SIZE

        try:
            hex_data = self._r2.cmd(f"p8 {size} @ 0x{address:x}")
            if hex_data is None:
                logger.debug(f"r2 returned None for read at 0x{address:x}")
                return b""
            hex_data = hex_data.strip()
            if not hex_data:
                return b""
            for c in hex_data:
                if c not in "0123456789abcdefABCDEF":
                    logger.error(f"Invalid hex character in read result at 0x{address:x}: {c}")
                    return b""
            try:
                result = bytes.fromhex(hex_data)
                if len(result) != size:
                    logger.warning(f"Read size mismatch at 0x{address:x}: expected {size}, got {len(result)}")
                    return b""
                return result
            except ValueError as e:
                logger.error(f"Failed to parse hex at 0x{address:x}: {e}")
                return b""
        except (ValueError, OSError) as e:
            logger.error(f"Failed to read bytes at 0x{address:x}: {e}")
            return b""

    def get_functions(self, cached: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """
        Get list of functions in the binary.

        Args:
            cached: Pre-cached function list if available

        Returns:
            List of function dictionaries with metadata
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        # Use cached functions if available
        if cached is not None:
            logger.debug(f"Using cached {len(cached)} functions")
            return cached

        # Fallback to querying r2
        functions = self._r2.cmdj("aflj") or []
        logger.debug(f"Found {len(functions)} functions (uncached)")
        return functions

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        """
        Get disassembly of a function at given address.

        Args:
            address: Function address

        Returns:
            List of instruction dictionaries
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        disasm = self._r2.cmdj(f"pdfj @ {address}") or {}
        ops: list[dict[str, Any]] = disasm.get("ops", [])
        return ops

    def get_basic_blocks(self, address: int) -> list[dict[str, Any]]:
        """
        Get basic blocks for a function at given address.

        Args:
            address: Function address

        Returns:
            List of basic block dictionaries
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        blocks = self._r2.cmdj(f"afbj @ {address}") or []
        return blocks

    def get_sections(self) -> list[dict[str, Any]]:
        """
        Get sections from the binary.

        Returns:
            List of section dictionaries with keys like name, size, vaddr, etc.
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        sections = self._r2.cmdj("iSj") or []
        return sections

    def get_arch_info(self, info: dict[str, Any]) -> dict[str, Any]:
        """
        Get architecture information from the binary.

        Args:
            info: Binary info from r2pipe

        Returns:
            Dictionary with arch, bits, endian, etc.
        """
        core_info = info.get("bin", {})
        return {
            "arch": core_info.get("arch", "unknown"),
            "bits": core_info.get("bits", 0),
            "endian": core_info.get("endian", "unknown"),
            "format": core_info.get("class", "unknown"),
            "machine": core_info.get("machine", "unknown"),
        }

    def get_arch_family(self, info: dict[str, Any]) -> tuple[str, int]:
        """
        Return (arch_family, bits) tuple.

        Args:
            info: Binary info from r2pipe

        Returns:
            Tuple of (arch_family, bits)
        """
        arch_info = self.get_arch_info(info)
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 32)
        family = "x86" if arch in ["x86", "x64"] else arch
        return family, bits

    def resolve_symbolic_vars(self, instruction: str, function_addr: int | None = None) -> str:
        """
        Resolve symbolic variable names in instruction to actual addresses.

        Converts var_XXh to [rsp+offset] or [rbp-offset] based on function analysis.

        Args:
            instruction: Assembly instruction with symbolic vars (e.g., "mov eax, [var_10h]")
            function_addr: Function address for variable context (optional)

        Returns:
            Instruction with resolved addresses
        """
        if self._r2 is None:
            return instruction

        # Pattern to match symbolic variables
        var_pattern = r"\[(var_(?:bp_)?|arg_)([0-9a-f]+)h(_\d+)?\]"
        import re

        matches = list(re.finditer(var_pattern, instruction, re.IGNORECASE))

        if not matches:
            return instruction

        # Get variable and argument information from current function if available
        var_map = {}
        if function_addr:
            try:
                vars_output = self._r2.cmd(f"afv @ {function_addr}")
                for line in vars_output.split("\n"):
                    if ("var_" in line or "arg" in line) and "@" in line:
                        parts = line.split("@")
                        if len(parts) == 2:
                            var_name = parts[0].split()[-1].strip()
                            location = parts[1].strip()
                            var_map[var_name] = location
            except Exception as e:
                logger.debug(f"Could not parse function variables at 0x{function_addr:x}: {e}")

        # Replace variables with resolved addresses
        resolved = instruction
        for match in reversed(matches):
            prefix = match.group(1)
            offset_hex = match.group(2)
            suffix = match.group(3) or ""
            offset = int(offset_hex, 16)

            # Construct variable name
            if prefix == "var_bp_":
                var_name = f"var_bp_{offset_hex}h{suffix}"
            elif prefix == "var_":
                var_name = f"var_{offset_hex}h{suffix}"
            else:
                var_name = f"arg_{offset_hex}h{suffix}"

            # Try function analysis first, then fallback
            if var_name in var_map:
                replacement = f"[{var_map[var_name]}]"
            else:
                if prefix == "var_bp_":
                    replacement = f"[rbp - 0x{offset:x}]"
                elif prefix == "arg_":
                    replacement = f"[rsp + 0x{offset:x}]"
                else:
                    replacement = f"[rsp + 0x{offset:x}]"

            resolved = resolved[: match.start()] + replacement + resolved[match.end() :]

        return resolved

    def resolve_physical_offset(self, address: int) -> int | None:
        """
        Resolve a virtual address to physical offset.

        Uses r2's s2p command or falls back to section mapping.

        Args:
            address: Virtual address to resolve

        Returns:
            Physical offset in the file, or None if resolution fails
        """
        if self._r2 is None:
            raise RuntimeError("Binary not opened. Call open() first.")

        paddr_result = self._r2.cmd(f"s2p 0x{address:x}")

        if paddr_result and paddr_result.strip():
            try:
                return int(paddr_result.strip(), 16)
            except ValueError:
                pass

        for section in self.get_sections():
            vaddr = section.get("vaddr")
            paddr = section.get("paddr")
            size = section.get("size") or section.get("vsize") or 0
            if vaddr is None or paddr is None:
                continue
            if size <= 0:
                continue
            section_end = vaddr + size
            if section_end < vaddr:
                continue
            if vaddr <= address < section_end:
                offset_in_section = address - vaddr
                physical_offset = paddr + offset_in_section
                if physical_offset < paddr:
                    continue
                logger.debug(f"Mapped vaddr 0x{address:x} -> section paddr 0x{physical_offset:x}")
                return int(physical_offset)

        logger.warning(f"Could not resolve physical offset for vaddr 0x{address:x}")
        return None
