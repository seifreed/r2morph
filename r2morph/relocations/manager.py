"""
Main relocation manager for handling code movement and reference updates.
"""

import logging
from dataclasses import dataclass
from typing import Set

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


@dataclass
class Relocation:
    """Represents a code relocation."""

    old_address: int
    new_address: int
    size: int
    relocation_type: str

    def offset(self) -> int:
        """Calculate address offset."""
        return self.new_address - self.old_address


class RelocationManager:
    """
    Manages code relocations and reference updates.

    Tracks moved code and updates all references (jumps, calls, data pointers).
    """

    def __init__(self, binary: Binary):
        """
        Initialize relocation manager.

        Args:
            binary: Binary instance
        """
        self.binary = binary
        self.relocations: list[Relocation] = []
        self.address_map: dict[int, int] = {}
        self._analyzed_refs: set[int] = set()

    def add_relocation(
        self, old_address: int, new_address: int, size: int, relocation_type: str = "move"
    ):
        """
        Register a code relocation.

        Args:
            old_address: Original address
            new_address: New address
            size: Size of relocated code
            relocation_type: Type of relocation
        """
        relocation = Relocation(
            old_address=old_address,
            new_address=new_address,
            size=size,
            relocation_type=relocation_type,
        )
        self.relocations.append(relocation)
        self.address_map[old_address] = new_address

        logger.debug(
            f"Registered relocation: 0x{old_address:x} -> 0x{new_address:x} "
            f"({size} bytes, {relocation_type})"
        )

    def get_new_address(self, old_address: int) -> int | None:
        """
        Get new address for a relocated address.

        Args:
            old_address: Original address

        Returns:
            New address or None if not relocated
        """
        if old_address in self.address_map:
            return self.address_map[old_address]

        for reloc in self.relocations:
            if reloc.old_address <= old_address < reloc.old_address + reloc.size:
                offset = old_address - reloc.old_address
                return reloc.new_address + offset

        return None

    def update_all_references(self) -> int:
        """
        Update all references in the binary to point to new addresses.

        Returns:
            Number of references updated
        """
        logger.info("Updating all references after relocations")

        updated = 0

        xrefs = self._find_all_xrefs()

        for xref in xrefs:
            if self._update_reference(xref):
                updated += 1

        logger.info(f"Updated {updated} references")
        return updated

    def _find_all_xrefs(self) -> list[dict]:
        """
        Find all cross-references in the binary.

        Returns:
            List of xref dicts
        """
        logger.debug("Finding all cross-references")

        xrefs = []

        xrefs_output = self.binary.r2.cmd("axtj")
        if xrefs_output:
            import json

            try:
                xrefs_data = json.loads(xrefs_output)
                xrefs.extend(xrefs_data)
            except json.JSONDecodeError:
                logger.warning("Failed to parse xrefs")

        logger.debug(f"Found {len(xrefs)} cross-references")
        return xrefs

    def _update_reference(self, xref: dict) -> bool:
        """
        Update a single reference.

        Args:
            xref: Cross-reference dict from radare2

        Returns:
            True if updated
        """
        from_addr = xref.get("from")
        to_addr = xref.get("to")
        ref_type = xref.get("type", "")

        if not from_addr or not to_addr:
            return False

        new_to_addr = self.get_new_address(to_addr)
        if new_to_addr is None:
            return False

        logger.debug(
            f"Updating {ref_type} reference at 0x{from_addr:x}: 0x{to_addr:x} -> 0x{new_to_addr:x}"
        )

        if ref_type in ["CALL", "JMP"]:
            return self._update_control_flow_ref(from_addr, to_addr, new_to_addr, ref_type)
        elif ref_type == "DATA":
            return self._update_data_ref(from_addr, to_addr, new_to_addr)

        return False

    def _update_control_flow_ref(
        self, from_addr: int, old_target: int, new_target: int, ref_type: str
    ) -> bool:
        """
        Update a control flow reference (call/jmp).

        Args:
            from_addr: Address of the reference instruction
            old_target: Old target address
            new_target: New target address
            ref_type: Reference type (CALL/JMP)

        Returns:
            True if updated
        """
        try:
            insn_json = self.binary.r2.cmd(f"aoj 1 @ 0x{from_addr:x}")
            import json

            insns = json.loads(insn_json)
            if not insns:
                return False

            insn = insns[0]
            mnemonic = insn.get("mnemonic", "")
            size = insn.get("size", 0)

            if "rel" in insn.get("type", "").lower():
                new_offset = new_target - (from_addr + size)

                new_insn = f"{mnemonic} {new_offset:+d}"
                new_bytes = self.binary.assemble(new_insn)

                if len(new_bytes) <= size:
                    self.binary.write_bytes(from_addr, new_bytes)
                    return True

            else:
                new_insn = f"{mnemonic} 0x{new_target:x}"
                new_bytes = self.binary.assemble(new_insn)

                if len(new_bytes) <= size:
                    self.binary.write_bytes(from_addr, new_bytes)
                    return True

        except Exception as e:
            logger.error(f"Failed to update control flow ref at 0x{from_addr:x}: {e}")

        return False

    def _update_data_ref(self, from_addr: int, old_target: int, new_target: int) -> bool:
        """
        Update a data reference.

        Args:
            from_addr: Address containing the pointer
            old_target: Old pointer value
            new_target: New pointer value

        Returns:
            True if updated
        """
        try:
            arch_info = self.binary.get_arch_info()
            ptr_size = arch_info["bits"] // 8

            current_ptr_hex = self.binary.r2.cmd(f"p8 {ptr_size} @ 0x{from_addr:x}")
            current_ptr = int.from_bytes(bytes.fromhex(current_ptr_hex.strip()), byteorder="little")

            if current_ptr == old_target:
                new_ptr_bytes = new_target.to_bytes(ptr_size, byteorder="little")
                self.binary.write_bytes(from_addr, new_ptr_bytes)
                return True

        except Exception as e:
            logger.error(f"Failed to update data ref at 0x{from_addr:x}: {e}")

        return False

    def calculate_space_needed(self, address: int, additional_bytes: int) -> bool:
        """
        Check if there's space to expand code at address.

        Args:
            address: Address to check
            additional_bytes: Number of bytes needed

        Returns:
            True if space available
        """
        insn_json = self.binary.r2.cmd(f"aoj 1 @ 0x{address:x}")
        import json

        insns = json.loads(insn_json)
        if not insns:
            return False

        current_size = insns[0].get("size", 0)
        next_addr = address + current_size

        next_bytes_hex = self.binary.r2.cmd(f"p8 {additional_bytes} @ 0x{next_addr:x}")
        next_bytes = bytes.fromhex(next_bytes_hex.strip())

        if all(b == 0x90 for b in next_bytes):
            return True

        if all(b == 0x00 for b in next_bytes):
            return True

        return False

    def shift_code_block(self, start_address: int, size: int, shift_amount: int) -> bool:
        """
        Shift a block of code by a certain amount.

        Args:
            start_address: Start of block
            size: Size of block
            shift_amount: Bytes to shift (positive = forward)

        Returns:
            True if successful
        """
        try:
            logger.info(
                f"Shifting code block at 0x{start_address:x} "
                f"(size={size}) by {shift_amount:+d} bytes"
            )

            block_hex = self.binary.r2.cmd(f"p8 {size} @ 0x{start_address:x}")
            block_bytes = bytes.fromhex(block_hex.strip())

            new_address = start_address + shift_amount

            self.binary.write_bytes(new_address, block_bytes)

            self.add_relocation(start_address, new_address, size, "move")

            if shift_amount > 0:
                self.binary.nop_fill(start_address, min(size, shift_amount))

            return True

        except Exception as e:
            logger.error(f"Failed to shift code block: {e}")
            return False
