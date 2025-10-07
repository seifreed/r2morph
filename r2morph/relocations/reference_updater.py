"""
Update references (jumps, calls, pointers) after code modifications.
"""

import logging
from enum import Enum

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class ReferenceType(Enum):
    """Types of references in binary."""

    CALL = "call"
    JUMP = "jump"
    DATA_PTR = "data_ptr"
    RELATIVE = "relative"
    ABSOLUTE = "absolute"


class ReferenceUpdater:
    """
    Updates code and data references after modifications.

    Handles jumps, calls, and data pointers that need updating
    when code is moved or inserted.
    """

    def __init__(self, binary: Binary):
        """
        Initialize reference updater.

        Args:
            binary: Binary instance
        """
        self.binary = binary
        self.updated_refs: set[int] = set()

    def update_jump_target(self, jump_addr: int, old_target: int, new_target: int) -> bool:
        """
        Update a jump instruction to point to new target.

        Args:
            jump_addr: Address of jump instruction
            old_target: Old target address
            new_target: New target address

        Returns:
            True if successful
        """
        try:
            insn_json = self.binary.r2.cmd(f"aoj 1 @ 0x{jump_addr:x}")
            import json

            insns = json.loads(insn_json)
            if not insns:
                return False

            insn = insns[0]
            mnemonic = insn.get("mnemonic", "")
            size = insn.get("size", 0)
            jump_type = insn.get("type", "")

            if "rel" in jump_type.lower() or "cjmp" in jump_type.lower():
                new_offset = new_target - (jump_addr + size)

                if new_offset >= 0:
                    new_insn = f"{mnemonic} +{new_offset}"
                else:
                    new_insn = f"{mnemonic} {new_offset}"

                new_bytes = self.binary.assemble(new_insn)

                if len(new_bytes) <= size:
                    self.binary.write_bytes(jump_addr, new_bytes)

                    if len(new_bytes) < size:
                        self.binary.nop_fill(jump_addr + len(new_bytes), size - len(new_bytes))

                    self.updated_refs.add(jump_addr)
                    logger.debug(f"Updated jump at 0x{jump_addr:x} -> 0x{new_target:x}")
                    return True
                else:
                    logger.warning(f"New jump instruction too large at 0x{jump_addr:x}")
                    return False

            else:
                new_insn = f"{mnemonic} 0x{new_target:x}"
                new_bytes = self.binary.assemble(new_insn)

                if len(new_bytes) <= size:
                    self.binary.write_bytes(jump_addr, new_bytes)
                    if len(new_bytes) < size:
                        self.binary.nop_fill(jump_addr + len(new_bytes), size - len(new_bytes))

                    self.updated_refs.add(jump_addr)
                    logger.debug(f"Updated absolute jump at 0x{jump_addr:x} -> 0x{new_target:x}")
                    return True

        except Exception as e:
            logger.error(f"Failed to update jump at 0x{jump_addr:x}: {e}")

        return False

    def update_call_target(self, call_addr: int, old_target: int, new_target: int) -> bool:
        """
        Update a call instruction to point to new target.

        Args:
            call_addr: Address of call instruction
            old_target: Old target address
            new_target: New target address

        Returns:
            True if successful
        """
        try:
            insn_json = self.binary.r2.cmd(f"aoj 1 @ 0x{call_addr:x}")
            import json

            insns = json.loads(insn_json)
            if not insns:
                return False

            insn = insns[0]
            size = insn.get("size", 0)
            call_type = insn.get("type", "")

            if "rel" in call_type.lower() or "call" in call_type.lower():
                new_offset = new_target - (call_addr + size)

                if new_offset >= 0:
                    new_insn = f"call +{new_offset}"
                else:
                    new_insn = f"call {new_offset}"

                new_bytes = self.binary.assemble(new_insn)

                if len(new_bytes) <= size:
                    self.binary.write_bytes(call_addr, new_bytes)
                    if len(new_bytes) < size:
                        self.binary.nop_fill(call_addr + len(new_bytes), size - len(new_bytes))

                    self.updated_refs.add(call_addr)
                    logger.debug(f"Updated call at 0x{call_addr:x} -> 0x{new_target:x}")
                    return True

        except Exception as e:
            logger.error(f"Failed to update call at 0x{call_addr:x}: {e}")

        return False

    def update_data_pointer(
        self, ptr_addr: int, old_value: int, new_value: int, ptr_size: int | None = None
    ) -> bool:
        """
        Update a data pointer.

        Args:
            ptr_addr: Address of pointer
            old_value: Old pointer value
            new_value: New pointer value
            ptr_size: Pointer size in bytes (auto-detect if None)

        Returns:
            True if successful
        """
        try:
            if ptr_size is None:
                arch_info = self.binary.get_arch_info()
                ptr_size = arch_info["bits"] // 8

            current_hex = self.binary.r2.cmd(f"p8 {ptr_size} @ 0x{ptr_addr:x}")
            current_bytes = bytes.fromhex(current_hex.strip())
            current_value = int.from_bytes(current_bytes, byteorder="little")

            if current_value == old_value:
                new_bytes = new_value.to_bytes(ptr_size, byteorder="little")
                self.binary.write_bytes(ptr_addr, new_bytes)

                self.updated_refs.add(ptr_addr)
                logger.debug(
                    f"Updated pointer at 0x{ptr_addr:x}: 0x{old_value:x} -> 0x{new_value:x}"
                )
                return True
            else:
                logger.warning(
                    f"Pointer value mismatch at 0x{ptr_addr:x}: "
                    f"expected 0x{old_value:x}, got 0x{current_value:x}"
                )

        except Exception as e:
            logger.error(f"Failed to update pointer at 0x{ptr_addr:x}: {e}")

        return False

    def find_references_to(self, target_addr: int) -> list[dict]:
        """
        Find all references to a target address.

        Args:
            target_addr: Target address

        Returns:
            List of reference dicts
        """
        logger.debug(f"Finding references to 0x{target_addr:x}")

        refs = []

        xrefs_json = self.binary.r2.cmd(f"axtj @ 0x{target_addr:x}")
        if xrefs_json:
            import json

            try:
                xrefs = json.loads(xrefs_json)
                refs.extend(xrefs)
            except json.JSONDecodeError:
                pass

        logger.debug(f"Found {len(refs)} references to 0x{target_addr:x}")
        return refs

    def update_all_references_to(self, old_addr: int, new_addr: int) -> int:
        """
        Update all references to an address.

        Args:
            old_addr: Old address
            new_addr: New address

        Returns:
            Number of references updated
        """
        logger.info(f"Updating all references: 0x{old_addr:x} -> 0x{new_addr:x}")

        refs = self.find_references_to(old_addr)
        updated = 0

        for ref in refs:
            ref_addr = ref.get("from")
            ref_type = ref.get("type", "").upper()

            if not ref_addr:
                continue

            success = False

            if ref_type in ["CALL", "C"]:
                success = self.update_call_target(ref_addr, old_addr, new_addr)
            elif ref_type in ["JMP", "J"]:
                success = self.update_jump_target(ref_addr, old_addr, new_addr)
            elif ref_type in ["DATA", "D"]:
                success = self.update_data_pointer(ref_addr, old_addr, new_addr)

            if success:
                updated += 1

        logger.info(f"Updated {updated}/{len(refs)} references")
        return updated
