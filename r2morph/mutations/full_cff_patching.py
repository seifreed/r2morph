"""Patching helpers for full control-flow flattening."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from r2morph.analysis.cfg import ControlFlowGraph

logger = logging.getLogger(__name__)


def patch_function_blocks(
    *,
    binary: Any,
    cfg: ControlFlowGraph,
    dispatcher_blocks: list[Any],
    dispatcher_addr: int,
    validation_manager: Any | None,
    create_mutation_checkpoint: Callable[[str], Any | None],
    record_mutation: Callable[..., None],
    session: Any | None,
    records: list[Any],
    rollback_policy: str,
) -> int:
    """Patch function blocks so they jump into the dispatcher."""
    patches_applied = 0
    func_addr = cfg.function_address

    mutation_checkpoint = create_mutation_checkpoint("full_cff")
    baseline = {}
    if validation_manager is not None:
        baseline = validation_manager.capture_structural_baseline(binary, func_addr)

    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "")

    for db in dispatcher_blocks:
        if db.is_exit:
            continue

        block_addr = db.block_address

        try:
            block_instrs = binary.get_function_disasm(func_addr)
            block_end = None

            for insn in block_instrs:
                insn_addr = insn.get("offset", 0)
                if insn_addr >= block_addr and insn_addr < block_addr + db.block_size:
                    if insn_addr + insn.get("size", 0) > block_addr + db.block_size:
                        block_end = insn_addr
                        break
                    block_end = insn_addr + insn.get("size", 0)

            if not block_end:
                continue

            if arch not in ("x86", "x86_64"):
                continue

            rel_offset = dispatcher_addr - (block_end + 5)
            if rel_offset < -2147483648 or rel_offset > 2147483647:
                logger.debug("Jump offset out of range for block at 0x%x", block_addr)
                continue

            jmp_bytes = b"\xe9" + rel_offset.to_bytes(4, "little", signed=True)
            original_bytes = binary.read_bytes(block_end, 5)
            if not binary.write_bytes(block_end, jmp_bytes):
                continue

            if original_bytes:
                record_mutation(
                    function_address=func_addr,
                    start_address=block_end,
                    end_address=block_end + 4,
                    original_bytes=original_bytes,
                    mutated_bytes=jmp_bytes,
                    original_disasm="original_block_end",
                    mutated_disasm=f"jmp 0x{dispatcher_addr:x}",
                    mutation_kind="full_cff",
                    metadata={
                        "block_addr": block_addr,
                        "dispatcher_addr": dispatcher_addr,
                        "structural_baseline": baseline,
                    },
                )
            patches_applied += 1

        except Exception as e:
            logger.debug("Failed to patch block at 0x%x: %s", block_addr, e)

    if patches_applied > 0 and validation_manager is not None and mutation_checkpoint is not None:
        if records:
            outcome = validation_manager.validate_mutation(binary, records[-1].to_dict())
            if not outcome.passed:
                if session is not None:
                    session.rollback_to(mutation_checkpoint)
                binary.reload()
                if records:
                    records.pop()
                if rollback_policy == "fail-fast":
                    raise RuntimeError("Mutation-level validation failed")
                return 0

    return patches_applied


__all__ = ["patch_function_blocks"]
