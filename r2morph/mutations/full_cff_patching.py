"""Patching helpers for full control-flow flattening."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from r2morph.analysis.cfg import ControlFlowGraph
from r2morph.core.constants import SIGNED_32_MAX, SIGNED_32_MIN, X86_RELATIVE_BRANCH_SIZE_BYTES

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PatchFunctionRequest:
    binary: Any
    cfg: ControlFlowGraph
    dispatcher_blocks: list[Any]
    dispatcher_addr: int
    validation_manager: Any | None
    create_mutation_checkpoint: Callable[[str], Any | None]
    record_mutation: Callable[..., Any]
    session: Any | None
    records: list[Any]
    rollback_policy: str


def _find_block_end(binary: Any, function_address: int, block: Any) -> int | None:
    block_end: int | None = None
    for instruction in binary.get_function_disasm(function_address):
        address = int(instruction.get("offset", 0))
        if not block.block_address <= address < block.block_address + block.block_size:
            continue
        instruction_end = address + int(instruction.get("size", 0))
        if instruction_end > block.block_address + block.block_size:
            return address
        block_end = instruction_end
    return block_end


def _rollback_failed_patch(request: PatchFunctionRequest, checkpoint: Any | None, patches_applied: int) -> int:
    if not (
        patches_applied > 0 and request.validation_manager is not None and checkpoint is not None and request.records
    ):
        return patches_applied

    outcome = request.validation_manager.validate_mutation(request.binary, request.records[-1].to_dict())
    if outcome.passed:
        return patches_applied
    if request.session is not None:
        request.session.rollback_to(checkpoint)
    request.binary.reload()
    request.records.pop()
    if request.rollback_policy == "fail-fast":
        raise RuntimeError("Mutation-level validation failed")
    return 0


def patch_function_blocks(request: PatchFunctionRequest) -> int:
    """Patch function blocks so they jump into the dispatcher."""
    patches_applied = 0
    func_addr = request.cfg.function_address

    mutation_checkpoint = request.create_mutation_checkpoint("full_cff")
    baseline = {}
    if request.validation_manager is not None:
        baseline = request.validation_manager.capture_structural_baseline(request.binary, func_addr)

    arch_info = request.binary.get_arch_info()
    arch = arch_info.get("arch", "")

    for db in request.dispatcher_blocks:
        if db.is_exit:
            continue

        block_addr = db.block_address

        try:
            block_end = _find_block_end(request.binary, func_addr, db)
            if block_end is None or arch not in ("x86", "x86_64"):
                continue

            rel_offset = request.dispatcher_addr - (block_end + X86_RELATIVE_BRANCH_SIZE_BYTES)
            if rel_offset < SIGNED_32_MIN or rel_offset > SIGNED_32_MAX:
                logger.debug("Jump offset out of range for block at 0x%x", block_addr)
                continue

            jmp_bytes = b"\xe9" + rel_offset.to_bytes(4, "little", signed=True)
            original_bytes = request.binary.read_bytes(block_end, X86_RELATIVE_BRANCH_SIZE_BYTES)
            if not request.binary.write_bytes(block_end, jmp_bytes):
                continue

            if original_bytes:
                request.record_mutation(
                    function_address=func_addr,
                    start_address=block_end,
                    end_address=block_end + 4,
                    original_bytes=original_bytes,
                    mutated_bytes=jmp_bytes,
                    original_disasm="original_block_end",
                    mutated_disasm=f"jmp 0x{request.dispatcher_addr:x}",
                    mutation_kind="full_cff",
                    metadata={
                        "block_addr": block_addr,
                        "dispatcher_addr": request.dispatcher_addr,
                        "structural_baseline": baseline,
                    },
                )
            patches_applied += 1

        except Exception as e:
            logger.debug("Failed to patch block at 0x%x: %s", block_addr, e)

    return _rollback_failed_patch(request, mutation_checkpoint, patches_applied)


__all__ = ["PatchFunctionRequest", "patch_function_blocks"]
