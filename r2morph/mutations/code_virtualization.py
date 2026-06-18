"""
Code Virtualization - replace native register code with custom VM bytecode.

Selected straight-line runs of 64-bit general-purpose register instructions
are translated into bytecode for a small stack-context virtual machine. The
native run is overwritten with a trampoline into a generated interpreter
(injected into an extended executable segment); the interpreter spills the
registers to a private stack frame, executes the bytecode against that
context, reloads the registers, and jumps back to the instruction following
the run. The architectural effect is identical, but the original opcodes no
longer appear linearly in the code.

Correctness is enforced by hard gates (see
:mod:`r2morph.mutations.code_virtualization_engine` and
:mod:`r2morph.mutations.code_virtualization_inject`): only provably
reproducible runs on injectable ELF64 binaries are virtualized; every other
case leaves the function untouched. Zero virtualizations always beats a
corrupt one.
"""

from __future__ import annotations

import logging
import random
import struct
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.code_virtualization_engine import (
    VirtualizedMemOp,
    VirtualizedOp,
    build_vm_blob,
    build_vm_scheme,
    decode_instruction,
    inject_junk_ops,
)
from r2morph.mutations.code_virtualization_inject import inject_blob, predict_blob_vaddr
from r2morph.mutations.code_virtualization_region import (
    build_region_scheme,
    extract_region,
)
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from r2morph.mutations.code_virtualization_region_decoders import _decode_lea, _decode_memory_mov, _decode_op_mem
from r2morph.mutations.code_virtualization_region_nesting import build_nested_region_blob
from r2morph.mutations.instruction_substitution_helpers import flags_live_after

logger = logging.getLogger(__name__)

# Minimum instructions in a run worth virtualizing.
_MIN_RUN_LENGTH = 2
# A relative trampoline jump needs 5 bytes in the run's byte span.
_TRAMPOLINE_SIZE = 5


_MEM_ARITH_MNEMONICS = ("add", "sub", "xor", "and", "or")


def _decode_run_item(text: str) -> VirtualizedOp | VirtualizedMemOp | None:
    """Decode one instruction into a VM item: a register/immediate op, a memory
    load/store ``mov``, an ``<op> reg, [base+disp]``, or ``None`` if the VM cannot
    reproduce it (ends the run)."""
    op = decode_instruction(text)
    if op is not None:
        return op
    mem = _decode_memory_mov(text)
    if mem is not None:
        kind, reg_slot, base_slot, disp, width = mem
        return VirtualizedMemOp(kind, reg_slot, base_slot, disp, width)
    mnemonic = text.split(None, 1)[0].lower() if text.strip() else ""
    # insn_addr/insn_size below are only used by the rip-relative forms, which the
    # engine does not yet support; pass 0 and accept only the base+disp forms.
    if mnemonic in _MEM_ARITH_MNEMONICS:
        decoded = _decode_op_mem(text, mnemonic, 0, 0)
        if decoded is not None and decoded[0] == "opmem":
            _, _mnemonic, reg_slot, base_slot, disp, width = decoded
            return VirtualizedMemOp(f"mem{mnemonic}", reg_slot, base_slot, disp, width)
    elif mnemonic == "lea":
        decoded = _decode_lea(text, 0, 0)
        if decoded is not None and decoded[0] == "lea":
            _, reg_slot, base_slot, disp, width = decoded
            return VirtualizedMemOp("lea", reg_slot, base_slot, disp, width)
    return None


class _Run:
    """A virtualizable straight-line run inside one basic block."""

    __slots__ = ("start", "continuation", "ops")

    def __init__(self, start: int, continuation: int, ops: list[VirtualizedOp | VirtualizedMemOp]) -> None:
        self.start = start
        self.continuation = continuation
        self.ops = ops


class CodeVirtualizationPass(MutationPass):
    """
    Mutation pass that virtualizes register runs into custom VM bytecode.

    Config options:
        - probability: Probability of virtualizing each function (default: 0.3)
        - max_functions: Maximum functions to virtualize (default: 5)
        - vm_nesting_depth: VM layers per function; 2 wraps the region in a
          second, independently-keyed inner VM (default: 1, no nesting)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeVirtualization", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 5)
        self.vm_nesting_depth = self.config.get("vm_nesting_depth", 1)
        self.set_support(
            formats=("ELF",),
            architectures=("x86_64",),
            validators=("structural",),
            stability="experimental",
            notes=(
                "translates 64-bit register runs to VM bytecode",
                "injects a generated interpreter into an extended segment",
                "leaves functions untouched when correctness cannot be proven",
            ),
        )

    def _find_run(self, binary: Any, block: dict[str, Any]) -> _Run | None:
        """Find the first virtualizable run inside a basic block.

        ``pdbj`` disassembles exactly the basic block, so a run never spans a
        block boundary - its interior can hold no jump target, and the
        trampoline cannot orphan an instruction reached by another edge.
        """
        try:
            insns = binary.r2.cmdj(f"pdbj @ {block['addr']}")
        except Exception:
            return None
        if not insns:
            return None

        disasms = [insn.get("opcode", "") for insn in insns]
        decoded = [_decode_run_item(text) for text in disasms]

        index = 0
        count = len(insns)
        while index < count:
            if decoded[index] is None:
                index += 1
                continue
            end = index
            while end < count and decoded[end] is not None:
                end += 1
            # A run must be followed by another instruction in the block to
            # supply the continuation address; the block's terminator (which
            # decode_instruction never accepts) provides it.
            if end < count and (end - index) >= _MIN_RUN_LENGTH and not flags_live_after(disasms, end - 1):
                start = insns[index]["addr"]
                continuation = insns[end]["addr"]
                if continuation - start >= _TRAMPOLINE_SIZE:
                    return _Run(start, continuation, [op for op in decoded[index:end] if op is not None])
            index = end
        return None

    def _virtualize_run(self, binary: Any, run: _Run) -> dict[str, Any] | None:
        """Inject the VM for ``run`` and install the trampoline."""
        blob_vaddr = predict_blob_vaddr(binary)
        if blob_vaddr is None:
            return None

        rng = random.Random(random.getrandbits(64))
        ops = inject_junk_ops(run.ops, rng)
        scheme = build_vm_scheme(rng)
        blob = build_vm_blob(ops, blob_vaddr, run.continuation, scheme)
        if blob is None:
            return None

        span = run.continuation - run.start
        original_bytes = binary.read_bytes(run.start, span)
        if not original_bytes or len(original_bytes) != span:
            return None

        checkpoint = self._create_mutation_checkpoint("virtualize")

        injected_vaddr = inject_blob(binary, blob)
        if injected_vaddr is None:
            return None
        if injected_vaddr != blob_vaddr:
            self._rollback_uncommitted(binary, checkpoint, reason="VM blob landed at an unexpected vaddr; aborting")
            return None

        relative = injected_vaddr - (run.start + _TRAMPOLINE_SIZE)
        trampoline = b"\xe9" + struct.pack("<i", relative) + b"\x90" * (span - _TRAMPOLINE_SIZE)
        if not binary.write_bytes(run.start, trampoline):
            self._rollback_uncommitted(binary, checkpoint, reason="failed to write VM trampoline; aborting")
            return None

        mutated_bytes = binary.read_bytes(run.start, span)
        record = self._record_mutation(
            function_address=run.start,
            start_address=run.start,
            end_address=run.continuation - 1,
            original_bytes=original_bytes,
            mutated_bytes=mutated_bytes,
            original_disasm=f"; {len(run.ops)} instructions",
            mutated_disasm=f"; trampoline -> VM ({len(blob)} bytes)",
            mutation_kind="code_virtualization",
            metadata={"instructions_count": len(run.ops), "bytecode_size": len(blob)},
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return None
        return {"instructions": len(run.ops), "bytecode": len(blob)}

    def _virtualize_function(self, binary: Any, func: dict[str, Any]) -> dict[str, Any] | None:
        """Virtualize a whole single-exit function via the control-flow VM."""
        try:
            disasm = binary.r2.cmdj(f"pdfj @ {func['addr']}")
        except Exception:
            return None
        if not disasm or "ops" not in disasm:
            return None
        rng = random.Random(random.getrandbits(64))
        region = extract_region(disasm["ops"], rng)
        if region is None:
            return None

        blob_vaddr = predict_blob_vaddr(binary)
        if blob_vaddr is None:
            return None
        # Nest when asked, falling back to a single layer if the region has no
        # peelable register-op run.
        blob = None
        if self.vm_nesting_depth >= 2:
            blob = build_nested_region_blob(region, blob_vaddr, rng, depth=self.vm_nesting_depth)
        if blob is None:
            scheme = build_region_scheme(region, rng)
            blob = build_region_blob(region, blob_vaddr, scheme)
        if blob is None:
            return None

        original_bytes = binary.read_bytes(region.entry_vaddr, _TRAMPOLINE_SIZE)
        if not original_bytes or len(original_bytes) != _TRAMPOLINE_SIZE:
            return None

        checkpoint = self._create_mutation_checkpoint("virtualize_function")
        injected_vaddr = inject_blob(binary, blob)
        if injected_vaddr is None:
            return None
        if injected_vaddr != blob_vaddr:
            self._rollback_uncommitted(binary, checkpoint, reason="VM blob landed at an unexpected vaddr; aborting")
            return None

        relative = injected_vaddr - (region.entry_vaddr + _TRAMPOLINE_SIZE)
        trampoline = b"\xe9" + struct.pack("<i", relative)
        if not binary.write_bytes(region.entry_vaddr, trampoline):
            self._rollback_uncommitted(binary, checkpoint, reason="failed to write VM trampoline; aborting")
            return None

        # The original body instructions are now unreachable (the VM does their
        # work and exits to the terminators, which stay native). Overwrite them
        # with per-instance random bytes so the logic cannot be recovered. Only
        # body ranges are filled - terminators and the trampoline are skipped.
        trampoline_end = region.entry_vaddr + _TRAMPOLINE_SIZE
        for addr, size in region.body_ranges:
            fill_start = max(addr, trampoline_end)
            fill_size = addr + size - fill_start
            if fill_size <= 0:
                continue
            junk = bytes(random.randrange(256) for _ in range(fill_size))
            if not binary.write_bytes(fill_start, junk):
                self._rollback_uncommitted(binary, checkpoint, reason="failed to overwrite dead body; aborting")
                return None

        instruction_count = sum(1 for item in region.instructions if item[0] != "exit")
        record = self._record_mutation(
            function_address=func["addr"],
            start_address=region.entry_vaddr,
            end_address=region.entry_vaddr + _TRAMPOLINE_SIZE - 1,
            original_bytes=original_bytes,
            mutated_bytes=binary.read_bytes(region.entry_vaddr, _TRAMPOLINE_SIZE),
            original_disasm=f"; {instruction_count} instructions (control-flow region)",
            mutated_disasm=f"; trampoline -> VM ({len(blob)} bytes)",
            mutation_kind="code_virtualization",
            metadata={"instructions_count": instruction_count, "bytecode_size": len(blob)},
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return None
        return {"instructions": instruction_count, "bytecode": len(blob)}

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply code virtualization to provable register runs."""
        self._reset_random()
        self._ensure_analyzed(binary)
        logger.info("Applying code virtualization")

        virtualized = 0
        skipped = 0
        total_insns = 0
        total_bytecode = 0

        for func in binary.get_functions():
            if virtualized >= self.max_functions:
                break
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue
            if random.random() > self.probability:
                skipped += 1
                continue

            # Prefer whole-function control-flow virtualization; fall back to
            # straight-line runs when the function is not fully reducible.
            region_result = self._virtualize_function(binary, func)
            if region_result is not None:
                total_insns += region_result["instructions"]
                total_bytecode += region_result["bytecode"]
                virtualized += 1
                continue

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as exc:
                logger.debug("Failed to get blocks for 0x%x: %s", func["addr"], exc)
                continue

            for block in blocks:
                run = self._find_run(binary, block)
                if run is None:
                    continue
                result = self._virtualize_run(binary, run)
                if result is None:
                    continue
                total_insns += result["instructions"]
                total_bytecode += result["bytecode"]
                virtualized += 1
                break

        return {
            "functions_virtualized": virtualized,
            "functions_skipped": skipped,
            "total_instructions": total_insns,
            "total_bytecode_bytes": total_bytecode,
        }
