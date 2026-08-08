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
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
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
from r2morph.mutations.code_virtualization_region_decoders import (
    _decode_fp_arith,
    _decode_fp_arith_idx,
    _decode_fp_arith_mem,
    _decode_fp_arith_riprel,
    _decode_fp_convert,
    _decode_fp_indexed,
    _decode_fp_mem,
    _decode_fp_packed_arith,
    _decode_fp_packed_mem,
    _decode_fp_riprel,
    _decode_lea,
    _decode_lea_indexed,
    _decode_memory_mov,
    _decode_movx,
    _decode_op_mem,
    _decode_op_mem_indexed,
    _decode_riprel_mov,
)
from r2morph.mutations.code_virtualization_region_nesting import build_nested_region_blob
from r2morph.mutations.instruction_substitution_helpers import flags_live_after

logger = logging.getLogger(__name__)

# Minimum instructions in a run worth virtualizing.
_MIN_RUN_LENGTH = 2
# A relative trampoline jump needs 5 bytes in the run's byte span.
_TRAMPOLINE_SIZE = 5
# Upper bound on instructions read when gathering a dispatch-shaped function
# linearly (its analysis stops at the computed jump, so there is no function size).
_MAX_DISPATCH_INSNS = 256


_MEM_ARITH_MNEMONICS = ("add", "sub", "xor", "and", "or")


def _decode_run_item(
    text: str, insn_addr: int = 0, insn_size: int = 0
) -> (
    VirtualizedOp
    | VirtualizedMemOp
    | VirtualizedFpMemOp
    | VirtualizedFpArithOp
    | VirtualizedFpConvertOp
    | VirtualizedFpArithMemOp
    | VirtualizedFpPackedOp
    | VirtualizedFpPackedMemOp
    | None
):
    """Decode one instruction into a VM item: a register/immediate op, a memory
    load/store ``mov``, a scalar ``movsd``/``movss`` xmm<->[base+disp], an ``<op>
    reg, [base+disp]``, a ``mov reg, [rip+disp]``, or ``None`` if the VM cannot
    reproduce it (ends the run)."""
    op = decode_instruction(text)
    if op is not None:
        return op
    # Scalar FP load/store is tried before the GP mov decoders: movsd/movss share
    # the "mov" prefix but route to the xmm save area, not a GP slot.
    fp = _decode_fp_mem(text)
    if fp is not None:
        kind, xmm_index, base_slot, disp, width = fp
        return VirtualizedFpMemOp(kind, xmm_index, base_slot, disp, width)
    fp_rip = _decode_fp_riprel(text, insn_addr, insn_size)
    if fp_rip is not None:
        # The rip target is an absolute address carried in the disp field; the
        # encoder stores it as an offset from the bytecode base. No base slot.
        rip_kind, rip_xmm, target, rip_width = fp_rip
        return VirtualizedFpMemOp(rip_kind, rip_xmm, -1, target, rip_width)
    fp_idx = _decode_fp_indexed(text)
    # Only the base form (7-tuple) is virtualized; the no-base "idxnb" form (an
    # absolute [index*scale+disp], a 6-tuple without the base slot) stays native.
    if fp_idx is not None and len(fp_idx) == 7:
        idx_kind, idx_xmm, idx_base, idx_index, idx_shift, idx_disp, idx_width = fp_idx
        return VirtualizedFpMemOp(idx_kind, idx_xmm, idx_base, idx_disp, idx_width, idx_index, idx_shift)
    fp_arith = _decode_fp_arith(text)
    if fp_arith is not None:
        _kind, fp_op, dst_index, src_index, arith_width = fp_arith
        return VirtualizedFpArithOp(fp_op, dst_index, src_index, arith_width)
    cvt = _decode_fp_convert(text)
    if cvt is not None:
        direction, fp_w, gp_w, a, b = cvt
        # _decode_fp_convert orders the last two fields by direction; normalize to
        # (xmm_index, gp_slot) so the op carries them in a fixed order.
        xmm_index, gp_slot = (a, b) if direction == "cvti2f" else (b, a)
        return VirtualizedFpConvertOp(direction, fp_w, gp_w, xmm_index, gp_slot)
    fp_arith_mem = _decode_fp_arith_mem(text)
    if fp_arith_mem is not None:
        _kind, am_op, am_xmm, am_base, am_disp, am_width = fp_arith_mem
        return VirtualizedFpArithMemOp(am_op, am_xmm, am_base, am_disp, am_width)
    fp_arith_rip = _decode_fp_arith_riprel(text, insn_addr, insn_size)
    if fp_arith_rip is not None:
        # rip-relative constant-pool source: base_index -1, disp carries the target.
        _kind, ar_op, ar_xmm, ar_target, ar_width = fp_arith_rip
        return VirtualizedFpArithMemOp(ar_op, ar_xmm, -1, ar_target, ar_width)
    fp_arith_idx = _decode_fp_arith_idx(text)
    if fp_arith_idx is not None:
        _kind, ai_op, ai_xmm, ai_base, ai_index, ai_shift, ai_disp, ai_width = fp_arith_idx
        return VirtualizedFpArithMemOp(ai_op, ai_xmm, ai_base, ai_disp, ai_width, ai_index, ai_shift)
    fp_packed = _decode_fp_packed_arith(text)
    if fp_packed is not None:
        _kind, pk_mnemonic, pk_dst, pk_src = fp_packed
        return VirtualizedFpPackedOp(pk_mnemonic, pk_dst, pk_src)
    # Packed 128-bit load/store is tried before the GP mov decoders: movaps/movups
    # share the "mov" prefix but move the full 128 bits through the xmm save area.
    fp_packed_mem = _decode_fp_packed_mem(text)
    if fp_packed_mem is not None:
        pm_kind, pm_xmm, pm_base, pm_disp = fp_packed_mem
        return VirtualizedFpPackedMemOp(pm_kind, pm_xmm, pm_base, pm_disp)
    mem = _decode_memory_mov(text)
    if mem is not None:
        kind, reg_slot, base_slot, disp, width = mem
        return VirtualizedMemOp(kind, reg_slot, base_slot, disp, width)
    movx = _decode_movx(text)
    if movx is not None and movx[0] == "movx":
        _, ext, src_size, dst_width, reg_slot, base_slot, disp = movx
        kind = f"mov{ext}x{'b' if src_size == 8 else 'w'}"
        return VirtualizedMemOp(kind, reg_slot, base_slot, disp, dst_width)
    if movx is not None and movx[0] == "movxidx":
        _, ext, src_size, dst_width, reg_slot, base_slot, index_slot, shift, disp = movx
        kind = f"mov{ext}x{'b' if src_size == 8 else 'w'}idx"
        return VirtualizedMemOp(kind, reg_slot, base_slot, disp, dst_width, index_slot, shift)
    riprel = _decode_riprel_mov(text, insn_addr, insn_size)
    if riprel is not None:
        kind, reg_slot, target, width = riprel
        # The rip-relative target is an absolute address (carried in the disp field);
        # the encoder stores it as an offset from the bytecode base. No base slot.
        return VirtualizedMemOp("loadrip" if kind == "riprel_load" else "storerip", reg_slot, -1, target, width)
    mnemonic = text.split(None, 1)[0].lower() if text.strip() else ""
    if mnemonic in _MEM_ARITH_MNEMONICS:
        decoded = _decode_op_mem(text, mnemonic, insn_addr, insn_size)
        if decoded is not None and decoded[0] == "opmem":
            _, _mnemonic, reg_slot, base_slot, disp, width = decoded
            return VirtualizedMemOp(f"mem{mnemonic}", reg_slot, base_slot, disp, width)
        if decoded is not None and decoded[0] == "opriprel":
            _, _mnemonic, reg_slot, target, width = decoded
            return VirtualizedMemOp(f"mem{mnemonic}rip", reg_slot, -1, target, width)
        indexed = _decode_op_mem_indexed(text, mnemonic)
        if indexed is not None and indexed[0] == "opmemidx":
            _, _mnemonic, reg_slot, base_slot, index_slot, shift, disp, width = indexed
            return VirtualizedMemOp(f"mem{mnemonic}idx", reg_slot, base_slot, disp, width, index_slot, shift)
    elif mnemonic == "lea":
        decoded = _decode_lea(text, insn_addr, insn_size)
        if decoded is not None and decoded[0] == "lea":
            _, reg_slot, base_slot, disp, width = decoded
            return VirtualizedMemOp("lea", reg_slot, base_slot, disp, width)
        if decoded is not None and decoded[0] == "learip":
            _, reg_slot, target, width = decoded
            return VirtualizedMemOp("learip", reg_slot, -1, target, width)
        indexed = _decode_lea_indexed(text)
        if indexed is not None and indexed[0] == "leaidx":
            _, reg_slot, base_slot, index_slot, shift, disp, width = indexed
            return VirtualizedMemOp("leaidx", reg_slot, base_slot, disp, width, index_slot, shift)
    return None


class _Run:
    """A virtualizable straight-line run inside one basic block."""

    __slots__ = ("start", "continuation", "ops")

    def __init__(
        self,
        start: int,
        continuation: int,
        ops: list[
            VirtualizedOp
            | VirtualizedMemOp
            | VirtualizedFpMemOp
            | VirtualizedFpArithOp
            | VirtualizedFpConvertOp
            | VirtualizedFpArithMemOp
            | VirtualizedFpPackedOp
            | VirtualizedFpPackedMemOp
        ],
    ) -> None:
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
          second, independently-keyed inner VM (default: 2, nested when a
          peelable register-op run exists, single-layer otherwise)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeVirtualization", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 5)
        self.vm_nesting_depth = self.config.get("vm_nesting_depth", 2)
        # Opt-in: also virtualize dispatch-shaped functions (a computed-goto loop
        # whose register-indirect jump becomes an ijmp re-entering the VM). Off by
        # default - the ordinary path never touches computed jumps.
        self.virtualize_dispatch = self.config.get("virtualize_dispatch", False)
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
        decoded = [_decode_run_item(insn.get("opcode", ""), insn.get("addr", 0), insn.get("size", 0)) for insn in insns]

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
        return self._emit_region(binary, func, region, rng, use_nesting=True)

    def _gather_dispatch_ops(self, binary: Any, func: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Linear instruction list of a dispatch-shaped function.

        A computed-goto loop's function analysis stops at the register-indirect
        jump (r2 cannot follow it), so ``pdfj`` returns a truncated body. Read the
        function linearly from its entry to the first terminator instead.
        """
        try:
            ops = binary.r2.cmdj(f"pdj {_MAX_DISPATCH_INSNS} @ {func['addr']}")
        except Exception:
            return None
        if not ops:
            return None
        gathered: list[dict[str, Any]] = []
        for insn in ops:
            if insn.get("type") == "invalid" or insn.get("opcode") == "invalid":
                break
            gathered.append(insn)
            if insn.get("type") in ("ret", "swi", "syscall"):
                return gathered
        return None  # no terminator found within the window

    def _reachable_blocks(self, by_addr: dict[int, dict[str, Any]], entry: int) -> set[int]:
        """Block addresses reachable from ``entry`` over r2's resolved edges.

        Follows each block's static ``jump``/``fail`` successors and, for a resolved
        switch block, its ``switch_op`` case targets and default - so every case block
        r2 discovered is gathered without reading or guessing the jump table.
        """
        reachable: set[int] = set()
        work = [entry]
        while work:
            addr = work.pop()
            if addr in reachable or addr not in by_addr:
                continue
            reachable.add(addr)
            block = by_addr[addr]
            successors: list[Any] = [block.get("jump"), block.get("fail")]
            switch_op = block.get("switch_op")
            if isinstance(switch_op, dict):
                successors.extend(case.get("jump") for case in switch_op.get("cases", []))
                successors.append(switch_op.get("def_val"))
            work.extend(succ for succ in successors if isinstance(succ, int) and succ in by_addr)
        return reachable

    def _block_ops(
        self, binary: Any, entry: int, by_addr: dict[int, dict[str, Any]], reachable: set[int]
    ) -> list[dict[str, Any]]:
        """Materialize the instructions of the reachable blocks, address-sorted.

        Prefers ``pdfj`` (one call covering a fully-resolved function) and fills any
        reachable block it did not cover with a per-block ``pdbj``.
        """
        ranges = [(by_addr[a]["addr"], by_addr[a]["addr"] + by_addr[a].get("size", 0)) for a in reachable]

        def in_reachable(addr: int) -> bool:
            return any(lo <= addr < hi for lo, hi in ranges)

        ops_by_addr: dict[int, dict[str, Any]] = {}
        for op in binary.get_function_disasm(entry):
            addr = op.get("addr")
            if isinstance(addr, int) and in_reachable(addr):
                ops_by_addr[addr] = op
        for lo, hi in ranges:
            if any(lo <= addr < hi for addr in ops_by_addr):
                continue
            for op in binary.r2.cmdj(f"pdbj @ {lo}") or []:
                addr = op.get("addr")
                if isinstance(addr, int) and lo <= addr < hi:
                    ops_by_addr[addr] = op
        return [ops_by_addr[addr] for addr in sorted(ops_by_addr)]

    def _gather_cfg_ops(self, binary: Any, func: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Gather a function's full CFG closure from r2's block analysis.

        Returns an entry-first, address-sorted op list covering every block reachable
        from the entry over static and resolved-switch edges, or ``None`` when the
        function is not a resolved switch (the caller then falls back to the linear
        dispatch gather). Gating on a resolved ``switch_op`` keeps the whole-function
        ``pdfj`` path responsible for ordinary multi-block functions and never guesses
        an extent for an unresolved computed jump.
        """
        entry = func["addr"]
        try:
            blocks = binary.get_basic_blocks(entry)
        except Exception:
            return None
        by_addr = {b["addr"]: b for b in blocks if isinstance(b.get("addr"), int)}
        if entry not in by_addr:
            return None
        reachable = self._reachable_blocks(by_addr, entry)
        if not any(isinstance(by_addr[a].get("switch_op"), dict) for a in reachable):
            return None
        ops = self._block_ops(binary, entry, by_addr, reachable)
        return ops or None

    def _virtualize_dispatch_function(self, binary: Any, func: dict[str, Any]) -> dict[str, Any] | None:
        """Virtualize a dispatch-shaped function (opt-in), lowering its computed
        jump to an ijmp that re-enters the VM at the virtualized target."""
        cfg_ops = self._gather_cfg_ops(binary, func)
        ops = cfg_ops if cfg_ops is not None else self._gather_dispatch_ops(binary, func)
        if ops is None:
            return None
        rng = random.Random(random.getrandbits(64))
        region = extract_region(ops, rng, allow_computed_jump=True)
        if region is None:
            return None
        computed = {item[0] for item in region.instructions} & {"ijmp", "ijmpmem", "ijmpmemnb"}
        if not computed:
            return None
        # A memory-indirect switch (ijmpmem/ijmpmemnb) re-enters the VM at a case block
        # via the target map, so every case must be gathered. That is only guaranteed
        # by the CFG-closure gather over r2's resolved switch_op; the linear gather may
        # miss a case, which would make a runtime target-map lookup fall through to the
        # wrong default exit, so a memory-indirect switch outside the CFG path stays
        # native.
        if cfg_ops is None and (computed & {"ijmpmem", "ijmpmemnb"}):
            return None
        # The dispatch path never nests: nesting peels straight-line arithmetic runs
        # and does not model the computed-jump re-entry, so the region VM is emitted
        # as a single layer.
        return self._emit_region(binary, func, region, rng, use_nesting=False)

    def _emit_region(
        self, binary: Any, func: dict[str, Any], region: Any, rng: random.Random, use_nesting: bool
    ) -> dict[str, Any] | None:
        """Build the interpreter for a lowered region, inject it, patch the
        trampoline, and overwrite the dead body. Shared by the whole-function and
        dispatch paths; ``use_nesting`` requests the nested-layer blob."""
        blob_vaddr = predict_blob_vaddr(binary)
        if blob_vaddr is None:
            return None
        # Nest by default, falling back to a single layer if the region has no
        # peelable register-op run. Both builders pick the dispatch shape (threaded
        # jump table or binary-search switch) per build from the region scheme, so
        # the dispatch architecture varies whether the build nests or not.
        blob = None
        if use_nesting and self.vm_nesting_depth >= 2:
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
            # Opt-in: a dispatch-shaped function (rejected by the reducible path
            # above because of its computed jump) is virtualized through the
            # dispatch contract instead.
            if region_result is None and self.virtualize_dispatch:
                region_result = self._virtualize_dispatch_function(binary, func)
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
