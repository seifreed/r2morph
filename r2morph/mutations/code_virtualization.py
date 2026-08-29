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
import struct
from dataclasses import dataclass
from typing import Any, cast

import r2morph.core.randomness as random
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.base import MutationPass
from r2morph.mutations.code_virtualization_apply import apply_code_virtualization
from r2morph.mutations.code_virtualization_engine import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedFpScalarVexOp,
    VirtualizedMemOp,
    VirtualizedOp,
    build_vm_blob,
    build_vm_scheme,
    decode_instruction,
    inject_junk_ops,
)
from r2morph.mutations.code_virtualization_engine_models import VirtualizedAddress
from r2morph.mutations.code_virtualization_inject import inject_blob, predict_blob_vaddr
from r2morph.mutations.code_virtualization_region import (
    build_region_scheme,
    extract_region,
)
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    FpIndexedItem,
    FpIndexedNoBaseItem,
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
    _decode_fp_vex_packed_arith,
    _decode_fp_vex_scalar_arith,
)
from r2morph.mutations.code_virtualization_region_memory_decoders import (
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

_FP_INDEXED_TUPLE_SIZE = 7
_FP_INDEXED_NO_BASE_TUPLE_SIZE = 6
_FP_SINGLE_WIDTH_BITS = 32
_BYTE_WIDTH_BITS = 8
_MIN_NESTING_DEPTH = 2

# Minimum instructions in a run worth virtualizing.
_MIN_RUN_LENGTH = 2
# A relative trampoline jump needs 5 bytes in the run's byte span.
_TRAMPOLINE_SIZE = 5
# Upper bound on instructions read when gathering a dispatch-shaped function
# linearly (its analysis stops at the computed jump, so there is no function size).
_MAX_DISPATCH_INSNS = 256
_MAX_UNSUPPORTED_RECORDS = 256
_COMPUTED_JUMP_TYPES = frozenset({"ujmp", "rjmp", "ijmp", "mjmp", "irjmp"})


_MEM_ARITH_MNEMONICS = ("add", "sub", "xor", "and", "or")

VirtualizedRunItem = (
    VirtualizedOp
    | VirtualizedMemOp
    | VirtualizedFpMemOp
    | VirtualizedFpArithOp
    | VirtualizedFpScalarVexOp
    | VirtualizedFpConvertOp
    | VirtualizedFpArithMemOp
    | VirtualizedFpPackedOp
    | VirtualizedFpPackedMemOp
)


def _decode_fp_memory_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedFpMemOp | None:
    decoded = _decode_fp_mem(text)
    if decoded is not None:
        kind, xmm_index, base_slot, disp, width = decoded
        return VirtualizedFpMemOp(kind, xmm_index, VirtualizedAddress(base_slot, disp), width)
    rip_relative = _decode_fp_riprel(text, insn_addr, insn_size)
    if rip_relative is not None:
        kind, xmm_index, target, width = rip_relative
        return VirtualizedFpMemOp(kind, xmm_index, VirtualizedAddress(-1, target), width)
    indexed = _decode_fp_indexed(text)
    if indexed is not None and len(indexed) == _FP_INDEXED_TUPLE_SIZE:
        kind, xmm_index, base_slot, index_slot, shift, disp, width = cast(FpIndexedItem, indexed)
        return VirtualizedFpMemOp(
            kind,
            xmm_index,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    if indexed is not None and len(indexed) == _FP_INDEXED_NO_BASE_TUPLE_SIZE:
        kind, xmm_index, index_slot, shift, disp, width = cast(FpIndexedNoBaseItem, indexed)
        return VirtualizedFpMemOp(
            kind,
            xmm_index,
            VirtualizedAddress(-1, disp, index_slot, shift),
            width,
        )
    return None


def _decode_fp_arithmetic_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedRunItem | None:
    decoded = _decode_fp_arith(text)
    if decoded is not None:
        _kind, operation, destination, source, width = decoded
        return VirtualizedFpArithOp(operation, destination, source, width)
    converted = _decode_fp_convert(text)
    if converted is not None:
        direction, fp_width, gp_width, first, second = converted
        xmm_index, gp_slot = (first, second) if direction == "cvti2f" else (second, first)
        return VirtualizedFpConvertOp(direction, fp_width, gp_width, xmm_index, gp_slot)
    memory = _decode_fp_arith_mem(text)
    if memory is not None:
        _kind, operation, xmm_index, base_slot, disp, width = memory
        return VirtualizedFpArithMemOp(operation, xmm_index, VirtualizedAddress(base_slot, disp, -1), width)
    rip_relative = _decode_fp_arith_riprel(text, insn_addr, insn_size)
    if rip_relative is not None:
        _kind, operation, xmm_index, target, width = rip_relative
        return VirtualizedFpArithMemOp(operation, xmm_index, VirtualizedAddress(-1, target, -1), width)
    indexed = _decode_fp_arith_idx(text)
    if indexed is not None:
        _kind, operation, xmm_index, base_slot, index_slot, shift, disp, width = indexed
        return VirtualizedFpArithMemOp(
            operation,
            xmm_index,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_fp_scalar_vex_item(text: str) -> VirtualizedFpScalarVexOp | None:
    decoded = _decode_fp_vex_scalar_arith(text)
    if decoded is None:
        return None
    _kind, operation, destination, first_source, second_source, width = decoded
    suffix = "ss" if width == _FP_SINGLE_WIDTH_BITS else "sd"
    return VirtualizedFpScalarVexOp(f"v{operation}{suffix}", destination, first_source, second_source)


def _decode_fp_packed_item(text: str) -> VirtualizedRunItem | None:
    vex = _decode_fp_vex_packed_arith(text)
    if vex is not None:
        _kind, mnemonic, destination, first_source, second_source = vex
        if destination == first_source:
            return VirtualizedFpPackedOp(mnemonic, destination, second_source, vex=True)
        return VirtualizedFpPackedOp(
            f"v{mnemonic}",
            destination,
            second_source,
            vex=True,
            src1_index=first_source,
        )
    decoded = _decode_fp_packed_arith(text)
    if decoded is not None:
        _kind, mnemonic, destination, source = decoded
        return VirtualizedFpPackedOp(mnemonic, destination, source)
    memory = _decode_fp_packed_mem(text)
    if memory is not None:
        kind, xmm_index, base_slot, disp = memory
        return VirtualizedFpPackedMemOp(kind, xmm_index, base_slot, disp)
    return None


def _decode_gp_memory_item(text: str, insn_addr: int, insn_size: int) -> VirtualizedMemOp | None:
    decoded = _decode_memory_mov(text)
    if decoded is not None:
        kind, register_slot, base_slot, disp, width = decoded
        return VirtualizedMemOp(kind, register_slot, VirtualizedAddress(base_slot, disp), width)
    extended = _decode_movx(text)
    if extended is not None and extended[0] == "movx":
        _, extension, source_size, width, register_slot, base_slot, disp = extended
        kind = f"mov{extension}x{'b' if source_size == _BYTE_WIDTH_BITS else 'w'}"
        return VirtualizedMemOp(kind, register_slot, VirtualizedAddress(base_slot, disp), width)
    if extended is not None and extended[0] == "movxidx":
        _, extension, source_size, width, register_slot, base_slot, index_slot, shift, disp = extended
        kind = f"mov{extension}x{'b' if source_size == _BYTE_WIDTH_BITS else 'w'}idx"
        return VirtualizedMemOp(
            kind,
            register_slot,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    rip_relative = _decode_riprel_mov(text, insn_addr, insn_size)
    if rip_relative is not None:
        kind, register_slot, target, width = rip_relative
        return VirtualizedMemOp(
            "loadrip" if kind == "riprel_load" else "storerip",
            register_slot,
            VirtualizedAddress(-1, target),
            width,
        )
    return None


def _decode_memory_arithmetic_item(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> VirtualizedMemOp | None:
    if mnemonic not in _MEM_ARITH_MNEMONICS:
        return None
    decoded = _decode_op_mem(text, mnemonic, insn_addr, insn_size)
    if decoded is not None and decoded[0] == "opmem":
        _, _mnemonic, register_slot, base_slot, disp, width = decoded
        return VirtualizedMemOp(f"mem{mnemonic}", register_slot, VirtualizedAddress(base_slot, disp), width)
    if decoded is not None and decoded[0] == "opriprel":
        _, _mnemonic, register_slot, target, width = decoded
        return VirtualizedMemOp(f"mem{mnemonic}rip", register_slot, VirtualizedAddress(-1, target), width)
    indexed = _decode_op_mem_indexed(text, mnemonic)
    if indexed is not None and indexed[0] == "opmemidx":
        _, _mnemonic, register_slot, base_slot, index_slot, shift, disp, width = indexed
        return VirtualizedMemOp(
            f"mem{mnemonic}idx",
            register_slot,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_lea_item(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> VirtualizedMemOp | None:
    if mnemonic != "lea":
        return None
    decoded = _decode_lea(text, insn_addr, insn_size)
    if decoded is not None and decoded[0] == "lea":
        _, register_slot, base_slot, disp, width = decoded
        return VirtualizedMemOp("lea", register_slot, VirtualizedAddress(base_slot, disp), width)
    if decoded is not None and decoded[0] == "learip":
        _, register_slot, target, width = decoded
        return VirtualizedMemOp("learip", register_slot, VirtualizedAddress(-1, target), width)
    indexed = _decode_lea_indexed(text)
    if indexed is not None and indexed[0] == "leaidx":
        _, register_slot, base_slot, index_slot, shift, disp, width = indexed
        return VirtualizedMemOp(
            "leaidx",
            register_slot,
            VirtualizedAddress(base_slot, disp, index_slot, shift),
            width,
        )
    return None


def _decode_run_item(text: str, insn_addr: int = 0, insn_size: int = 0) -> VirtualizedRunItem | None:
    """Decode one instruction into a VM item: a register/immediate op, a memory
    load/store ``mov``, a scalar ``movsd``/``movss`` xmm<->[base+disp], an ``<op>
    reg, [base+disp]``, a ``mov reg, [rip+disp]``, or ``None`` if the VM cannot
    reproduce it (ends the run)."""
    op = decode_instruction(text)
    if op is not None:
        return op
    mnemonic = text.split(None, 1)[0].lower() if text.strip() else ""
    decoded_items = (
        _decode_fp_memory_item(text, insn_addr, insn_size),
        _decode_fp_scalar_vex_item(text),
        _decode_fp_arithmetic_item(text, insn_addr, insn_size),
        _decode_fp_packed_item(text),
        _decode_gp_memory_item(text, insn_addr, insn_size),
        _decode_memory_arithmetic_item(text, mnemonic, insn_addr, insn_size),
        _decode_lea_item(text, mnemonic, insn_addr, insn_size),
    )
    return next((item for item in decoded_items if item is not None), None)


class _Run:
    """A virtualizable straight-line run inside one basic block."""

    __slots__ = ("continuation", "ops", "start")

    def __init__(
        self,
        start: int,
        continuation: int,
        ops: list[VirtualizedRunItem],
    ) -> None:
        self.start = start
        self.continuation = continuation
        self.ops = ops


@dataclass(frozen=True)
class _RunBuild:
    blob_vaddr: int
    blob: bytes
    original_bytes: bytes
    span: int


class CodeVirtualizationPass(MutationPass):
    """
    Mutation pass that virtualizes register runs into custom VM bytecode.

    Config options:
        - probability: Probability of virtualizing each function (default: 0.3)
        - max_functions: Maximum functions to virtualize (default: 5)
        - vm_nesting_depth: VM layers per function; 2 wraps the region in a
          second, independently-keyed inner VM (default: 2, nested when a
          peelable register-op run exists, single-layer otherwise)
        - reject_partial_virtualization: Reject a function when only a
          straight-line region can be proven (default: False)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeVirtualization", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 5)
        self.vm_nesting_depth = self.config.get("vm_nesting_depth", 2)
        self.reject_partial_virtualization = self.config.get("reject_partial_virtualization", False)
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

    @staticmethod
    def _build_run(binary: Any, run: _Run) -> _RunBuild | None:
        blob_vaddr = predict_blob_vaddr(binary)
        if blob_vaddr is None:
            return None
        rng = random.Random(random.getrandbits(64))
        ops = inject_junk_ops(run.ops, rng)
        blob = build_vm_blob(ops, blob_vaddr, run.continuation, build_vm_scheme(rng))
        if blob is None:
            return None
        span = run.continuation - run.start
        original_bytes = binary.read_bytes(run.start, span)
        if not original_bytes or len(original_bytes) != span:
            return None
        return _RunBuild(blob_vaddr, blob, bytes(original_bytes), span)

    def _install_run(self, binary: Any, run: _Run, build: _RunBuild) -> dict[str, Any] | None:
        checkpoint = self._create_mutation_checkpoint("virtualize")
        injected_vaddr = inject_blob(binary, build.blob)
        if injected_vaddr is None:
            return None
        if injected_vaddr != build.blob_vaddr:
            self._rollback_uncommitted(binary, checkpoint, reason="VM blob landed at an unexpected vaddr; aborting")
            return None
        relative = injected_vaddr - (run.start + _TRAMPOLINE_SIZE)
        trampoline = b"\xe9" + struct.pack("<i", relative) + b"\x90" * (build.span - _TRAMPOLINE_SIZE)
        if not binary.write_bytes(run.start, trampoline):
            self._rollback_uncommitted(binary, checkpoint, reason="failed to write VM trampoline; aborting")
            return None
        record = self._record_mutation(
            function_address=run.start,
            start_address=run.start,
            end_address=run.continuation - 1,
            original_bytes=build.original_bytes,
            mutated_bytes=binary.read_bytes(run.start, build.span),
            original_disasm=f"; {len(run.ops)} instructions",
            mutated_disasm=f"; trampoline -> VM ({len(build.blob)} bytes)",
            mutation_kind="code_virtualization",
            metadata={"instructions_count": len(run.ops), "bytecode_size": len(build.blob)},
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return None
        return {"instructions": len(run.ops), "bytecode": len(build.blob)}

    def _virtualize_run(self, binary: Any, run: _Run) -> dict[str, Any] | None:
        """Inject the VM for ``run`` and install the trampoline."""
        build = self._build_run(binary, run)
        return None if build is None else self._install_run(binary, run, build)

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

    def _has_computed_jump(self, binary: Any, func: dict[str, Any]) -> bool:
        """Detect dispatch-shaped functions before the ordinary region path."""
        return self._find_computed_jump(binary, func) is not None

    def _find_computed_jump(self, binary: Any, func: dict[str, Any]) -> dict[str, Any] | None:
        """Return the first computed jump that blocks the default VM path."""
        try:
            ops = binary.r2.cmdj(f"pdj {_MAX_DISPATCH_INSNS} @ {func['addr']}") or []
        except (ValueError, OSError, BrokenPipeError, RuntimeError):
            return None
        return next((op for op in ops if op.get("type") in _COMPUTED_JUMP_TYPES), None)

    def _find_first_unvirtualizable_instruction(self, binary: Any, func: dict[str, Any]) -> dict[str, Any] | None:
        """Find the first instruction rejected by the whole-function classifier."""
        try:
            disasm = binary.r2.cmdj(f"pdfj @ {func['addr']}")
        except (ValueError, OSError, BrokenPipeError, RuntimeError):
            return None
        if not isinstance(disasm, dict):
            return None
        instructions = [instruction for instruction in disasm.get("ops", []) if isinstance(instruction, dict)]
        for index, instruction in enumerate(instructions):
            kind = instruction.get("type")
            if kind == "ret":
                continue
            if kind in ("swi", "syscall"):
                next_instruction = instructions[index + 1] if index + 1 < len(instructions) else None
                if next_instruction is None or next_instruction.get("type") == "ret":
                    continue
            if classification._classify(instruction, allow_computed_jump=self.virtualize_dispatch) is None:
                return cast(dict[str, Any], instruction)
        return None

    @staticmethod
    def _unsupported_instruction_diagnostic(instruction: dict[str, Any] | None) -> tuple[str, str]:
        """Map a rejected instruction to a stable capability label and reason."""
        if instruction is None:
            return "provable_function_shape", "no supported virtualization shape was proven"
        kind = str(instruction.get("type", ""))
        opcode = str(instruction.get("opcode", "")).lower()
        if kind in _COMPUTED_JUMP_TYPES:
            capability, reason = "computed_control_flow", "computed control flow is not enabled for this pass"
        elif "fs:" in opcode or "gs:" in opcode:
            capability, reason = "thread_local_storage", "thread-local storage addressing semantics were not proven"
        elif opcode.startswith("lock "):
            capability, reason = "thread_synchronization", "atomic synchronization semantics were not proven"
        elif kind in ("swi", "syscall") or opcode.startswith(("syscall", "sysenter", "int ")):
            capability, reason = "signals_and_system_calls", "system-call and interrupt semantics were not proven"
        elif kind in ("call", "rcall", "ucall") or opcode.startswith("call"):
            capability, reason = "calls", "call semantics were not proven for whole-function virtualization"
        elif "[" in opcode:
            capability, reason = (
                "memory_operands",
                "memory operand semantics were not proven for whole-function virtualization",
            )
        elif any(token in opcode for token in ("xmm", "ymm", "zmm", "st0", "st1")):
            capability, reason = "floating_point_and_simd", "floating-point or SIMD semantics were not proven"
        else:
            capability, reason = (
                "instruction_semantics",
                "instruction semantics were not proven for whole-function virtualization",
            )
        return capability, reason

    @staticmethod
    def _unsupported_record(
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        capability: str,
        reason: str,
        severity: str,
    ) -> dict[str, Any]:
        """Build a stable, actionable record for a rejected function."""
        return {
            "function_address": int(func.get("addr", 0)),
            "instruction_address": int((instruction or {}).get("addr", func.get("addr", 0))),
            "capability": capability,
            "reason": reason,
            "severity": severity,
        }

    def _record_diagnostic(
        self,
        records: list[dict[str, Any]],
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        diagnostic: tuple[str, str, str],
    ) -> None:
        """Keep actionable rejection evidence bounded per pass run."""
        severity, capability, reason = diagnostic
        if len(records) < _MAX_UNSUPPORTED_RECORDS:
            records.append(self._unsupported_record(func, instruction, capability, reason, severity))

    def _record_partial_virtualization(
        self,
        records: list[dict[str, Any]],
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        enabled: bool,
    ) -> int:
        """Record a warning when only a straight-line region was transformed."""
        if not enabled:
            return 0
        capability, reason = self._unsupported_instruction_diagnostic(instruction)
        self._record_diagnostic(
            records,
            func,
            instruction,
            (
                "warning",
                capability,
                f"only a straight-line region was proven; {reason}",
            ),
        )
        return 1

    def _record_unsupported_function(
        self,
        records: list[dict[str, Any]],
        func: dict[str, Any],
        instruction: dict[str, Any] | None,
        reason_prefix: str = "",
    ) -> None:
        """Record one bounded rejection with the best available capability."""
        capability, reason = self._unsupported_instruction_diagnostic(instruction)
        self._record_diagnostic(
            records,
            func,
            instruction,
            ("error", capability, f"{reason_prefix}{reason}"),
        )

    def _virtualize_fallback_run(
        self,
        binary: Any,
        func: dict[str, Any],
        unsupported_instruction: dict[str, Any] | None,
        partial_records: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, int]:
        """Virtualize one proven straight-line run, if a function has one."""
        try:
            blocks = binary.get_basic_blocks(func["addr"])
        except Exception as exc:
            logger.debug("Failed to get blocks for 0x%x: %s", func["addr"], exc)
            return None, 0
        for block in blocks:
            run = self._find_run(binary, block)
            if run is None:
                continue
            result = self._virtualize_run(binary, run)
            if result is not None:
                partial = self._record_partial_virtualization(partial_records, func, unsupported_instruction, True)
                return result, partial
        return None, 0

    def _build_region_payload(
        self, binary: Any, region: Any, rng: random.Random, use_nesting: bool
    ) -> tuple[int, bytes, bytes] | None:
        blob_vaddr = predict_blob_vaddr(binary)
        if blob_vaddr is None:
            return None
        blob = None
        if use_nesting and self.vm_nesting_depth >= _MIN_NESTING_DEPTH:
            blob = build_nested_region_blob(region, blob_vaddr, rng, depth=self.vm_nesting_depth)
        if blob is None:
            blob = build_region_blob(region, blob_vaddr, build_region_scheme(region, rng))
        if blob is None:
            return None
        original_bytes = binary.read_bytes(region.entry_vaddr, _TRAMPOLINE_SIZE)
        if not original_bytes or len(original_bytes) != _TRAMPOLINE_SIZE:
            return None
        return blob_vaddr, blob, bytes(original_bytes)

    def _install_region_payload(self, binary: Any, region: Any, blob_vaddr: int, blob: bytes) -> tuple[Any] | None:
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
        return (checkpoint,)

    def _overwrite_region_body(self, binary: Any, region: Any, checkpoint: Any) -> bool:
        trampoline_end = region.entry_vaddr + _TRAMPOLINE_SIZE
        for address, size in region.body_ranges:
            fill_start = max(address, trampoline_end)
            fill_size = address + size - fill_start
            if fill_size <= 0:
                continue
            junk = bytes(random.randrange(256) for _ in range(fill_size))
            if not binary.write_bytes(fill_start, junk):
                self._rollback_uncommitted(binary, checkpoint, reason="failed to overwrite dead body; aborting")
                return False
        return True

    def _emit_region(
        self, binary: Any, func: dict[str, Any], region: Any, rng: random.Random, use_nesting: bool
    ) -> dict[str, Any] | None:
        """Build the interpreter for a lowered region, inject it, patch the
        trampoline, and overwrite the dead body. Shared by the whole-function and
        dispatch paths; ``use_nesting`` requests the nested-layer blob."""
        payload = self._build_region_payload(binary, region, rng, use_nesting)
        if payload is None:
            return None
        blob_vaddr, blob, original_bytes = payload
        installed = self._install_region_payload(binary, region, blob_vaddr, blob)
        if installed is None:
            return None
        checkpoint = installed[0]
        if not self._overwrite_region_body(binary, region, checkpoint):
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
        return apply_code_virtualization(self, binary)
