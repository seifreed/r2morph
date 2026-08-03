"""Interpreter-assembly and bytecode generation for region virtualization.

Given a lowered :class:`Region` and its per-instance :class:`RegionScheme`,
this module emits the VM: :func:`encode_region` lowers the item list to the
encrypted, position-masked bytecode, :func:`_interpreter_asm` generates the
dispatch loop and the per-handler instances, and :func:`build_region_blob`
assembles the interpreter at its cave vaddr, XOR-encrypts the dispatch table on
the assembled bytes, and appends the bytecode.

The lifting side that produces the :class:`Region` lives in
:mod:`code_virtualization_region`; both share the value objects in
:mod:`code_virtualization_region_models`.
"""

from __future__ import annotations

import logging
import random
import re
import struct

from r2morph.mutations.code_virtualization_antidebug import timing_fold_asm, tracer_detect_asm
from r2morph.mutations.code_virtualization_dispatch import decode_block, switch_dispatch, thread_back_jumps
from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    RSP_INDEX,
)
from r2morph.mutations.code_virtualization_engine_common import DISPATCH_SWITCH
from r2morph.mutations.code_virtualization_engine_rename import rename_local_body
from r2morph.mutations.code_virtualization_region_codegen_encode import (
    _item_size as _item_size,
)
from r2morph.mutations.code_virtualization_region_codegen_encode import (
    build_ijmp_targets,
)
from r2morph.mutations.code_virtualization_region_codegen_encode import (
    encode_region as encode_region,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    _fp_arith_handler_asm,
    _fp_arith_mem_handler_asm,
    _fp_compare_handler_asm,
    _fp_convert_handler_asm,
    _fp_indexed_handler_asm,
    _fp_memory_handler_asm,
    _fp_move_handler_asm,
    _fp_packed_arith_handler_asm,
    _fp_packed_arith_mem_handler_asm,
    _fp_packed_mem_handler_asm,
    xmm_reload_asm,
    xmm_spill_asm,
)
from r2morph.mutations.code_virtualization_region_handlers import (
    _FLAGS_OFFSET,
    _FRAME_SIZE,
    _GUARD,
    _VSP_OFFSET,
    _cmp_memory_handler_asm,
    _compare_handler_asm,
    _imul3_handler_asm,
    _imul_handler_asm,
    _incdec_handler_asm,
    _indexed_address_asm,
    _lea_handler_asm,
    _lea_indexed_handler_asm,
    _lea_indexed_nobase_handler_asm,
    _leave_handler_asm,
    _mem_address_asm,
    _memory_handler_asm,
    _mov_from_rsp_handler_asm,
    _mov_to_rsp_handler_asm,
    _movx_handler_asm,
    _movx_indexed_handler_asm,
    _op_handler_asm,
    _op_mba_handler_asm,
    _op_mem_indexed_handler_asm,
    _op_memdst_handler_asm,
    _op_memory_handler_asm,
    _op_synth_handler_asm,
    _pop_handler_asm,
    _push_handler_asm,
    _pushi_handler_asm,
    _riprel_handler_asm,
    _rspadj_handler_asm,
    _shift_handler_asm,
)
from r2morph.mutations.code_virtualization_region_integrity import (
    checksum_prologue_asm,
    compute_build_checksum,
)
from r2morph.mutations.code_virtualization_region_isa import build_isa_spec
from r2morph.mutations.code_virtualization_region_microops import (
    _frestore_handler_asm,
    _fsave_handler_asm,
    _vbinop_handler_asm,
    _vbinopsynth_handler_asm,
    _vcmpsynth_handler_asm,
    _vlea_handler_asm,
    _vleaidx_handler_asm,
    _vleaidxnb_handler_asm,
    _vload_handler_asm,
    _vloadidx_handler_asm,
    _vloadrip_handler_asm,
    _vmovx_handler_asm,
    _vmovxidx_handler_asm,
    _vpop_handler_asm,
    _vpush_handler_asm,
    _vpushi_handler_asm,
    _vshift_handler_asm,
    _vstore_handler_asm,
    _vstoreidx_handler_asm,
    _vstorerip_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import (
    _DWORD_BROADCAST,
    _QWORD_BROADCAST,
    Region,
    RegionScheme,
)

logger = logging.getLogger(__name__)


# Semantically-neutral instructions used as per-instance junk. They are emitted
# only after a handler's terminating jump (unreachable), so they never execute;
# they make each VM instance structurally distinct to defeat handler signatures.
_JUNK_TEMPLATES: tuple[str, ...] = (
    "nop",
    "mov r10, r11",
    "xor r10, r11",
    "and r10, r11",
    "or r11, r10",
    "xchg r8, r9",
    "add r10, {small}",
    "sub r11, {small}",
    "lea rax, [rax + {small}]",
    "ror r10, {shift}",
)


def _junk_asm(rng: random.Random) -> str:
    """A short run of unreachable junk instructions for handler diversification.

    Operands are register-to-register or small immediates only, so every
    template always assembles - a junk instruction that failed to assemble
    would abort the whole virtualization.
    """
    lines = []
    for _ in range(rng.randint(0, 4)):
        template = rng.choice(_JUNK_TEMPLATES)
        lines.append("  " + template.format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n")
    return "".join(lines)


# Live junk emitted at a handler's entry, so it actually executes and makes
# duplicate handlers differ in reachable code, not only in the unreachable tail.
# It touches only rbx/rbp/r12, which hold no live interpreter state (every GP
# register is spilled to the frame, and the dispatch loop only keeps rsi/rsp/r15
# live); flag effects are irrelevant at entry, where the captured flags are not
# yet set and a branch handler reloads them from the frame slot.
_LIVE_JUNK_TEMPLATES: tuple[str, ...] = (
    "mov rbx, rbp",
    "xor rbx, r12",
    "and rbp, r12",
    "or r12, rbx",
    "xchg rbx, rbp",
    "add r12, {small}",
    "sub rbx, {small}",
    "lea rbp, [rbp + {small}]",
    "ror r12, {shift}",
)


# Per-instance opaque-predicate identities. Each computes a value into rbp from a
# scratch seed register ({s}) whose parity is fixed for every input, paired with
# the branch that is consequently always taken. ``x*(x+1)`` / ``x*(x-1)`` (adjacent
# integers) and ``2x`` are always even (jz after test ,1); ``x|1`` and ``x|(x+1)``
# (the latter spans adjacent integers, one of them odd) are always odd (jnz). A
# fixed predicate is itself a signature, so the form is varied per instance.
_OPAQUE_VARIANTS: tuple[tuple[str, str], ...] = (
    ("  lea rbp, [{s} + 1]\n  imul rbp, {s}\n  test rbp, 1\n", "jz"),
    ("  lea rbp, [{s} - 1]\n  imul rbp, {s}\n  test rbp, 1\n", "jz"),
    ("  lea rbp, [{s} + {s}]\n  test rbp, 1\n", "jz"),
    ("  mov rbp, {s}\n  or rbp, 1\n  test rbp, 1\n", "jnz"),
    ("  lea rbp, [{s} + 1]\n  or rbp, {s}\n  test rbp, 1\n", "jnz"),
)


def _opaque_predicate_asm(rng: random.Random, index: int) -> str:
    """A reachable, always-taken branch guarding an unreachable junk body.

    One of :data:`_OPAQUE_VARIANTS` (chosen per instance) computes a value whose
    parity is fixed for every input, so its paired branch is always taken and the
    junk body between the branch and the label never executes. The predicate reads
    and writes only rbx/rbp/r12 - state-neutral at a handler head, exactly like the
    live junk above - and clobbers only flags (not yet meaningful there, a branch
    handler reloads them from the frame slot), so it adds opaque control flow
    without touching program state. A linear sweep, or a handler signature that
    assumes straight-line handler heads, must now account for a branch whose
    direction it cannot resolve without proving the identity. ``index`` (unique per
    handler instance, across nested layers) keeps the skip label unique.
    """
    # Every identity only reads the seed (it writes rbp), so the seed can be a
    # live register the dispatch keeps - the bytecode stream pointer rsi or the
    # position r13 - without clobbering it. Branching on genuine runtime VM state,
    # not dead scratch, defeats the "branch on an unconstrained value -> prune as
    # opaque" heuristic; rbx/r12 (dead scratch here) keep cheaper variants in play.
    seed = rng.choice(("rbx", "r12", "rsi", "r13"))  # rbp holds the predicate accumulator
    compute, branch = rng.choice(_OPAQUE_VARIANTS)
    dead = "".join(
        "  " + rng.choice(_LIVE_JUNK_TEMPLATES).format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n"
        for _ in range(rng.randint(1, 3))
    )
    return f"{compute.format(s=seed)}  {branch} opaque_{index}\n{dead}opaque_{index}:\n"


def _live_junk_asm(rng: random.Random, index: int) -> str:
    """A short run of reachable, state-neutral junk for the head of a handler,
    sometimes capped with an opaque-predicate branch over an unreachable body."""
    lines = []
    for _ in range(rng.randint(0, 3)):
        template = rng.choice(_LIVE_JUNK_TEMPLATES)
        lines.append("  " + template.format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n")
    if rng.random() < 0.5:
        lines.append(_opaque_predicate_asm(rng, index))
    return "".join(lines)


# SysV integer-argument registers (plus rax for the varargs al-count) the call
# bridge loads from the program's frame slots before a native call, and spills
# back after to capture the callee's results.
_CALL_ARG_REGISTERS: tuple[str, ...] = ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax")


def _call_bridge_asm(index: int, slot: tuple[int, ...], target_asm: str, advance: int) -> str:
    """Bridge a virtualized call out to a native callee and back.

    ``target_asm`` is the prologue that leaves the absolute callee address in r10
    (the direct and register-indirect forms differ only there); ``advance`` is the
    call item's size. Every program register lives in a frame slot, so the real
    registers are free to set up the System V argument registers; r12/rbx
    (callee-saved) carry the VM frame base and stream pointer across the call. The
    program's stack is relocated below the VM frame, so the manual return-address
    push and the callee's own frame never collide with the spilled context. Only
    rax (the return value) and the loaded argument registers are spilled back: the
    rest of the caller-saved set is undefined across a call by the ABI, and the
    callee preserves the callee-saved program values still held in their slots.

    ``index`` makes the resume label unique across duplicated handler instances.
    """
    off = {name: slot[GP_REGISTERS.index(name)] * 8 for name in _CALL_ARG_REGISTERS}
    loads = "".join(f"  mov {name}, qword ptr [rsp+{off[name]}]\n" for name in _CALL_ARG_REGISTERS)
    spills = "".join(f"  mov qword ptr [rsp+{off[name]}], {name}\n" for name in _CALL_ARG_REGISTERS)
    return (
        target_asm
        + "  mov r12, rsp\n  mov rbx, rsi\n"
        + loads
        + f"  mov rsp, qword ptr [r12+{slot[RSP_INDEX] * 8}]\n"
        + f"  lea r11, [rip+call_resume_{index}]\n  push r11\n  jmp r10\n"
        + f"call_resume_{index}:\n  mov rsp, r12\n"
        + spills
        + f"  mov rsi, rbx\n  add rsi, {advance}\n  jmp vm_dispatch\n"
    )


def _call_handler_asm(index: int, key_dword: str, slot: tuple[int, ...]) -> str:
    """Direct ``call``: the target is a signed 32-bit offset from the bytecode
    base (r15, callee-saved so it survives the call), recomputed base-independently."""
    target = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
        "  movsxd r10, eax\n  add r10, r15\n"
    )
    return _call_bridge_asm(index, slot, target, 5)


def _icall_handler_asm(index: int, key: int, slot: tuple[int, ...]) -> str:
    """Register-indirect ``call reg``: the target is the program value of a GP
    register, read from its frame slot. Base-independent (no r15), so it nests."""
    target = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n" "  mov r10, qword ptr [rsp+r8*8]\n"
    return _call_bridge_asm(index, slot, target, 2)


def _ijmp_handler_asm(index: int, key: int) -> str:
    """Register-indirect jump (``jmp reg``): re-enter the VM at the virtualized copy
    of the computed target. The target is the program value of a GP register (read
    from its frame slot, same operand layout as ``icall``); it is looked up in the
    runtime target map (native address -> bytecode offset) and, on a hit, committed
    to the vIP (rsi) so dispatch resumes at the virtualized target instead of the
    overwritten native code. A miss - a target outside the region, which a
    correctly-extracted dispatch region never produces - falls through to the
    default VM exit. Unique scan/hit labels keep duplicated handler instances
    distinct."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov r10, qword ptr [rsp+r8*8]\n"
        "  lea r11, [rip+ijmp_map]\n  mov ecx, dword ptr [r11]\n  add r11, 4\n"
        f"ijmp_scan_{index}:\n  test ecx, ecx\n  jz vm_exit\n"
        f"  cmp qword ptr [r11], r10\n  je ijmp_hit_{index}\n  add r11, 12\n  dec ecx\n  jmp ijmp_scan_{index}\n"
        f"ijmp_hit_{index}:\n  mov eax, dword ptr [r11+8]\n  lea rsi, [rip+bytecode]\n  add rsi, rax\n  jmp vm_dispatch\n"
    )


def _vcall_handler_asm(retarget_target: str, rsp_off: int) -> str:
    """In-function direct ``call``: push a resume vIP onto the program's relocated
    stack and re-enter the VM at the callee's virtualized entry, so the call and its
    return run entirely inside the VM (the native body is junk-filled). The target is
    decoded exactly like a jmp (``retarget_target`` leaves the callee's absolute vIP in
    r9); the resume vIP is the byte after this 5-byte item - an address inside the
    appended bytecode that the matching ``vret`` recognizes by range."""
    return (
        retarget_target
        + "  lea r10, [rsi+5]\n"  # resume vIP = the item after this 5-byte vcall
        + f"  mov r11, qword ptr [rsp+{rsp_off}]\n  sub r11, 8\n  mov qword ptr [r11], r10\n"
        + f"  mov qword ptr [rsp+{rsp_off}], r11\n"
        + "  mov rsi, r9\n  jmp vm_dispatch\n"
    )


def _vret_handler_asm(
    index: int, ret_addr: int, rsp_off: int, bytecode_len: int, reload_seq: str, frame_size: int
) -> str:
    """Return-aware ``ret`` terminator for a region with in-function calls: if the top
    of the program's relocated stack is a resume vIP a ``vcall`` pushed (an address in
    the appended bytecode ``[r15, r15+bytecode_len)``), pop it and resume the VM there;
    otherwise it is a genuine caller return address, so reload the context and return
    natively to ``ret_addr``. The bytecode range is a build-known invariant: a real
    return address points into loaded code, never into the injected blob."""
    return (
        f"  mov r10, qword ptr [rsp+{rsp_off}]\n  mov r9, qword ptr [r10]\n"
        f"  mov r11, r9\n  sub r11, r15\n  cmp r11, {bytecode_len}\n  jae vret_native_{index}\n"
        f"  add r10, 8\n  mov qword ptr [rsp+{rsp_off}], r10\n  mov rsi, r9\n  jmp vm_dispatch\n"
        f"vret_native_{index}:\n{reload_seq}  add rsp, {frame_size}\n  jmp {hex(ret_addr)}\n"
    )


def _call_mem_handler_asm(
    index: int, key: int, key_dword: str, slot: tuple[int, ...], riprel: bool, field_perm: int, addr_variant: int = 0
) -> str:
    """Memory-indirect ``call qword [mem]``: the callee address is a pointer loaded
    from memory (vtable / IAT-GOT dispatch). The shared memory-address prologue
    computes the pointer's address into r10 (base+disp from a frame slot, or
    bytecode base plus a stored offset for the rip-relative form); dereferencing it
    yields the target. The item carries an unused register field so it reuses the
    load handlers' address machinery and operand layout verbatim."""
    address, advance = _mem_address_asm(riprel, key, key_dword, field_perm, addr_variant)
    target = address + "  mov r10, qword ptr [r10]\n"
    return _call_bridge_asm(index, slot, target, advance)


def _call_mem_idx_handler_asm(
    index: int, key: int, key_dword: str, slot: tuple[int, ...], field_perm: int, addr_variant: int = 0
) -> str:
    """Indexed memory-indirect ``call qword [base+index*scale+disp]`` (function-
    pointer table dispatch). The shared indexed-address prologue computes the
    pointer's address into r10; dereferencing it yields the target. The item
    carries an unused register field so the scaled-index operand layout applies."""
    address, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    target = address + "  mov r10, qword ptr [r10]\n"
    return _call_bridge_asm(index, slot, target, advance)


# RFLAGS bit positions read by the conditional-branch conditions (Intel SDM Vol 1
# 3.4.3): carry, parity, zero, sign, overflow.
_FLAG_CF = 0
_FLAG_PF = 2
_FLAG_ZF = 6
_FLAG_SF = 7
_FLAG_OF = 11

# Each canonical branch condition (the value set of region._CONDITION) as
# (base, negate): ``base`` names the boolean quantity computed from the flags and
# ``negate`` flips it for the inverted mnemonic (je vs jne share ZF). Bases:
# z=ZF, s=SF, o=OF, p=PF, c=CF, be=CF|ZF, l=SF^OF, le=ZF|(SF^OF).
_JCC_CONDITION_BASE: dict[str, tuple[str, bool]] = {
    "je": ("z", False),
    "jne": ("z", True),
    "js": ("s", False),
    "jns": ("s", True),
    "jo": ("o", False),
    "jno": ("o", True),
    "jp": ("p", False),
    "jnp": ("p", True),
    "jb": ("c", False),
    "jae": ("c", True),
    "jbe": ("be", False),
    "ja": ("be", True),
    "jl": ("l", False),
    "jge": ("l", True),
    "jle": ("le", False),
    "jg": ("le", True),
}


def _extract_flag_bit_asm(dst: str, bit: int) -> str:
    """Isolate RFLAGS bit ``bit`` (from eax) as a 0/1 value in 32-bit reg ``dst``."""
    return f"  mov {dst}, eax\n  shr {dst}, {bit}\n  and {dst}, 1\n"


def _jcc_taken_asm(condition: str) -> str:
    """Compute the branch-taken value (0/1) into ecx from RFLAGS held in eax.

    The x86 conditions are evaluated arithmetically (bit extract + boolean fold)
    so the branch carries no native conditional jump. r10d/r11d are scratch.
    """
    base, negate = _JCC_CONDITION_BASE[condition]
    if base == "be":  # CF | ZF
        body = _extract_flag_bit_asm("ecx", _FLAG_CF) + _extract_flag_bit_asm("r10d", _FLAG_ZF) + "  or ecx, r10d\n"
    elif base == "l":  # SF ^ OF
        body = _extract_flag_bit_asm("ecx", _FLAG_SF) + _extract_flag_bit_asm("r10d", _FLAG_OF) + "  xor ecx, r10d\n"
    elif base == "le":  # ZF | (SF ^ OF)
        body = (
            _extract_flag_bit_asm("ecx", _FLAG_ZF)
            + _extract_flag_bit_asm("r10d", _FLAG_SF)
            + _extract_flag_bit_asm("r11d", _FLAG_OF)
            + "  xor r10d, r11d\n  or ecx, r10d\n"
        )
    else:
        bit = {"z": _FLAG_ZF, "s": _FLAG_SF, "o": _FLAG_OF, "p": _FLAG_PF, "c": _FLAG_CF}[base]
        body = _extract_flag_bit_asm("ecx", bit)
    if negate:
        body += "  xor ecx, 1\n"
    return body


def _jcc_handler_asm(condition: str, retarget_target: str) -> str:
    """Emit a conditional-branch handler that carries no native jcc.

    Decodes the taken target into r9 (``retarget_target``) and the fall-through
    (rsi+5) into r8, computes the taken bit from the captured RFLAGS, then selects
    the next vIP branch-free with a 0/-1 mask - no native conditional jump or cmov,
    so a devirtualizer cannot read the condition or the CFG edge off the handler.
    """
    return (
        retarget_target  # r9 = taken target
        + "  lea r8, [rsi+5]\n"  # r8 = fall-through vIP (past the 5-byte jcc item)
        + f"  mov eax, dword ptr [rsp+{_FLAGS_OFFSET}]\n"  # captured RFLAGS (low 32 bits)
        + _jcc_taken_asm(condition)  # ecx = taken (0/1)
        + "  neg rcx\n"  # rcx = 0 or all-ones mask
        + "  mov r10, r9\n  and r10, rcx\n"  # target & mask
        + "  not rcx\n  and r8, rcx\n"  # fall-through & ~mask
        + "  or r10, r8\n  mov rsi, r10\n  jmp vm_dispatch\n"
    )


def _setcc_slot_read(offset: int, key: int, reg: str) -> str:
    """Read the destination slot index at ``[rsi+offset]`` into 64-bit ``reg``.

    Mirrors the micro-op slot read: the byte is un-masked with the build key and
    the stream position (``r13b``, left holding it by the dispatch).
    """
    return f"  movzx {reg}d, byte ptr [rsi+{offset}]\n  xor {reg}b, {key}\n  xor {reg}b, r13b\n"


def _setcc_handler_asm(condition: str, key: int) -> str:
    """Emit a conditional-set handler that carries no native setcc.

    Computes the condition (0/1) arithmetically from the captured RFLAGS - like
    ``_jcc_handler_asm`` - and writes it to the destination slot's low byte only,
    preserving the upper seven bytes exactly as a native ``setcc r/m8`` would.
    """
    return (
        f"  mov eax, dword ptr [rsp+{_FLAGS_OFFSET}]\n"  # captured RFLAGS
        + _jcc_taken_asm(condition)  # ecx = condition (0/1)
        + _setcc_slot_read(1, key, "r8")  # r8 = destination slot
        + "  mov byte ptr [rsp+r8*8], cl\n"  # write low byte only
        + "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _cmov_handler_asm(condition: str, width: int, key: int) -> str:
    """Emit a conditional-move handler that carries no native cmov.

    Computes a 0/-1 mask from the captured RFLAGS - like ``_jcc_handler_asm`` -
    then selects ``src`` or the current ``dst`` branch-free. A 32-bit move loads
    both operands 32-bit (zero-extending) so the qword write clears the upper half,
    matching x86-64's zero-extension; a 64-bit move keeps the full registers.
    """
    reg_suffix = "d" if width == 32 else ""
    size_kw = "dword" if width == 32 else "qword"
    load_src = f"  mov r11{reg_suffix}, {size_kw} ptr [rsp+r10*8]\n"
    load_dst = f"  mov r9{reg_suffix}, {size_kw} ptr [rsp+r8*8]\n"
    return (
        f"  mov eax, dword ptr [rsp+{_FLAGS_OFFSET}]\n"  # captured RFLAGS
        + _jcc_taken_asm(condition)  # ecx = condition (0/1)
        + "  neg rcx\n"  # rcx = 0 or all-ones mask
        + _setcc_slot_read(1, key, "r8")  # r8 = destination slot
        + _setcc_slot_read(2, key, "r10")  # r10 = source slot
        + load_src
        + "  and r11, rcx\n"  # src & mask
        + "  not rcx\n"
        + load_dst
        + "  and r9, rcx\n"  # dst & ~mask
        + "  or r11, r9\n"
        + "  mov qword ptr [rsp+r8*8], r11\n"  # write (upper half cleared for a 32-bit move)
        + "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _movx_reg_handler_asm(handler_key: str, key: int) -> str:
    """Emit a register-source movzx/movsx handler.

    The source register's full value already lives in its slot, so its low byte,
    word, or dword is the operand: read the source slot, zero- or sign-extend the
    low al/ax/eax into r10, and write the destination slot. A 32-bit destination is
    zero-extended into the full slot because the 32-bit write into r10d clears r10's
    upper half. A dword source is the movsxd form (always sign-extend into 64-bit).
    No flags.
    """
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    src_reg = {"8": "al", "16": "ax", "32": "eax"}[src_size_text]
    if src_size_text == "32":
        extend = f"  movsxd r10, {src_reg}\n"
    elif ext == "z":
        extend = f"  movzx r10d, {src_reg}\n"
    elif dst_width_text == "64":
        extend = f"  movsx r10, {src_reg}\n"
    else:
        extend = f"  movsx r10d, {src_reg}\n"
    return (
        _setcc_slot_read(1, key, "r8")  # r8 = destination slot
        + _setcc_slot_read(2, key, "r9")  # r9 = source slot
        + "  mov rax, qword ptr [rsp+r9*8]\n"  # source value (al/ax = its low byte/word)
        + extend
        + "  mov qword ptr [rsp+r8*8], r10\n"
        + "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def handler_instances_asm(
    index_to_key: dict[int, str],
    *,
    key: int,
    key_qword: str,
    key_dword: str,
    rsp_off: int,
    junk_rng: random.Random,
    reload_seq: str,
    retarget: str,
    retarget_target: str,
    frame_size: int,
    slot: tuple[int, ...],
    bytecode_len: int = 0,
    extra: dict[str, str] | None = None,
    field_perm: int = 0,
    body_seed: int = 0,
    isa_seed: int = 0,
) -> str:
    """Emit the ``H_{index}`` handler instances for one interpreter (or layer).

    ``index_to_key`` maps each global handler index to its handler key; ``extra``
    supplies bodies for handler keys outside the standard dispatch table (e.g.
    the nested-VM transfer handlers). All bodies jump back to the shared
    ``vm_dispatch`` and carry per-instance reachable/unreachable junk.
    """
    extra = extra or {}
    # This build's semantic ISA personality: flag_variant selects the flag-synthesis
    # spelling, arith_variant the MBA fold, and shift_variant the shift flag-capture
    # idiom, shared by every matching handler.
    spec = build_isa_spec(isa_seed)
    flag_variant = spec.flag_variant
    arith_variant = spec.arith_variant
    compare_variant = spec.compare_variant
    shift_variant = spec.shift_variant
    addr_variant = spec.addr_variant
    lines: list[str] = []
    for index in sorted(index_to_key):
        handler_key = index_to_key[index]
        # Reachable head junk makes duplicate handlers diverge in executed code.
        lines.append(f"H_{index}:\n{_live_junk_asm(junk_rng, index)}")
        # Everything the dispatch chain below appends for this handler is its body;
        # capture that slice so a per-instance scratch-register rename can be applied
        # to it (only when it is pure-VM-internal - see rename_local_body).
        body_start = len(lines)
        if handler_key in extra:
            lines.append(extra[handler_key])
        elif handler_key == "call":
            lines.append(_call_handler_asm(index, key_dword, slot))
        elif handler_key == "icall":
            lines.append(_icall_handler_asm(index, key, slot))
        elif handler_key == "callmem":
            lines.append(_call_mem_handler_asm(index, key, key_dword, slot, False, field_perm, addr_variant))
        elif handler_key == "callmemrip":
            lines.append(_call_mem_handler_asm(index, key, key_dword, slot, True, field_perm, addr_variant))
        elif handler_key == "callmemidx":
            lines.append(_call_mem_idx_handler_asm(index, key, key_dword, slot, field_perm, addr_variant))
        elif handler_key == "vcall":
            lines.append(_vcall_handler_asm(retarget_target, rsp_off))
        elif handler_key == "vpush":
            lines.append(_vpush_handler_asm(key))
        elif handler_key == "vpop":
            lines.append(_vpop_handler_asm(key))
        elif handler_key == "fsave":
            lines.append(_fsave_handler_asm())
        elif handler_key == "frestore":
            lines.append(_frestore_handler_asm())
        elif handler_key.startswith("vpushi_"):
            lines.append(_vpushi_handler_asm(handler_key, key_qword, key_dword))
        elif handler_key.startswith("vcmpsynth_"):
            lines.append(_vcmpsynth_handler_asm(handler_key, key, flag_variant, arith_variant, compare_variant))
        elif handler_key.startswith("vbinopsynth_"):
            lines.append(_vbinopsynth_handler_asm(handler_key, key, flag_variant, arith_variant))
        elif handler_key.startswith("vbinop_"):
            lines.append(_vbinop_handler_asm(handler_key, key, arith_variant))
        elif handler_key.startswith("vloadidx_"):
            lines.append(_vloadidx_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vstoreidx_"):
            lines.append(_vstoreidx_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vload_"):
            lines.append(_vload_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vstore_"):
            lines.append(_vstore_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vloadrip_"):
            lines.append(_vloadrip_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vstorerip_"):
            lines.append(_vstorerip_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vleaidxnb_"):
            lines.append(_vleaidxnb_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vleaidx_"):
            lines.append(_vleaidx_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("vlea_", "vlearip_")):
            lines.append(_vlea_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vmovxidx_"):
            lines.append(_vmovxidx_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vmovx_"):
            lines.append(_vmovx_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("vshift_"):
            lines.append(_vshift_handler_asm(handler_key, key, shift_variant))
        elif handler_key.startswith("opsynth_"):
            lines.append(
                _op_synth_handler_asm(handler_key, key, key_qword, key_dword, field_perm, flag_variant, arith_variant)
            )
        elif handler_key.startswith("opmba_"):
            lines.append(_op_mba_handler_asm(handler_key, key, key_qword, key_dword, field_perm, arith_variant))
        elif handler_key.startswith("op_"):
            lines.append(_op_handler_asm(handler_key, key, key_qword, key_dword, field_perm))
        elif handler_key.startswith(("cmp_", "test_")):
            lines.append(
                _compare_handler_asm(
                    handler_key, key, key_qword, key_dword, field_perm, flag_variant, arith_variant, compare_variant
                )
            )
        elif handler_key.startswith(("shl_", "shr_", "sar_")):
            lines.append(_shift_handler_asm(handler_key, key, field_perm, shift_variant))
        elif handler_key.startswith("imul3_"):
            lines.append(_imul3_handler_asm(handler_key, key, key_dword, field_perm))
        elif handler_key.startswith("push_"):
            lines.append(_push_handler_asm(key, rsp_off))
        elif handler_key.startswith("pop_"):
            lines.append(_pop_handler_asm(key, rsp_off))
        elif handler_key == "pushi":
            lines.append(_pushi_handler_asm(key_qword, rsp_off))
        elif handler_key.startswith("rspadj_"):
            lines.append(_rspadj_handler_asm(handler_key, key_dword, rsp_off))
        elif handler_key == "movfromrsp":
            lines.append(_mov_from_rsp_handler_asm(key, rsp_off))
        elif handler_key == "movtorsp":
            lines.append(_mov_to_rsp_handler_asm(key, rsp_off))
        elif handler_key == "leave":
            lines.append(_leave_handler_asm(key, rsp_off))
        elif handler_key.startswith("imul_"):
            lines.append(_imul_handler_asm(handler_key, key, field_perm))
        elif handler_key.startswith(("cmpmem_", "cmpriprel_")):
            lines.append(
                _cmp_memory_handler_asm(
                    handler_key, key, key_dword, field_perm, flag_variant, arith_variant, compare_variant, addr_variant
                )
            )
        elif handler_key.startswith(("opmemdst_", "opmemdstrip_")):
            lines.append(
                _op_memdst_handler_asm(
                    handler_key, key, key_dword, field_perm, flag_variant, arith_variant, addr_variant
                )
            )
        elif handler_key.startswith(("opmem_", "opriprel_")):
            lines.append(
                _op_memory_handler_asm(
                    handler_key, key, key_dword, field_perm, flag_variant, arith_variant, addr_variant
                )
            )
        elif handler_key.startswith("leaidxnb_"):
            lines.append(_lea_indexed_nobase_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("leaidx_"):
            lines.append(_lea_indexed_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("lea_", "learip_")):
            lines.append(_lea_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("opmemidx_"):
            lines.append(
                _op_mem_indexed_handler_asm(handler_key, key, key_dword, field_perm, flag_variant, arith_variant)
            )
        elif handler_key.startswith("incdec_"):
            lines.append(_incdec_handler_asm(handler_key, key, flag_variant, arith_variant))
        elif handler_key.startswith("movxreg_"):
            lines.append(_movx_reg_handler_asm(handler_key, key))
        elif handler_key.startswith("movxidx_"):
            lines.append(_movx_indexed_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("movx_"):
            lines.append(_movx_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("riprel_load_", "riprel_store_")):
            lines.append(_riprel_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("fpload_", "fpstore_", "fploadrip_", "fpstorerip_")):
            lines.append(_fp_memory_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("fploadidx_", "fpstoreidx_", "fploadidxnb_", "fpstoreidxnb_")):
            lines.append(_fp_indexed_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("fparithmem_", "fparithmemrip_", "fparithmemidx_")):
            lines.append(_fp_arith_mem_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("fparith_"):
            lines.append(_fp_arith_handler_asm(handler_key, key, field_perm))
        elif handler_key.startswith(("cvti2f_", "cvtf2i_")):
            lines.append(_fp_convert_handler_asm(handler_key, key, field_perm))
        elif handler_key.startswith("fpcmp_"):
            lines.append(_fp_compare_handler_asm(handler_key, key, field_perm))
        elif handler_key.startswith("fpmov_"):
            lines.append(_fp_move_handler_asm(handler_key, key, field_perm))
        elif handler_key.startswith(("fppackedmem_", "fppackedmemrip_", "fppackedmemidx_")):
            lines.append(_fp_packed_arith_mem_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith("fppacked_"):
            lines.append(_fp_packed_arith_handler_asm(handler_key, key, field_perm))
        elif handler_key in ("fppload", "fppstore", "fpploadrip", "fppstorerip", "fpploadidx", "fppstoreidx"):
            lines.append(_fp_packed_mem_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key.startswith(("load_", "store_")):
            lines.append(_memory_handler_asm(handler_key, key, key_dword, field_perm, addr_variant))
        elif handler_key == "jmp":
            lines.append(retarget)
        elif handler_key == "ijmp":
            lines.append(_ijmp_handler_asm(index, key))
        elif handler_key.startswith("jcc_"):
            condition = handler_key.split("_", 1)[1]
            lines.append(_jcc_handler_asm(condition, retarget_target))
        elif handler_key.startswith("setcc_"):
            lines.append(_setcc_handler_asm(handler_key.split("_", 1)[1], key))
        elif handler_key.startswith("cmov_"):
            _, cmov_condition, cmov_width = handler_key.split("_")
            lines.append(_cmov_handler_asm(cmov_condition, int(cmov_width), key))
        elif handler_key == "nop":
            lines.append("  add rsi, 1\n  jmp vm_dispatch\n")
        elif handler_key.startswith("vret_"):
            ret_addr = int(handler_key.split("_", 1)[1])
            lines.append(_vret_handler_asm(index, ret_addr, rsp_off, bytecode_len, reload_seq, frame_size))
        elif handler_key.startswith("exit_"):
            exit_addr = int(handler_key.split("_", 1)[1])
            lines.append(f"{reload_seq}  add rsp, {frame_size}\n  jmp {hex(exit_addr)}\n")
        body = rename_local_body("".join(lines[body_start:]), random.Random(body_seed ^ index))
        del lines[body_start:]
        lines.append(body)
        # Junk after the handler's terminating jump - unreachable, never runs.
        lines.append(_junk_asm(junk_rng))
    return "".join(lines)


def _interpreter_asm(region: Region, scheme: RegionScheme) -> str:
    key = scheme.xor_key
    key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
    key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
    retarget_target = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        # Un-mask the position the encoder folded into the target (r13b holds it
        # from the dispatch), broadcast to 32 bits - the branch offset is keyed by
        # key XOR position like every other operand.
        f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
        "  lea r9, [rip+bytecode]\n  add r9, rax\n"
    )
    # The unconditional jmp handler commits the decoded target straight to the vIP;
    # the conditional handler selects between it and the fall-through branch-free.
    retarget = retarget_target + "  mov rsi, r9\n  jmp vm_dispatch\n"

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    rsp_off = slot[RSP_INDEX] * 8  # byte offset of the relocated program rsp slot
    # Only regions that move scalar FP need the 16 XMM registers preserved in the
    # frame; for everything else the spill/reload is pure overhead and is omitted.
    has_fp = any(item[0] in ("fpload", "fpstore") for item in region.instructions)
    # Per-build dispatch architecture: the switch shape is a single central
    # binary-search comparison tree, the threaded shape the inlined encrypted
    # offset-table computed goto. The switch shape is gated off the computed-jump
    # contract (target_map): that path needs the ijmp target map to stay
    # table-tail-adjacent, which only the threaded (vm_table) layout provides.
    is_switch = scheme.dispatch_shape == DISPATCH_SWITCH and not region.target_map
    # Zero the virtual operand stack pointer; micro-op arithmetic folds through it.
    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n  mov qword ptr [rsp+{_VSP_OFFSET}], 0\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp+{slot[index] * 8}], {name}\n")
    if has_fp:
        lines.append(xmm_spill_asm())
    # Anti-tamper: checksum the interpreter's own code into a frame slot the
    # dispatch folds into every opcode decrypt. Runs after the spill, so the
    # scratch registers it clobbers are already saved.
    # The threaded shape excludes the trailing offset table (encrypted after
    # assembly) from the checksum; the switch shape has no table, so the checksum
    # runs to vm_code_end (the end of the interpreter code, before the bytecode).
    checksum_end = "vm_code_end" if is_switch else "vm_table"
    lines.append(checksum_prologue_asm(scheme.xor_key, slot=scheme.checksum_offset, end_label=checksum_end))
    # Timing anti-debug woven into the same checksum slot: a single-stepped run
    # folds 0xFF into the byte and misdecodes every opcode; an untraced run folds
    # 0x00 (the counter reads sit inside the checksummed range, so the benign build
    # is bit-identical and neither the encoder nor the checksum computation change).
    lines.append(timing_fold_asm(scheme.xor_key, slot=scheme.checksum_offset))
    # Tracer anti-debug woven into the same checksum slot: an attached ptrace
    # debugger (TracerPid != 0 in /proc/self/status) folds 0xFF and misdecodes every
    # opcode; an untraced native run and a Unicorn emulation both fold 0x00, so the
    # benign build stays bit-identical and the checksum computation is unchanged.
    lines.append(tracer_detect_asm(slot=scheme.checksum_offset, key=scheme.table_key))
    # Direct-threaded, polymorphic dispatch: rather than a single shared dispatch
    # block every handler jumps back to (a fan-in hub a devirtualizer flags as the
    # dispatcher by in-degree, and pattern-matches as one fixed sequence), the
    # opcode decode is inlined at the entry and at the tail of every handler, and
    # each copy shuffles its order-independent XOR groups so no two copies share a
    # byte layout. Each handler thus decodes the next opcode itself and jumps
    # straight to the next handler. The decode runs once per opcode either way and
    # shuffling only reorders instructions, so executed count and size are
    # unchanged; only the interpreter's code grows (one copy per handler).
    poly_rng = random.Random(scheme.table_key)
    handler_count = sum(len(indices) for indices in scheme.dup.values())
    # Undo the opcode byte's position mask and fold in the key and the runtime
    # self-checksum: the encoder pre-biased the opcode with the expected checksum, so
    # a faithful interpreter cancels it and a tampered one misdecodes every opcode.
    # Both dispatch shapes share this decrypt group and the bounds guard.
    opcode_xors = [
        f"  xor al, {key}\n",
        "  xor al, r13b\n",
        f"  xor al, byte ptr [rsp+{scheme.checksum_offset}]\n",
    ]
    bounds = f"  cmp al, {handler_count}\n  jae vm_exit\n"

    def make_decode() -> str:
        return decode_block(
            opcode_xors=opcode_xors,
            bounds=bounds,
            # Base-independent indirect dispatch: each table entry is a 32-bit signed
            # offset from vm_table to its handler. The offsets are XOR-encrypted (not
            # a plaintext switch a disassembler recovers) and the table key is
            # diffused with the self-checksum (broadcast to 32 bits), so tampering
            # corrupts handler-address resolution too.
            table_load="  lea r14, [rip+vm_table]\n  mov eax, dword ptr [r14+rax*4]\n",
            table_xors=[
                f"  xor eax, {hex(scheme.table_key)}\n",
                f"  movzx ecx, byte ptr [rsp+{scheme.checksum_offset}]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n",
            ],
            rng=poly_rng,
        )

    # Capture the program's entry rsp, then relocate its virtual stack a guard
    # distance below the VM frame so the function's own push/pop never collides with
    # the spilled context. rsp is only ever a memory base or a push/pop target, so
    # this constant shift stays self-consistent. r13/r14 are free scratch between
    # handlers; r15 holds the bytecode base.
    entry_setup = (
        f"  lea rax, [rsp+{_FRAME_SIZE}]\n  sub rax, {_GUARD}\n  mov qword ptr [rsp+{slot[RSP_INDEX] * 8}], rax\n"
        "  lea rsi, [rip+bytecode]\n  mov r15, rsi\n"
    )
    if is_switch:
        # Switch shape: the entry falls into one central vm_dispatch block every
        # handler jumps back to; it decodes the opcode once and routes through a
        # compare/branch ladder (no offset table, no computed goto). Handler labels
        # are capital H_<index>, so the shared ladder is emitted with that prefix.
        lines.append(entry_setup)
        lines.append(
            switch_dispatch(opcode_xors=opcode_xors, bounds=bounds, total=handler_count, rng=poly_rng, label_prefix="H")
        )
    else:
        lines.append(entry_setup + make_decode())

    reload_seq = "".join(
        f"  mov {name}, qword ptr [rsp+{slot[index] * 8}]\n" for index, name in enumerate(GP_REGISTERS) if name != "rsp"
    )
    if has_fp:
        reload_seq += xmm_reload_asm()

    # Each opcode index gets its own handler instance (an operation with two
    # indices is emitted twice, each copy carrying different junk), so the
    # opcode->operation map is not one-to-one and the duplicate handlers carry
    # no shared byte signature.
    index_to_key: dict[int, str] = {}
    for handler_key, indices in scheme.dup.items():
        for index in indices:
            index_to_key[index] = handler_key
    total = len(index_to_key)

    junk_rng = random.Random(scheme.junk_seed)
    lines.append(
        handler_instances_asm(
            index_to_key,
            key=key,
            key_qword=key_qword,
            key_dword=key_dword,
            rsp_off=rsp_off,
            junk_rng=junk_rng,
            reload_seq=reload_seq,
            retarget=retarget,
            retarget_target=retarget_target,
            frame_size=_FRAME_SIZE,
            slot=slot,
            bytecode_len=sum(_item_size(item) for item in region.instructions),
            field_perm=scheme.field_perm,
            body_seed=scheme.body_seed,
            isa_seed=scheme.isa_seed,
        )
    )

    # Every index in 0..total-1 maps to a handler; the bounds guard above sends an
    # out-of-range (corrupt) opcode to the default exit so it cannot leave the VM.
    table = "".join(f"  .long H_{index} - vm_table\n" for index in range(total))
    # Runtime target map for computed jumps (ijmp): a count followed by (native
    # address, bytecode offset) pairs the ijmp handler scans to re-enter the VM at
    # a virtualized target. Empty for an ordinary region, so its blob is unchanged.
    # It is emitted BEFORE vm_table so the dispatch table stays the tail of the
    # assembled interpreter - build_region_blob locates the table (for its runtime
    # decryption and the self-checksum) as the last ``total*4`` bytes, so any data
    # after the table would corrupt both.
    if is_switch:
        # No offset table: handler tails already jump to the central vm_dispatch
        # block, so no threading pass is needed. Mark the end of the checksummed
        # interpreter code right before the appended bytecode. The switch shape is
        # gated off target_map, so there is no ijmp map to place here.
        lines.append(
            f"vm_exit:\n{reload_seq}  add rsp, {_FRAME_SIZE}\n  jmp {hex(region.exit_vaddr)}\nvm_code_end:\nbytecode:\n"
        )
        interpreter = "".join(lines)
    else:
        # Runtime target map for computed jumps (ijmp): a count followed by (native
        # address, bytecode offset) pairs the ijmp handler scans to re-enter the VM
        # at a virtualized target. Empty for an ordinary region, so its blob is
        # unchanged. It is emitted BEFORE vm_table so the dispatch table stays the
        # tail of the assembled interpreter - build_region_blob locates the table
        # (for its runtime decryption and the self-checksum) as the last ``total*4``
        # bytes, so any data after the table would corrupt both.
        ijmp_targets = build_ijmp_targets(region)
        ijmp_map = ""
        if ijmp_targets:
            entries = "".join(f"  .quad {addr}\n  .long {offset}\n" for addr, offset in ijmp_targets)
            ijmp_map = f"ijmp_map:\n  .long {len(ijmp_targets)}\n{entries}"
        lines.append(
            f"vm_exit:\n{reload_seq}  add rsp, {_FRAME_SIZE}\n  jmp {hex(region.exit_vaddr)}\n"
            f"{ijmp_map}vm_table:\n{table}bytecode:\n"
        )
        # Thread the dispatch: every handler tail (and the retarget) ends with a back
        # jump to the (now removed) central dispatcher; splice a freshly shuffled
        # decode copy in for each so control flows handler -> decode -> next handler
        # with no shared hub block and no two copies sharing a byte layout.
        interpreter = thread_back_jumps("".join(lines), make_decode)
    # Relocate the flags slot: every flag capture/restore and the branch-free jcc's
    # flags read renders as the memory operand `[rsp + 128]` (the canonical 0x80
    # slot). 128 is unique to the flags slot in this interpreter - the GP slots are
    # <= 120, the checksum sits at >= 0x88 (never 128), and the xmm area is indexed
    # (`[rsp + r8 + ...]`) - so this rewrites exactly the flag references, moving the
    # slot off its fixed frame offset without threading it through every handler.
    return re.sub(r"\[rsp\s*\+\s*128\]", f"[rsp + {scheme.flags_offset}]", interpreter)


def build_region_blob(region: Region, cave_vaddr: int, scheme: RegionScheme) -> bytes | None:
    """Assemble the region interpreter at ``cave_vaddr`` and append its bytecode."""
    try:
        import keystone
    except ImportError:
        logger.warning("keystone unavailable; cannot virtualize region")
        return None
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(_interpreter_asm(region, scheme), cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("Region interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        return None
    data = bytearray(encoding)
    total = sum(len(indices) for indices in scheme.dup.values())
    if scheme.dispatch_shape == DISPATCH_SWITCH and not region.target_map:
        # Switch shape: no dispatch table, so the self-checksum covers the whole
        # interpreter code (up to vm_code_end, i.e. all of ``data`` before the
        # bytecode appended below) and there is nothing to encrypt in place.
        checksum = compute_build_checksum(bytes(data), scheme.xor_key)
    else:
        # The dispatch table (``total`` 32-bit offsets) is the tail of the assembled
        # interpreter; XOR-encrypt each entry in place so the handler addresses are
        # not a plaintext jump table. The dispatch decrypts them at runtime with the
        # same key, and keystone cannot XOR a label difference it computes itself, so
        # the encryption happens here on the assembled bytes.
        table_start = len(data) - total * 4
        # Expected runtime self-checksum over the interpreter code (everything up to
        # the dispatch table, so the table encryption below does not perturb it); the
        # encoder folds it into the opcodes, and the table key is diffused with it too.
        checksum = compute_build_checksum(bytes(data[:table_start]), scheme.xor_key)
        table_key = scheme.table_key ^ (checksum * 0x01010101)
        for entry_index in range(total):
            offset = table_start + entry_index * 4
            encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ table_key
            data[offset : offset + 4] = encrypted.to_bytes(4, "little")
    # The bytecode is appended right after the interpreter, so its base is the
    # cave plus the interpreter's assembled length; rip-relative targets are
    # encoded relative to it. A target too far to express as a signed 32-bit
    # offset leaves the function native.
    bytecode_base = cave_vaddr + len(data)
    try:
        bytecode = encode_region(region, scheme, bytecode_base, checksum)
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; leaving function native")
        return None
    return bytes(data) + bytecode
