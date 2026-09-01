"""Control-flow handler assembly for region virtualization."""

from __future__ import annotations

from dataclasses import dataclass

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    RSP_INDEX,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import _YMM_UPPER_SAVE_OFFSET
from r2morph.mutations.code_virtualization_region_handlers import (
    _FLAGS_OFFSET,
    _GUARD,
    _KEY_QWORD_SLOT,
    _MXCSR_SAVE_OFFSET,
    _XMM_SAVE_OFFSET,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    _indexed_address_asm,
    _indexed_address_nobase_asm,
    _mem_address_asm,
)
from r2morph.mutations.code_virtualization_region_models import (
    _DWORD_BROADCAST,
)

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
    "rol r11, {shift}",
    "shl r8, {shift}",
    "shr r9, {shift}",
    "imul r10, r11, {small}",
    "not r8",
    "neg r9",
    "test r10, r11",
    "cmp r8, r9",
    "bswap r10",
    "lea r11, [r8 + r9]",
    "mov r8, r10",
    "xor r9, r8",
)


def _junk_asm(rng: random.Random) -> str:
    """A short run of unreachable junk instructions for handler diversification.

    Operands are register-to-register or small immediates only, so every
    template always assembles - a junk instruction that failed to assemble
    would abort the whole virtualization.
    """
    lines = []
    for _ in range(rng.randint(1, 6)):
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
    "rol rbx, {shift}",
    "shl rbp, {shift}",
    "add rbx, rbp",
    "sub r12, rbx",
    "not rbp",
    "neg r12",
    "imul rbp, r12, {small}",
    "lea r12, [rbx + rbp]",
    "xchg r12, rbx",
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
    # s*s + s == s*(s+1), a product of adjacent integers, always even.
    ("  mov rbp, {s}\n  imul rbp, rbp\n  add rbp, {s}\n  test rbp, 1\n", "jz"),
    # s*s - s == s*(s-1), also adjacent integers, always even.
    ("  mov rbp, {s}\n  imul rbp, rbp\n  sub rbp, {s}\n  test rbp, 1\n", "jz"),
    # 2*s(s+1), an even value doubled, still even.
    ("  lea rbp, [{s} + 1]\n  imul rbp, {s}\n  shl rbp, 1\n  test rbp, 1\n", "jz"),
    # 2*s | 1, an even value with the low bit forced on, always odd.
    ("  lea rbp, [{s} + {s}]\n  or rbp, 1\n  test rbp, 1\n", "jnz"),
    # s | 3, low two bits forced on, always odd.
    ("  mov rbp, {s}\n  and rbp, {s}\n  or rbp, 3\n  test rbp, 1\n", "jnz"),
    # s*s | 1, a square with the low bit forced on, always odd.
    ("  mov rbp, {s}\n  imul rbp, rbp\n  or rbp, 1\n  test rbp, 1\n", "jnz"),
)
_OPAQUE_BRANCH_PROBABILITY = 0.5
_DWORD_WIDTH_BITS = 32


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
    if rng.random() < _OPAQUE_BRANCH_PROBABILITY:
        lines.append(_opaque_predicate_asm(rng, index))
    return "".join(lines)


# SysV integer-argument registers (plus rax for the varargs al-count) the call
# bridge loads from the program's frame slots before a native call, and spills
# back after to capture the callee's results.
_CALL_ARG_REGISTERS: tuple[str, ...] = ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax")
_XMM_REGISTERS = tuple(range(16))
_CALL_VPC_OFFSET = 0x2D0
_CALL_BASE_OFFSET = 0x2D8
_CALL_CALLEE_SAVED_REGISTERS: tuple[str, ...] = ("rbx", "rbp", "r13", "r14", "r15", "r12")


@dataclass(frozen=True)
class CallBridgeConfig:
    frame_size: int = 0x300
    flags_offset: int = _FLAGS_OFFSET
    stack_depth: int = 0
    preserve_ymm: bool = False
    stack_guard: int = _GUARD


def _call_frame_load_asm(register: str, offset: int) -> str:
    """Load one encrypted call-frame value through the stable frame base."""
    return (
        f"  mov r11, qword ptr [r12+{offset}]\n"
        f"  xor r11, qword ptr [r12+{_KEY_QWORD_SLOT}]\n"
        f"  mov {register}, r11\n"
    )


def _call_frame_spills_asm(slot: tuple[int, ...], flags_offset: int, preserve_ymm: bool) -> str:
    """Capture native call results into the encrypted VM frame after return."""
    xmm_spills = "".join(
        f"  movups xmmword ptr [r12+{_XMM_SAVE_OFFSET + index * 16}], xmm{index}\n" for index in _XMM_REGISTERS
    )
    ymm_spills = (
        "".join(
            f"  vextractf128 xmm0, ymm{index}, 1\n"
            f"  movups xmmword ptr [r12+{_YMM_UPPER_SAVE_OFFSET + index * 16}], xmm0\n"
            for index in _XMM_REGISTERS
        )
        if preserve_ymm
        else ""
    )
    register_spills = "".join(
        f"  xor {name}, qword ptr [r12+{_KEY_QWORD_SLOT}]\n"
        f"  mov qword ptr [r12+{slot[GP_REGISTERS.index(name)] * 8}], {name}\n"
        f"  xor {name}, qword ptr [r12+{_KEY_QWORD_SLOT}]\n"
        for name in _CALL_ARG_REGISTERS
    )
    return (
        f"  pushfq\n  pop qword ptr [r12+{flags_offset}]\n"
        + xmm_spills
        + ymm_spills
        + register_spills
        + f"  ldmxcsr dword ptr [r12+{_MXCSR_SAVE_OFFSET}]\n"
        + f"  mov rsi, qword ptr [r12+{_CALL_VPC_OFFSET}]\n"
        + f"  mov r15, qword ptr [r12+{_CALL_BASE_OFFSET}]\n"
        + "  mov rsp, r12\n"
    )


def _call_bridge_asm(
    index: int,
    slot: tuple[int, ...],
    target_asm: str,
    advance: int,
    bridge: CallBridgeConfig | None = None,
) -> str:
    """Bridge a virtualized call out to a native callee and back.

    ``target_asm`` is the prologue that leaves the absolute callee address in r10
    (the direct and register-indirect forms differ only there); ``advance`` is the
    call item's size. The VM frame and current stream pointers are saved in private
    frame cells before all six System V callee-saved registers are restored from the
    program context. On return, the frame base is reconstructed from the relocated
    program stack, so no interpreter register has to remain live inside the callee.
    The program's stack is relocated below the VM frame, so the manual return-address
    push and the callee's own frame never collide with the spilled context. Only rax
    and the loaded argument registers are spilled back; the rest of the caller-saved
    set is undefined across a call by the ABI.

    ``index`` makes the resume label unique across duplicated handler instances.
    """
    bridge = bridge or CallBridgeConfig()
    off = {name: slot[GP_REGISTERS.index(name)] * 8 for name in _CALL_ARG_REGISTERS}
    loads = "".join(f"  mov {name}, qword ptr [rsp+{off[name]}]\n" for name in _CALL_ARG_REGISTERS)
    xmm_loads = "".join(
        f"  movups xmm{index}, xmmword ptr [rsp+{_XMM_SAVE_OFFSET + index * 16}]\n" for index in _XMM_REGISTERS
    )
    ymm_loads = (
        "".join(
            f"  vinsertf128 ymm{index}, ymm{index}, xmmword ptr [rsp+{_YMM_UPPER_SAVE_OFFSET + index * 16}], 1\n"
            for index in _XMM_REGISTERS
        )
        if bridge.preserve_ymm
        else ""
    )
    callee_saved_loads = "".join(
        _call_frame_load_asm(register, slot[GP_REGISTERS.index(register)] * 8)
        for register in _CALL_CALLEE_SAVED_REGISTERS
        if register != "r12"
    )
    stack_load = f"  mov r11, qword ptr [r12+{slot[RSP_INDEX] * 8}]\n" f"  xor r11, qword ptr [r12+{_KEY_QWORD_SLOT}]\n"
    r12_load = _call_frame_load_asm("r12", slot[GP_REGISTERS.index("r12")] * 8)
    return (
        target_asm
        + f"  mov r12, rsp\n  mov rbx, rsi\n  mov qword ptr [rsp+{_CALL_VPC_OFFSET}], rsi\n"
        + f"  mov qword ptr [rsp+{_CALL_BASE_OFFSET}], r15\n"
        + f"  stmxcsr dword ptr [rsp+{_MXCSR_SAVE_OFFSET}]\n"
        + loads
        + xmm_loads
        + ymm_loads
        + callee_saved_loads
        + stack_load
        + "  mov rsp, r11\n"
        + r12_load
        + f"  lea r11, [rip+call_resume_{index}]\n  push r11\n  jmp r10\n"
        + f"call_resume_{index}:\n  lea r12, [rsp+{bridge.stack_guard - bridge.frame_size + bridge.stack_depth}]\n"
        + _call_frame_spills_asm(slot, bridge.flags_offset, bridge.preserve_ymm)
        + f"  add rsi, {advance}\n  jmp vm_dispatch\n"
    )


def _call_handler_asm(
    index: int,
    key_dword: str,
    slot: tuple[int, ...],
    bridge: CallBridgeConfig | None = None,
) -> str:
    """Direct ``call``: the target is a signed 32-bit offset from the bytecode
    base (r15, callee-saved so it survives the call), recomputed base-independently."""
    target = (
        f"  mov eax, dword ptr [rsi+1]\n  xor eax, {key_dword}\n"
        f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
        "  movsxd r10, eax\n  add r10, r15\n"
    )
    return _call_bridge_asm(index, slot, target, 5, bridge)


def _icall_handler_asm(
    index: int,
    key: str,
    slot: tuple[int, ...],
    bridge: CallBridgeConfig | None = None,
    internal_target_map: bool = False,
) -> str:
    """Register-indirect ``call reg`` with native fallback and local VM re-entry."""
    target = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n" "  mov r10, qword ptr [rsp+r8*8]\n"
    native = _call_bridge_asm(index, slot, target, 2, bridge)
    if not internal_target_map:
        return native
    return target + _internal_call_target_asm(index, slot[RSP_INDEX] * 8) + f"icall_native_{index}:\n" + native


def _internal_call_target_asm(index: int, rsp_off: int) -> str:
    """Re-enter a mapped local target, otherwise branch to the native bridge."""
    return (
        "  lea r11, [rip+ijmp_map]\n  neg r10\n  add r10, r11\n"
        "  mov ecx, dword ptr [r11]\n  add r11, 4\n"
        f"icall_scan_{index}:\n  test ecx, ecx\n  jz icall_native_{index}\n"
        f"  cmp qword ptr [r11], r10\n  je icall_internal_{index}\n"
        f"  add r11, 12\n  dec ecx\n  jmp icall_scan_{index}\n"
        f"icall_internal_{index}:\n  mov eax, dword ptr [r11+8]\n"
        "  lea r9, [rip+bytecode]\n  add r9, rax\n"
        "  lea r10, [rsi+2]\n"
        f"  mov r11, qword ptr [rsp+{rsp_off}]\n  sub r11, 8\n"
        "  mov qword ptr [r11], r10\n"
        f"  mov qword ptr [rsp+{rsp_off}], r11\n"
        "  mov rsi, r9\n  jmp vm_dispatch\n"
    )


def _syscall_handler_asm(slot: tuple[int, ...]) -> str:
    """Execute a returning Linux syscall with the program's real register state.

    The VM frame and bytecode pointer stay in r12/rbx while the program stack and
    syscall registers are restored. Linux clobbers rcx/r11 and returns in rax, so
    those values plus post-syscall flags are captured before dispatch resumes.
    Non-returning signal context restoration is outside this bridge's contract.
    """
    registers = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10")
    offsets = {name: slot[GP_REGISTERS.index(name)] * 8 for name in registers}
    loads = "".join(f"  mov {name}, qword ptr [rsp+{offsets[name]}]\n" for name in registers)
    stores = "".join(
        f"  mov qword ptr [rsp+{slot[GP_REGISTERS.index(name)] * 8}], {name}\n" for name in ("rax", "rcx", "r11")
    )
    return (
        "  mov r12, rsp\n  mov rbx, rsi\n"
        + loads
        + f"  mov rsp, qword ptr [r12+{slot[RSP_INDEX] * 8}]\n  xor rsp, qword ptr [r12+{_KEY_QWORD_SLOT}]\n"
        + "  syscall\n  mov rsp, r12\n"
        + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        + stores
        + "  mov rsi, rbx\n  add rsi, 1\n  jmp vm_dispatch\n"
    )


def _ijmp_handler_asm(index: int, key: str) -> str:
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
        "  mov r10, qword ptr [rsp+r8*8]\n" + _ijmp_scan_asm(index)
    )


def _ijmp_scan_asm(index: int) -> str:
    """Shared computed-jump re-entry: ``r10`` holds the runtime target address; scan
    the target map and, on a hit, commit the stored bytecode offset to the vIP so
    dispatch resumes at the virtualized target. A miss - a target outside the region,
    which a correctly-extracted region never produces - falls through to the default
    VM exit. Unique scan/hit labels keep duplicate handler instances distinct.

    The map keys the deltas ``ijmp_map - target`` rather than the link-time target
    addresses, so the scan is base-independent: ``lea`` already yields the runtime
    address of the map, and subtracting the runtime target from it cancels the load
    base (``(B+map) - (B+target) == map - target``). A non-relocated image sees the
    identical delta, so the non-PIE contract is unchanged. ``r10`` is dead past the
    scan (a hit reads only the map, a miss reloads every program register from its
    frame slot at ``vm_exit``), so normalizing it in place clobbers nothing; the
    native flags the normalization sets are already clobbered by the scan itself,
    and the program's flags live in their frame slot.
    """
    return (
        "  lea r11, [rip+ijmp_map]\n  neg r10\n  add r10, r11\n"
        "  mov ecx, dword ptr [r11]\n  add r11, 4\n"
        f"ijmp_scan_{index}:\n  test ecx, ecx\n  jz vm_exit\n"
        f"  cmp qword ptr [r11], r10\n  je ijmp_hit_{index}\n"
        f"  add r11, 12\n  dec ecx\n  jmp ijmp_scan_{index}\n"
        f"ijmp_hit_{index}:\n  mov eax, dword ptr [r11+8]\n"
        "  lea rsi, [rip+bytecode]\n  add rsi, rax\n  jmp vm_dispatch\n"
    )


def _ijmpmem_handler_asm(index: int, key: str, key_dword: str, field_perm: int, addr_variant: int = 0) -> str:
    """Memory-indirect computed jump ``jmp qword [base+index*scale+disp]`` (non-PIE
    jump-table switch). The shared indexed-address prologue computes the table-entry
    address into r10; dereferencing it loads the case target from the preserved rodata
    table, which is then re-entered through the target map."""
    address, _advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    return address + "  mov r10, qword ptr [r10]\n" + _ijmp_scan_asm(index)


def _ijmpmemnb_handler_asm(index: int, key: str, key_dword: str, field_perm: int, addr_variant: int = 0) -> str:
    """No-base memory-indirect computed jump ``jmp qword [index*scale+disp]`` - the
    common non-PIE switch where the table base is the displacement. Like
    :func:`_ijmpmem_handler_asm` without the base add."""
    address, _advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    return address + "  mov r10, qword ptr [r10]\n" + _ijmp_scan_asm(index)


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


@dataclass(frozen=True)
class VRetHandlerConfig:
    index: int
    ret_addr: int
    rsp_off: int
    bytecode_len: int
    reload_seq: str
    frame_size: int
    stack_cleanup: int = 0


@dataclass(frozen=True)
class CallMemoryHandlerConfig:
    index: int
    key: str
    key_dword: str
    slot: tuple[int, ...]
    field_perm: int
    addr_variant: int = 0
    frame_size: int = 0x300
    flags_offset: int = _FLAGS_OFFSET
    stack_depth: int = 0
    preserve_ymm: bool = False
    stack_guard: int = _GUARD


def _vret_handler_asm(config: VRetHandlerConfig) -> str:
    """Return-aware ``ret`` terminator for a region with in-function calls: if the top
    of the program's relocated stack is a resume vIP a ``vcall`` pushed (an address in
    the appended bytecode ``[r15, r15+bytecode_len)``), pop it and resume the VM there.
    Otherwise the frame has unwound to the outermost call, where the top is the zeroed
    floor cell vm_entry reserved (a non-bytecode value): reload the context, restore
    the real rsp, and return natively to ``ret_addr``. The bytecode range is a build-
    known invariant: a resume vIP always lands in the injected blob, and the floor cell
    and every genuine value below it never do."""
    cleanup = f"  add r10, {config.stack_cleanup}\n" if config.stack_cleanup else ""
    return (
        f"  mov r10, qword ptr [rsp+{config.rsp_off}]\n  mov r9, qword ptr [r10]\n"
        f"  mov r11, r9\n  sub r11, r15\n  cmp r11, {config.bytecode_len}\n"
        f"  jae vret_native_{config.index}\n"
        f"  add r10, 8\n" + cleanup + f"  mov qword ptr [rsp+{config.rsp_off}], r10\n  mov rsi, r9\n  jmp vm_dispatch\n"
        f"vret_native_{config.index}:\n{config.reload_seq}  add rsp, {config.frame_size}\n"
        f"  jmp {hex(config.ret_addr)}\n"
    )


def _call_mem_handler_asm(config: CallMemoryHandlerConfig, riprel: bool, internal_target_map: bool = False) -> str:
    """Memory-indirect ``call qword [mem]``: the callee address is a pointer loaded
    from memory (vtable / IAT-GOT dispatch). The shared memory-address prologue
    computes the pointer's address into r10 (base+disp from a frame slot, or
    bytecode base plus a stored offset for the rip-relative form); dereferencing it
    yields the target. The item carries an unused register field so it reuses the
    load handlers' address machinery and operand layout verbatim."""
    address, advance = _mem_address_asm(
        riprel,
        config.key,
        config.key_dword,
        config.field_perm,
        config.addr_variant,
    )
    target = address + "  mov r10, qword ptr [r10]\n"
    native = _call_bridge_asm(
        config.index,
        config.slot,
        target,
        advance,
        CallBridgeConfig(
            config.frame_size,
            config.flags_offset,
            config.stack_depth,
            config.preserve_ymm,
            config.stack_guard,
        ),
    )
    if not internal_target_map:
        return native
    return (
        target
        + _internal_call_target_asm(config.index, config.slot[RSP_INDEX] * 8)
        + f"icall_native_{config.index}:\n"
        + native
    )


def _call_mem_idx_handler_asm(
    config: CallMemoryHandlerConfig, no_base: bool = False, internal_target_map: bool = False
) -> str:
    """Indexed memory-indirect call through a function-pointer table.

    ``no_base`` selects the absolute ``index*scale+disp`` form; both forms use
    the same native-call bridge after loading the target pointer.
    """
    address_builder = _indexed_address_nobase_asm if no_base else _indexed_address_asm
    address, advance = address_builder(
        config.key,
        config.key_dword,
        config.field_perm,
        config.addr_variant,
    )
    target = address + "  mov r10, qword ptr [r10]\n"
    native = _call_bridge_asm(
        config.index,
        config.slot,
        target,
        advance,
        CallBridgeConfig(
            config.frame_size,
            config.flags_offset,
            config.stack_depth,
            config.preserve_ymm,
            config.stack_guard,
        ),
    )
    if not internal_target_map:
        return native
    return (
        target
        + _internal_call_target_asm(config.index, config.slot[RSP_INDEX] * 8)
        + f"icall_native_{config.index}:\n"
        + native
    )


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


def _setcc_slot_read(offset: int, key: str, reg: str) -> str:
    """Read the destination slot index at ``[rsi+offset]`` into 64-bit ``reg``.

    Mirrors the micro-op slot read: the byte is un-masked with the build key and
    the stream position (``r13b``, left holding it by the dispatch).
    """
    return f"  movzx {reg}d, byte ptr [rsi+{offset}]\n  xor {reg}b, {key}\n  xor {reg}b, r13b\n"


def _setcc_handler_asm(condition: str, key: str) -> str:
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


def _cmov_handler_asm(condition: str, width: int, key: str) -> str:
    """Emit a conditional-move handler that carries no native cmov.

    Computes a 0/-1 mask from the captured RFLAGS - like ``_jcc_handler_asm`` -
    then selects ``src`` or the current ``dst`` branch-free. A 32-bit move loads
    both operands 32-bit (zero-extending) so the qword write clears the upper half,
    matching x86-64's zero-extension; a 64-bit move keeps the full registers.
    """
    reg_suffix = "d" if width == _DWORD_WIDTH_BITS else ""
    size_kw = "dword" if width == _DWORD_WIDTH_BITS else "qword"
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


def _movx_reg_handler_asm(handler_key: str, key: str) -> str:
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
