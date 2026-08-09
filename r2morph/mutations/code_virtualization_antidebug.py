"""Timing and tracer anti-debug folded into the VM's runtime self-checksum.

The interpreter already rolls a one-byte checksum of its own body into a frame
slot and folds that slot into every opcode and table-entry decrypt, so a tampered
interpreter misdecodes and the dispatch bounds-guard routes control to the early
exit - there is no comparison or conditional branch to patch out. This module
reuses that exact slot: it times a short instruction window with the timestamp
counter and folds a *branch-free* 0-or-0xFF byte into the same slot.

An untraced run - and a Unicorn emulation - observes a tiny inter-read delta
(``< 2**N`` cycles), so the folded byte is provably ``0x00`` for EVERY per-build
variant. The stored checksum then stays exactly ``compute_build_checksum(...)``,
the encoder's opcode bias cancels as before, and the decode is bit-identical to a
build without the fold. A single-stepping debugger inflates the delta past
``2**N`` (a per-instruction ptrace trap dwarfs a handful of native cycles), the
byte becomes ``0xFF``, and every subsequent opcode and table entry misdecodes into
the exit path.

Because the benign contribution is ``0`` for all variants, the polymorphism below
has no Python mirror to keep in sync and cannot desync the checksum. The emitted
counter reads sit inside ``[vm_entry, vm_table)`` - the range
``compute_build_checksum`` already covers - so neither the encoder nor the
checksum computation changes.

The fold runs right after the checksum prologue and before dispatch, where every
GP register is already spilled to the frame; it touches only ``rax``/``rdx``/
``rcx``/``r8`` (all spilled, and ``rax`` is overwritten by the next prologue line),
never the not-yet-loaded ``rsi``/``r13``/``r14``/``r15``.
"""

from __future__ import annotations

import random

# A benign inter-read delta is a few hundred native cycles, far under ``2**16``;
# a single-step trap (a kernel round-trip per instruction) inflates it past any of
# these. 16-18 keeps the untraced path inert while still catching tracing.
_SHIFT_CHOICES = (16, 17, 18)

# Branch-free reductions of "delta is non-zero" to ``al`` in ``{0x00, 0xFF}``.
# After ``neg rax`` the carry flag is set iff ``rax`` was non-zero, so ``sbb X, X``
# yields ``-CF`` (0 or all-ones) and ``al`` carries the same low byte in any width.
_REDUCE_CHOICES = ("sbb eax, eax", "sbb rax, rax", "sbb al, al")

# The counter read leaves the timestamp in ``edx:eax`` (both zero-extended); the
# high half is disjoint from the low half, so ``or`` and ``add`` assemble the same
# 64-bit value.
_COMBINE_CHOICES = ("or", "add")

# Register pool for the surviving first timestamp and the discardable work window.
# ``r8`` always survives the second read; ``rcx`` survives only under plain
# ``rdtsc`` (``rdtscp`` writes ``ecx`` with TSC_AUX).
_SCRATCH_HIGH = "r8"
_SCRATCH_LOW = "rcx"

# Maximum window increment: keeps the work-window constant a small immediate.
_WINDOW_MASK = 0x7F


def _dword_name(reg64: str) -> str:
    """The 32-bit sub-register spelling for the scratch 64-bit registers used here."""
    return {"r8": "r8d", "rcx": "ecx"}[reg64]


def _combine_timestamp(combine: str) -> str:
    """Assemble the counter's ``edx:eax`` pair into a 64-bit value in ``rax``."""
    return f"  shl rdx, 32\n  {combine} rax, rdx\n"


def _work_window(work_reg: str, key: int) -> str:
    """State-neutral cycles between the two reads on a discardable scratch register.

    The result is never read; the window exists only so a debugger's per-instruction
    single-step overhead has something to accumulate against the timestamp delta.
    """
    reg = _dword_name(work_reg)
    step = (key & _WINDOW_MASK) + 1
    return f"  xor {reg}, {reg}\n  add {reg}, {step}\n  imul {reg}, {reg}, 3\n  rol {reg}, 1\n"


# The tracer probe reads /proc/self/status and folds a byte into the checksum slot
# when a debugger is attached (TracerPid != 0). It is observational only - unlike
# ptrace(PTRACE_TRACEME), reading procfs has no effect on the traced process, so it
# never alters the semantics of an arbitrary virtualized program (a target that
# later execve's or handles signals is untouched). The whole "/proc/self/status"
# path is 17 bytes; these two little-endian qwords plus a trailing 's\0' spell it
# on the stack without materializing a plaintext string in the interpreter's data.
_STATUS_PATH_LO = 0x65732F636F72702F  # "/proc/se"
_STATUS_PATH_HI = 0x75746174732F666C  # "lf/statu"

# "TracerPi" (the first 8 bytes of the "TracerPid:" line) as a little-endian qword,
# scanned for with an unaligned qword compare. The decimal digit that says whether a
# tracer is attached sits 11 bytes past the match ("TracerPid:\t<digit>"): '0' when
# untraced, the tracer's PID otherwise.
_TRACERPID_TAG = 0x6950726563617254
_TRACERPID_DIGIT_OFFSET = 11

# procfs read buffer, carved transiently below the interpreter frame (never moving
# rsp). TracerPid appears within the first ~150 bytes of status (Name, Umask, State,
# Tgid, Ngid, Pid, PPid, TracerPid), well inside this window.
_STATUS_BUF_OFFSET = 0x100
_STATUS_PATH_OFFSET = 0x40
_STATUS_READ_LEN = 192
_STATUS_SCAN_LIMIT = 180


# The tracer constants (path words + scan tag) live in a data island appended
# after the dispatch table, outside the checksummed ``[vm_entry, vm_table)`` span,
# stored as ``const ^ broadcast(checksum)`` and de-masked at runtime against the
# interpreter's own self-checksum byte. A masking immediate two instructions away
# is constant-folded by a decompiler straight back to the plaintext string; the
# self-checksum is the result of a loop over the whole code segment, which the
# decompiler leaves as an opaque runtime value, so the folded expression can no
# longer be evaluated and the ``/proc/self/status`` path and ``TracerPid`` tag
# never render as literals. The island sits outside the checksummed range so the
# masked bytes do not feed the checksum they are masked by (no circular fixpoint).
_TRACER_ISLAND_LABEL = "tracer_const_island"
# Three little-endian qwords: path low, path high, scan tag - patched after
# assembly by :func:`patch_tracer_constants`.
_TRACER_ISLAND_LEN = 24


def _broadcast_checksum_to(reg: str, slot: int) -> str:
    """Load the self-checksum byte from ``slot`` and smear it across all 8 lanes.

    ``checksum * 0x0101010101010101`` places the byte in every lane with no
    inter-lane carry (the byte is ``< 256``), yielding the same 64-bit value the
    build XORed into each stored constant. ``rcx`` is free scratch in this window.
    """
    return f"  movzx {reg}, byte ptr [rsp+{slot}]\n  mov rcx, 0x0101010101010101\n  imul {reg}, rcx\n"


def _load_checksum_masked(reg: str, field_offset: int, slot: int) -> str:
    """Reconstruct a stored constant into ``reg`` from the island, keyed by checksum.

    Loads ``const ^ broadcast(checksum)`` from ``[rip+island+field_offset]`` and
    XORs the runtime checksum broadcast back out. Because the key is the opaque
    self-checksum, a decompiler cannot fold the XOR to the underlying constant.
    ``rdx``/``rcx`` are free scratch here.
    """
    label = _TRACER_ISLAND_LABEL if field_offset == 0 else f"{_TRACER_ISLAND_LABEL}+{field_offset}"
    return f"  mov {reg}, qword ptr [rip+{label}]\n" + _broadcast_checksum_to("rdx", slot) + f"  xor {reg}, rdx\n"


def tracer_const_island_asm() -> str:
    """The appended constant island: three qword placeholders patched post-assembly.

    Emitted after the dispatch table (so it stays outside the checksummed span) and
    before the bytecode. The zero placeholders are overwritten by
    :func:`patch_tracer_constants` once the build checksum is known.
    """
    return f"{_TRACER_ISLAND_LABEL}:\n  .quad 0\n  .quad 0\n  .quad 0\n"


def patch_tracer_constants(data: bytearray, island_start: int, checksum: int) -> None:
    """Write ``const ^ broadcast(checksum)`` into the island at ``island_start``.

    Mirrors the runtime de-mask: the interpreter loads each qword and XORs the
    checksum broadcast back out, recovering the path words and scan tag. The island
    lies outside the checksummed range, so these writes do not perturb ``checksum``.
    """
    broadcast = (checksum & 0xFF) * 0x0101010101010101
    for i, const in enumerate((_STATUS_PATH_LO, _STATUS_PATH_HI, _TRACERPID_TAG)):
        offset = island_start + i * 8
        data[offset : offset + 8] = ((const ^ broadcast) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def tracer_detect_asm(slot: int) -> str:
    """Assembly that folds a *ptrace-tracer* signal into the checksum ``slot`` byte.

    Emitted right after :func:`timing_fold_asm`, in the same window where every GP
    register is spilled to the frame and the VM-internal ``rsi``/``r13``/``r14``/
    ``r15`` are not yet loaded, so the whole block is free to use every register but
    ``rsp``. It opens ``/proc/self/status``, reads the header into a transient
    buffer below the frame, scans for the ``TracerPid:`` line, and folds a
    *branch-free* 0-or-0xFF byte into ``slot``: ``0x00`` when the tracer PID is
    ``'0'`` (no debugger) and ``0xFF`` otherwise.

    Like the timing fold, the benign contribution is provably ``0`` for the common
    cases, so there is no Python mirror and the stored checksum is unchanged: an
    untraced native run reads ``TracerPid:\\t0`` and folds ``0``; a Unicorn emulation
    - whose only emulated syscall is ``exit`` - leaves ``openat``/``read`` as no-ops
    over a zero-filled buffer, the ``TracerPid`` tag is never found, and the fold is
    ``0`` as well. A run under ptrace resolves a non-zero tracer PID, the byte
    becomes ``0xFF``, and every subsequent opcode and table entry misdecodes into
    the exit path. This catches an *attached* debugger even when it is not single
    stepping (which the timing fold would miss).

    The ``/proc/self/status`` path words and the ``TracerPid`` scan tag would
    otherwise be fixed plaintext immediates - an anti-debug tell a static scan greps
    for and a decompiler folds back to a literal string even when they are masked by
    a second immediate. Each is instead stored as ``const ^ broadcast(checksum)`` in
    the appended :func:`tracer_const_island_asm` and reconstructed here by XORing the
    runtime self-checksum broadcast back out, so ``.text`` carries no plaintext and
    the folded expression keys on a value the decompiler cannot evaluate.

    ``slot`` is the frame offset of the checksum byte (the same one the timing fold
    and every opcode decrypt use); it doubles as the de-mask key here.
    """
    return (
        # Spell "/proc/self/status\0" just below the frame (transient scratch), each
        # path word reconstructed from the checksum-keyed island, not a plaintext one.
        f"  lea r11, [rsp - {hex(_STATUS_PATH_OFFSET)}]\n"
        + _load_checksum_masked("rax", 0, slot)
        + "  mov qword ptr [r11], rax\n"
        + _load_checksum_masked("rax", 8, slot)
        + "  mov qword ptr [r11+8], rax\n"
        + "  mov word ptr [r11+16], 0x73\n"
        # openat(AT_FDCWD, path, O_RDONLY); rax = fd (or a no-op 257 under Unicorn).
        + "  mov rax, 257\n  mov rdi, -100\n  mov rsi, r11\n  xor edx, edx\n  xor r10d, r10d\n  syscall\n"
        + "  mov r8, rax\n"
        # read(fd, buf, len) into the transient buffer, then close(fd).
        + f"  mov rdi, r8\n  lea rsi, [rsp - {hex(_STATUS_BUF_OFFSET)}]\n  xor eax, eax\n  mov edx, {_STATUS_READ_LEN}\n  syscall\n"
        + "  mov rdi, r8\n  mov eax, 3\n  syscall\n"
        # Scan the buffer for the "TracerPid:" line via an unaligned qword compare;
        # the scan tag is reconstructed from the checksum-keyed island for the same reason.
        + f"  lea rsi, [rsp - {hex(_STATUS_BUF_OFFSET)}]\n"
        + _load_checksum_masked("r9", 16, slot)
        + "  xor ecx, ecx\n  xor r8d, r8d\n"
        + "tracer_scan:\n"
        + f"  cmp r8d, {_STATUS_SCAN_LIMIT}\n  jae tracer_done\n"
        + "  mov rax, qword ptr [rsi+r8]\n  cmp rax, r9\n  je tracer_found\n  inc r8\n  jmp tracer_scan\n"
        + "tracer_found:\n"
        # The digit after "TracerPid:\t"; anything but '0' (0x30) means a tracer.
        + f"  movzx eax, byte ptr [rsi+r8+{_TRACERPID_DIGIT_OFFSET}]\n  cmp al, 0x30\n  setne cl\n"
        + "tracer_done:\n"
        + f"  neg cl\n  xor byte ptr [rsp+{slot}], cl\n"
    )


def timing_fold_asm(key: int, slot: int) -> str:
    """Assembly that folds a timing signal into the checksum ``slot`` byte.

    Emitted after ``checksum_prologue_asm`` and before dispatch. ``key`` (the
    build's ``xor_key``) selects the shift, the scratch registers, the fence
    bracketing, the read instruction and the reduce spelling; because the benign
    contribution is ``0`` for every choice, the variation is free of any Python
    mirror. ``slot`` is the frame offset of the checksum byte (engine and region
    interpreters use different offsets).
    """
    rng = random.Random(key)
    shift = rng.choice(_SHIFT_CHOICES)
    use_rdtscp = rng.random() < 0.5
    use_lfence = rng.random() < 0.5
    reduce_spelling = rng.choice(_REDUCE_CHOICES)
    combine = rng.choice(_COMBINE_CHOICES)

    read = "rdtscp" if use_rdtscp else "rdtsc"
    # The first timestamp must survive the second read. ``rdtscp`` clobbers ``rcx``,
    # so it can only live in ``r8`` there; plain ``rdtsc`` may keep it in either.
    first_reg = _SCRATCH_HIGH if use_rdtscp else rng.choice((_SCRATCH_HIGH, _SCRATCH_LOW))
    work_reg = _SCRATCH_LOW if first_reg == _SCRATCH_HIGH else _SCRATCH_HIGH

    fence = "  lfence\n" if use_lfence else ""
    return (
        f"  {read}\n"
        + _combine_timestamp(combine)
        + f"  mov {first_reg}, rax\n"
        + fence
        + _work_window(work_reg, key)
        + fence
        + f"  {read}\n"
        + _combine_timestamp(combine)
        + f"  sub rax, {first_reg}\n"
        + f"  shr rax, {shift}\n"
        + "  neg rax\n"
        + f"  {reduce_spelling}\n"
        + f"  xor byte ptr [rsp+{slot}], al\n"
    )
