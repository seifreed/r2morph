"""Tracer detection folded into the VM's runtime self-checksum.

The interpreter already rolls a one-byte checksum of its own body into a frame
slot and folds that slot into every opcode and table-entry decrypt, so a tampered
interpreter misdecodes and the dispatch bounds-guard routes control to the early
exit. This module reuses that exact slot for a branch-free ``TracerPid`` signal.
Unlike elapsed-time heuristics, the kernel-reported tracer state cannot corrupt a
benign execution because the process was descheduled or emulated slowly.
"""

from __future__ import annotations

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
# Six little-endian qwords, all checksum-masked and patched after assembly by
# :func:`patch_tracer_constants`: path low, path high, scan tag, then the three
# syscall numbers (openat/read/close). The syscall numbers are masked for the same
# reason as the string: a plaintext ``mov rax, 257`` lets a decompiler attribute the
# probe as ``sys_openat`` / ``sys_read`` / ``sys_close``; loading the number from the
# checksum-keyed island leaves the syscall register opaque, so the anti-debug syscalls
# are no longer named in the pseudocode.
_SYS_OPENAT = 257
_SYS_READ = 0
_SYS_CLOSE = 3
# AT_FDCWD, the openat dirfd. A plaintext ``mov rdi, -100`` is itself an openat tell
# even once the syscall number is masked, so it is masked too, leaving the openat
# call with no foldable constant in the decompiler.
_AT_FDCWD = -100 & 0xFFFFFFFFFFFFFFFF
# Field offsets into the island for the syscall-setup qwords.
# The ASCII '0' the tracer digit is compared against. A plaintext ``cmp al, 0x30``
# is itself the tell - a decompiler folds it to ``!= '0'`` and names the TracerPid
# check - so it is masked too, leaving the compare with no foldable literal.
_TRACERPID_ZERO = 0x30
_SYS_OPENAT_OFFSET = 24
_SYS_READ_OFFSET = 32
_SYS_CLOSE_OFFSET = 40
_AT_FDCWD_OFFSET = 48
_TRACERPID_ZERO_OFFSET = 56
_TRACER_ISLAND_CONSTS = (
    _STATUS_PATH_LO,
    _STATUS_PATH_HI,
    _TRACERPID_TAG,
    _SYS_OPENAT,
    _SYS_READ,
    _SYS_CLOSE,
    _AT_FDCWD,
    _TRACERPID_ZERO,
)
_TRACER_ISLAND_LEN = 8 * len(_TRACER_ISLAND_CONSTS)


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

    Emitted after the encrypted offset tables (so it stays outside the checksummed
    span) and before the bytecode. The zero placeholders are overwritten by
    :func:`patch_tracer_constants` once the build checksum is known.
    """
    quads = "".join("  .quad 0\n" for _ in _TRACER_ISLAND_CONSTS)
    return f"{_TRACER_ISLAND_LABEL}:\n{quads}"


def patch_tracer_constants(data: bytearray, island_start: int, checksum: int) -> None:
    """Write ``const ^ broadcast(checksum)`` into the island at ``island_start``.

    Mirrors the runtime de-mask: the interpreter loads each qword and XORs the
    checksum broadcast back out, recovering the path words and scan tag. The island
    lies outside the checksummed range, so these writes do not perturb ``checksum``.
    """
    broadcast = (checksum & 0xFF) * 0x0101010101010101
    for i, const in enumerate(_TRACER_ISLAND_CONSTS):
        offset = island_start + i * 8
        data[offset : offset + 8] = ((const ^ broadcast) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def tracer_detect_asm(slot: int) -> str:
    """Assembly that folds a *ptrace-tracer* signal into the checksum ``slot`` byte.

    Runs as one integrity-keyed bootstrap state while every GP register is spilled
    to the frame and the VM-internal ``rsi``/``r13``/``r14``/``r15`` are not yet
    loaded, so the whole block is free to use every register but ``rsp``. It opens
    ``/proc/self/status``, reads the header into a transient
    buffer below the frame, scans for the ``TracerPid:`` line, and folds a
    *branch-free* 0-or-0xFF byte into ``slot``: ``0x00`` when the tracer PID is
    ``'0'`` (no debugger) and ``0xFF`` otherwise.

    The benign contribution is ``0`` for the common cases, so there is no Python
    mirror and the stored checksum is unchanged: an
    untraced native run reads ``TracerPid:\\t0`` and folds ``0``; a Unicorn emulation
    - whose only emulated syscall is ``exit`` - leaves ``openat``/``read`` as no-ops
    over a zero-filled buffer, the ``TracerPid`` tag is never found, and the fold is
    ``0`` as well. A run under ptrace resolves a non-zero tracer PID, the byte
    becomes ``0xFF``, and every subsequent opcode and table entry misdecodes into
    the exit path. This catches both single-stepping and free-running tracers.

    The ``/proc/self/status`` path words and the ``TracerPid`` scan tag would
    otherwise be fixed plaintext immediates - an anti-debug tell a static scan greps
    for and a decompiler folds back to a literal string even when they are masked by
    a second immediate. Each is instead stored as ``const ^ broadcast(checksum)`` in
    the appended :func:`tracer_const_island_asm` and reconstructed here by XORing the
    runtime self-checksum broadcast back out, so ``.text`` carries no plaintext and
    the folded expression keys on a value the decompiler cannot evaluate.

    ``slot`` is the frame offset of the checksum byte used by every opcode decrypt;
    it doubles as the de-mask key here.
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
        # The syscall number is reconstructed from the checksum-keyed island, not a
        # plaintext immediate, so a decompiler cannot fold rax to 257 and name openat.
        + _load_checksum_masked("rax", _SYS_OPENAT_OFFSET, slot)
        + _load_checksum_masked("rdi", _AT_FDCWD_OFFSET, slot)
        + "  mov rsi, r11\n  xor edx, edx\n  xor r10d, r10d\n  syscall\n"
        + "  mov r8, rax\n"
        # read(fd, buf, len) into the transient buffer, then close(fd) - both syscall
        # numbers likewise de-masked from the island so neither is named in pseudocode.
        + f"  mov rdi, r8\n  lea rsi, [rsp - {hex(_STATUS_BUF_OFFSET)}]\n"
        + _load_checksum_masked("rax", _SYS_READ_OFFSET, slot)
        + f"  mov edx, {_STATUS_READ_LEN}\n  syscall\n"
        + "  mov rdi, r8\n"
        + _load_checksum_masked("rax", _SYS_CLOSE_OFFSET, slot)
        + "  syscall\n"
        # Scan the buffer for the "TracerPid:" line via an unaligned qword compare;
        # the scan tag is reconstructed from the checksum-keyed island for the same reason.
        + f"  lea rsi, [rsp - {hex(_STATUS_BUF_OFFSET)}]\n"
        + _load_checksum_masked("r9", 16, slot)
        + "  xor ecx, ecx\n  xor r8d, r8d\n"
        + "tracer_scan:\n"
        + f"  cmp r8d, {_STATUS_SCAN_LIMIT}\n  jae tracer_done\n"
        + "  mov rax, qword ptr [rsi+r8]\n  cmp rax, r9\n  je tracer_found\n  inc r8\n  jmp tracer_scan\n"
        + "tracer_found:\n"
        # The digit after "TracerPid:\t"; anything but '0' means a tracer. The '0'
        # is de-masked from the checksum-keyed island so the compare carries no
        # plaintext 0x30 for a decompiler to fold into a named TracerPid check.
        + f"  movzx eax, byte ptr [rsi+r8+{_TRACERPID_DIGIT_OFFSET}]\n"
        + _load_checksum_masked("rdi", _TRACERPID_ZERO_OFFSET, slot)
        + "  cmp al, dil\n  setne cl\n"
        + "tracer_done:\n"
        + f"  neg cl\n  xor byte ptr [rsp+{slot}], cl\n"
    )
