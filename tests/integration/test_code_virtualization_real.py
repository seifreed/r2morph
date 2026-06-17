"""
Regression: code virtualization must preserve program semantics.

These tests run the ACTUAL produced binary, not a model: the pass virtualizes
a register run on a real ELF fixture, and a Unicorn emulation of the resulting
file confirms the exit code is unchanged. No mocks, no monkeypatch - a real
Binary, the real radare2-native injection, and the real generated interpreter.
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_engine import decode_instruction

FIXTURE = Path(__file__).resolve().parents[1].parent / "dataset" / "elf_vm_arith_x86_64"

unicorn = pytest.importorskip("unicorn")
from unicorn import UC_ARCH_X86, UC_HOOK_INSN, UC_MODE_64, Uc  # noqa: E402
from unicorn.x86_const import UC_X86_INS_SYSCALL, UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSP  # noqa: E402

_EXIT_SYSCALL = 0x3C


def _emulate_exit_code(path: Path) -> int | None:
    """Load an ELF64's PT_LOADs and run from the entrypoint to the exit syscall."""
    raw = path.read_bytes()
    entry = struct.unpack_from("<Q", raw, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    phnum = struct.unpack_from("<H", raw, 0x38)[0]

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    for i in range(phnum):
        off = e_phoff + i * phentsize
        p_type = struct.unpack_from("<I", raw, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", raw, off + 8)
        base = p_vaddr & ~0xFFF
        size = ((p_vaddr + max(p_memsz, p_filesz) + 0xFFF) & ~0xFFF) - base
        mu.mem_map(base, max(size, 0x1000))
        mu.mem_write(p_vaddr, raw[p_offset : p_offset + p_filesz])

    mu.mem_map(0x200000, 0x10000)
    mu.reg_write(UC_X86_REG_RSP, 0x208000)

    captured: dict[str, int] = {}

    def on_syscall(uc: Uc, _user_data: object) -> None:
        if uc.reg_read(UC_X86_REG_RAX) == _EXIT_SYSCALL:
            captured["code"] = uc.reg_read(UC_X86_REG_RDI) & 0xFF
            uc.emu_stop()

    mu.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
    mu.emu_start(entry, 0, count=50000)
    return captured.get("code")


def test_virtualized_fixture_preserves_exit_code(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(FIXTURE) == _emulate_exit_code(mutated) == 45


def _virtualize(src: Path, dst: Path) -> bytes:
    """Virtualize ``src`` into ``dst`` and return the appended VM region bytes."""
    shutil.copy(src, dst)
    original_size = src.stat().st_size
    binary = Binary(str(dst), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    assert stats["functions_virtualized"] >= 1
    return dst.read_bytes()[original_size:]


def test_virtualization_is_polymorphic_yet_semantically_stable(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    first_region = _virtualize(FIXTURE, tmp_path / "first")
    second_region = _virtualize(FIXTURE, tmp_path / "second")

    # Two builds of the same input share no static VM signature (randomized
    # opcodes + encrypted bytecode) yet both preserve the exit code.
    assert first_region and second_region
    assert first_region != second_region
    assert _emulate_exit_code(tmp_path / "first") == _emulate_exit_code(tmp_path / "second") == 45


def test_decode_instruction_rejects_uneproducible_operands() -> None:
    assert decode_instruction("mov eax, 1") is None  # 32-bit width not modeled
    assert decode_instruction("mov rsp, rax") is None  # interpreter owns rsp
    assert decode_instruction("mov rax, qword ptr [rbx]") is None  # memory operand
    assert decode_instruction("jmp 0x400000") is None  # control flow
    assert decode_instruction("add rbx, rcx") is not None  # plain 64-bit GP op
