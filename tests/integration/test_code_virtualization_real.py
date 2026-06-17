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

_DATASET = Path(__file__).resolve().parents[1].parent / "dataset"
FIXTURE = _DATASET / "elf_vm_arith_x86_64"
FIXTURE32 = _DATASET / "elf_vm_arith32_x86_64"
# Multi-block fixture: exercises the basic-block-bounded run extraction so a
# trampoline can never orphan an instruction reached by another edge.
FIXTURE_MULTIBLOCK = _DATASET / "elf_blockswap_x86_64"

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
    mapped: set[int] = set()

    def map_pages(start: int, length: int) -> None:
        for page in range(start & ~0xFFF, (start + length + 0xFFF) & ~0xFFF, 0x1000):
            if page not in mapped:
                mu.mem_map(page, 0x1000)
                mapped.add(page)

    for i in range(phnum):
        off = e_phoff + i * phentsize
        p_type = struct.unpack_from("<I", raw, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", raw, off + 8)
        map_pages(p_vaddr, max(p_memsz, p_filesz))
        mu.mem_write(p_vaddr, raw[p_offset : p_offset + p_filesz])

    map_pages(0x200000, 0x10000)
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


# Branch-heavy fixtures (comparisons, conditional/unconditional jumps, loops):
# the whole function is lowered into VM bytecode, so its exit code must survive.
_CONTROL_FLOW_FIXTURES = [
    "elf_jumpchain_x86_64",
    "elf_blockswap_x86_64",
    "elf_cff_flagdead_x86_64",
    "elf_cff_flaglive_x86_64",
    "elf_flag_live_x86_64",
]


@pytest.mark.parametrize("fixture_name", _CONTROL_FLOW_FIXTURES)
def test_control_flow_virtualization_preserves_exit_code(fixture_name: str, tmp_path: Path) -> None:
    fixture = _DATASET / fixture_name
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated"
    shutil.copy(fixture, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated)


def test_virtualized_isa_fixture_preserves_exit_code(tmp_path: Path) -> None:
    # Shifts, imul and test (with a flag-driven branch) must virtualize and
    # still produce the same result.
    fixture = _DATASET / "elf_vm_isa_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_isa"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 45


def test_virtualized_multiexit_fixture_preserves_exit_code(tmp_path: Path) -> None:
    # A function with two distinct terminators (early-exit + main path) must
    # virtualize, each terminator becoming its own VM exit.
    fixture = _DATASET / "elf_vm_multiexit_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_me"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_straight_line_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # This function contains a call, so the whole-function control-flow VM
    # rejects it; the pass must fall back to virtualizing the straight-line
    # register run before the call. Exercises the fallback path that every
    # fully-reducible fixture above bypasses.
    fixture = _DATASET / "elf_vm_run_callfallback_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_run"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 45


def test_memory_operand_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function stores to and loads from [rsp-8]; the control-flow VM must
    # virtualize the memory operands, computing the address from the captured
    # original rsp, and still produce the same result.
    fixture = _DATASET / "elf_vm_memops_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_mem"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_riprel_memory_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads a global through a rip-relative operand; the VM cannot
    # keep the absolute address after relocating the code, so it must reach the
    # global via a bytecode-base-relative offset and still produce the result.
    fixture = _DATASET / "elf_vm_global_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_glob"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_compare_with_memory_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function compares a register against a value in memory and branches on
    # the result; the VM must compute the address, run the real cmp, and capture
    # its flags so the branch is taken correctly (equal path -> exit 42).
    fixture = _DATASET / "elf_vm_cmpmem_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_cmpmem"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_arithmetic_with_memory_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function adds an rsp-relative operand and a rip-relative global into a
    # register; the VM must compute each address, apply the real arithmetic
    # against memory, and write the result back (12 + 20 + 10 -> exit 42).
    fixture = _DATASET / "elf_vm_opmem_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_opmem"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_lea_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function computes addresses with lea in both the rip-relative and the
    # base+displacement form; the VM must compute each address into the
    # destination register without dereferencing (*gval + 2 -> exit 42).
    fixture = _DATASET / "elf_vm_lea_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_lea"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_memory_destination_arithmetic_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function accumulates a register into memory in place (read-modify-
    # write); the VM must compute the address and apply the real op directly
    # against memory (30 + 12 -> exit 42).
    fixture = _DATASET / "elf_vm_memdst_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_memdst"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_large_unsigned_immediate_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads a 32-bit immediate whose high bit is set (beyond the
    # signed range, like a hash/magic constant); the VM must accept and carry it
    # rather than rejecting the instruction (0x8000002a & 0xff -> exit 42).
    fixture = _DATASET / "elf_vm_bigimm_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_bigimm"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_indexed_lea_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function computes a scaled-index address (base + index*scale) with lea;
    # the VM must scale the index by a shift and add the base from frame slots
    # (10 + 8*4 -> exit 42).
    fixture = _DATASET / "elf_vm_leaidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_leaidx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_indexed_memory_arithmetic_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function adds an array element addressed by a scaled index into a
    # register; the VM must compute base + index*scale, read memory there, and
    # apply the real op (10 + arr[1]=32 -> exit 42).
    fixture = _DATASET / "elf_vm_opmemidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_opmemidx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_incdec_virtualization_preserves_carry_flag(tmp_path: Path) -> None:
    # A compare sets the carry flag, then inc must preserve it (unlike add by
    # one) so the following branch on carry is taken; the VM must reload the
    # program's flags before the real inc (exit 42, a clobbered CF would exit 99).
    fixture = _DATASET / "elf_vm_incdec_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_incdec"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_three_operand_imul_virtualization_preserves_product(tmp_path: Path) -> None:
    # A 32-bit and a 64-bit three-operand imul (reg, reg, imm) drive branches;
    # the 64-bit product overflows 32 bits, so a truncated multiply or a
    # mis-widened immediate would change the exit code (42 correct, 99 wrong).
    fixture = _DATASET / "elf_vm_imul3_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_imul3"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_no_base_indexed_lea_virtualization_preserves_address(tmp_path: Path) -> None:
    # No-base scaled-index lea (lea reg, [index*scale + disp]) must compute the
    # scaled address without a base register; both [idx*8] and [idx*4+disp] drive
    # branches, so a wrong scale or displacement changes the exit code (42 vs 99).
    fixture = _DATASET / "elf_vm_leaidxnb_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_leaidxnb"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_thirty_two_bit_lea_virtualization_truncates_address(tmp_path: Path) -> None:
    # A plain and a scaled-index lea with a 32-bit destination must truncate the
    # (>32-bit) base address to its low 32 bits and zero-extend; shifting the
    # result down exposes a handler that stored the full 64-bit address (42 vs 99).
    fixture = _DATASET / "elf_vm_lea32_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_lea32"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_movabs_immediate_virtualization_preserves_high_word(tmp_path: Path) -> None:
    # Two movabs (mov reg, imm64) constants are shifted down to expose their high
    # word and branched on; a handler that truncated the 64-bit immediate would
    # change the exit code (42 correct, 99 wrong).
    fixture = _DATASET / "elf_vm_movabs_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_movabs"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_movzx_movsx_virtualization_preserves_extension(tmp_path: Path) -> None:
    # A high-bit byte is zero-extended (movzx -> 216) and sign-extended (movsx
    # -> -40), and the function branches on the full extended values; the VM must
    # reproduce each extension exactly (exit 42, a wrong extension would exit 99).
    fixture = _DATASET / "elf_vm_movx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_movx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_indexed_movzx_movsx_virtualization_preserves_extension(tmp_path: Path) -> None:
    # A byte addressed by an index is zero- and sign-extended, then the function
    # branches on the full extended values; the VM must compute the indexed
    # address and reproduce each extension (exit 42, a wrong one would exit 99).
    fixture = _DATASET / "elf_vm_movxidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_movxidx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def _text_range(path: Path) -> tuple[int, int, int]:
    """Return (entry_file_offset, exit_syscall_offset, vaddr_base) for the .text run."""
    raw = path.read_bytes()
    entry = struct.unpack_from("<Q", raw, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    phnum = struct.unpack_from("<H", raw, 0x38)[0]
    for i in range(phnum):
        off = e_phoff + i * phentsize
        p_type, p_flags = struct.unpack_from("<II", raw, off)
        p_offset, p_vaddr, _, _, _, _ = struct.unpack_from("<QQQQQQ", raw, off + 8)
        if p_type == 1 and p_flags & 0x1:
            entry_off = p_offset + (entry - p_vaddr)
            syscall_off = raw.index(b"\x0f\x05", entry_off)
            return entry_off, syscall_off, p_vaddr
    raise AssertionError("no executable segment")


def test_dead_body_is_overwritten_so_logic_is_unrecoverable(tmp_path: Path) -> None:
    # After whole-function virtualization the original instructions between the
    # trampoline and the terminator must no longer be present in the binary.
    fixture = _DATASET / "elf_blockswap_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    entry_off, syscall_off, _ = _text_range(fixture)
    original_body = fixture.read_bytes()[entry_off + 5 : syscall_off]
    assert b"\xb8\x01\x00\x00\x00" in original_body  # 'mov eax, 1' is present originally

    mutated = tmp_path / "mutated"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_body = mutated.read_bytes()[entry_off + 5 : syscall_off]
    assert mutated_body != original_body
    assert b"\xb8\x01\x00\x00\x00" not in mutated_body  # original logic destroyed
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated)  # ...yet still correct


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


def test_virtualized_32bit_fixture_preserves_exit_code(tmp_path: Path) -> None:
    if not FIXTURE32.exists():
        pytest.skip(f"fixture missing: {FIXTURE32}")

    mutated = tmp_path / "mutated32"
    shutil.copy(FIXTURE32, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(FIXTURE32) == _emulate_exit_code(mutated) == 45


def test_virtualizing_multiblock_binary_preserves_exit_code(tmp_path: Path) -> None:
    # A run must stay inside one basic block; otherwise the trampoline would
    # orphan an instruction reached by another edge. This fixture branches, so
    # extracting per-instruction-count rather than per-basic-block would crash.
    if not FIXTURE_MULTIBLOCK.exists():
        pytest.skip(f"fixture missing: {FIXTURE_MULTIBLOCK}")

    mutated = tmp_path / "mutated_mb"
    shutil.copy(FIXTURE_MULTIBLOCK, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert _emulate_exit_code(FIXTURE_MULTIBLOCK) == _emulate_exit_code(mutated)


def test_decode_instruction_widths_and_rejections() -> None:
    assert decode_instruction("mov eax, 1").width == 32  # 32-bit now supported
    assert decode_instruction("mov rax, 1").width == 64
    assert decode_instruction("add eax, rbx") is None  # mismatched operand widths
    assert decode_instruction("mov rsp, rax") is None  # interpreter owns rsp
    assert decode_instruction("mov esp, eax") is None  # ...in either width
    assert decode_instruction("mov rax, qword ptr [rbx]") is None  # memory operand
    assert decode_instruction("jmp 0x400000") is None  # control flow
    assert decode_instruction("add rbx, rcx") is not None  # plain 64-bit GP op
