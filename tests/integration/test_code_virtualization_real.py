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
from r2morph.mutations.code_virtualization import CodeVirtualizationPass, _decode_run_item
from r2morph.mutations.code_virtualization_engine import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    decode_instruction,
)

_DATASET = Path(__file__).resolve().parents[1].parent / "dataset"
FIXTURE = _DATASET / "elf_vm_arith_x86_64"
FIXTURE32 = _DATASET / "elf_vm_arith32_x86_64"
# Multi-block fixture: exercises the basic-block-bounded run extraction so a
# trampoline can never orphan an instruction reached by another edge.
FIXTURE_MULTIBLOCK = _DATASET / "elf_blockswap_x86_64"

unicorn = pytest.importorskip("unicorn")
from unicorn import UC_ARCH_X86, UC_HOOK_INSN, UC_MODE_64, Uc, UcError  # noqa: E402
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
    # Instruction cap to bound a runaway emulation; sized well above a faithful
    # run. The interpreter's one-time entry self-checksum scans its whole body, so
    # the count scales with the (now broad) handler set - a real virtualized run
    # executes on the order of 10^4-10^5 instructions, so 2_000_000 leaves ample
    # headroom while still terminating a true infinite loop near-instantly.
    mu.emu_start(entry, 0, count=2_000_000)
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


# The interpreter's first instruction is a constant-size frame allocation
# (``sub rsp, 0x180``); the injected blob is appended at end-of-file, so this
# byte sequence marks vm_entry, the start of the checksummed region.
_VM_ENTRY_SIGNATURE = bytes.fromhex("4881EC80020000")


def test_tampering_interpreter_byte_diverges_from_original(tmp_path: Path) -> None:
    # Anti-tamper: the interpreter checksums its own code into every opcode
    # decrypt, so flipping a single byte of the interpreter body must change the
    # observable result - there is no comparison to patch out, the corrupted
    # checksum simply misdecodes the bytecode.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    data = bytearray(mutated.read_bytes())
    vm_entry = data.find(_VM_ENTRY_SIGNATURE)
    assert vm_entry != -1, "interpreter not found in mutated binary"
    assert _emulate_exit_code(mutated) == 45  # faithful build still runs

    # Flip one byte inside the interpreter body (past the frame allocation, in
    # the spill/dispatch region the checksum covers) and re-emulate.
    data[vm_entry + 0x10] ^= 0xFF
    tampered = tmp_path / "tampered"
    tampered.write_bytes(bytes(data))
    try:
        tampered_code = _emulate_exit_code(tampered)
    except UcError:
        tampered_code = None  # a trap is also a divergence from exit 45
    assert tampered_code != 45


# Fixtures with at least one register-op run to peel into a nested inner VM.
_NESTING_FIXTURES = [
    ("elf_vm_arith_x86_64", 45),
    ("elf_vm_isa_x86_64", None),
    ("elf_jumpchain_x86_64", None),
    ("elf_blockswap_x86_64", None),
]


@pytest.mark.parametrize("depth", [2, 3])
@pytest.mark.parametrize("fixture_name,expected", _NESTING_FIXTURES)
def test_nested_virtualization_preserves_exit_code(
    fixture_name: str, expected: int | None, depth: int, tmp_path: Path
) -> None:
    # N-layer nesting: each layer transfers a peeled register-op run into the
    # next, independently-keyed VM and back. The exit code must survive.
    fixture = _DATASET / fixture_name
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "vm_nesting_depth": depth}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    baseline = _emulate_exit_code(fixture)
    assert _emulate_exit_code(mutated) == baseline
    if expected is not None:
        assert baseline == expected


def test_nested_virtualization_grows_with_depth(tmp_path: Path) -> None:
    # Structural proof of recursion: adding an inner layer adds its own dispatch
    # table and interpreter, so the blob grows. A fixed seed holds the random
    # handler duplication and MBA-variant sizes constant across depths, so the
    # nesting depth is the only variable. Depth 3 only exceeds depth 2 when the
    # function has a second peelable register-op run, so that bound is non-strict.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    def _blob_size(depth: int) -> int:
        mutated = tmp_path / f"depth{depth}"
        shutil.copy(FIXTURE, mutated)
        binary = Binary(str(mutated), writable=True)
        binary.open()
        try:
            CodeVirtualizationPass(config={"probability": 1.0, "vm_nesting_depth": depth, "seed": 1234}).apply(binary)
            binary.save()
        finally:
            binary.close()
        return len(mutated.read_bytes())

    assert _blob_size(1) < _blob_size(2) <= _blob_size(3)


def test_tampering_nested_interpreter_byte_diverges(tmp_path: Path) -> None:
    # The self-checksum spans both layers, so flipping one interpreter byte of a
    # nested build must still diverge from the original exit code.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "vm_nesting_depth": 2}).apply(binary)
        binary.save()
    finally:
        binary.close()

    data = bytearray(mutated.read_bytes())
    vm_entry = data.find(_VM_ENTRY_SIGNATURE)
    assert vm_entry != -1
    assert _emulate_exit_code(mutated) == 45
    data[vm_entry + 0x10] ^= 0xFF
    tampered = tmp_path / "tampered"
    tampered.write_bytes(bytes(data))
    try:
        tampered_code = _emulate_exit_code(tampered)
    except UcError:
        tampered_code = None
    assert tampered_code != 45


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


def test_call_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The whole function is region-reducible except for one direct call, so the
    # control-flow VM must virtualize it end to end: the new call handler bridges
    # out to the native callee (with the argument loaded from its frame slot),
    # captures the return value, keeps the relocated stack balanced, and resumes.
    # No straight-line run of >=2 engine-supported ops exists outside the region
    # (the surrounding movs are isolated and push/pop/call are region-only), so a
    # virtualized function here can only be the whole-function call path.
    fixture = _DATASET / "elf_vm_call_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_call"
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


def test_indirect_call_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The only non-register instruction is a register-indirect call (call rax),
    # whose target is materialized into rax beforehand. The VM must read the call
    # target from rax's frame slot at runtime, bridge out to the native callee,
    # and capture the return value - the base-independent indirect-call path.
    fixture = _DATASET / "elf_vm_icall_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_icall"
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


def test_memory_indirect_call_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # Two memory-indirect calls - one rip-relative (call [rip+vt], the IAT/GOT
    # form) and one base-relative (call [rax], the vtable form). For each, the VM
    # must compute the pointer's address, load the callee from memory, bridge out
    # to it and capture the return value, reusing the load handlers' address
    # machinery.
    fixture = _DATASET / "elf_vm_mcall_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_mcall"
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


def test_indexed_memory_call_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # An indexed memory-indirect call (call [tbl + rcx*8]) - function-pointer
    # table dispatch. The VM must compute base+index*scale, load the callee from
    # the table, bridge out and capture the return value, reusing the scaled-index
    # address machinery.
    fixture = _DATASET / "elf_vm_idxcall_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_idxcall"
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


def test_flag_synthesis_preserves_branch_decisions(tmp_path: Path) -> None:
    # Every flag-setting op here is flag-live (a branch reads its flags), so the
    # region routes it to the synthesizing handler: the result is computed by MBA
    # and CF/OF/SF/ZF/PF are synthesized by hand instead of captured from a literal
    # op. The branches check the trickiest flags (sub borrow CF, signed overflow
    # OF), so a wrong synthesis diverts to a non-42 exit.
    fixture = _DATASET / "elf_vm_flagsynth_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_flagsynth"
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


def test_compare_flag_synthesis_preserves_branch_decisions(tmp_path: Path) -> None:
    # cmp and test set flags only; the region synthesizes their flags (cmp == a-b,
    # test == a&b, via MBA) instead of running a literal cmp/test + pushfq. The
    # branches check a signed comparison (SF vs OF through jge) and the zero/sign
    # flags of test, so a wrong synthesis diverts to a non-42 exit.
    fixture = _DATASET / "elf_vm_cmpsynth_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_cmpsynth"
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


def test_boolean_flag_synthesis_preserves_branch_decisions(tmp_path: Path) -> None:
    # Flag-live and/xor/or are synthesized too (result via boolean MBA, flags in
    # logic mode with CF=OF=0). The branches check the zero flag of and/xor and the
    # sign flag of or, so a wrong synthesis diverts to a non-42 exit.
    fixture = _DATASET / "elf_vm_boolflaglive_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_boolflaglive"
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


def test_memory_arith_flag_synthesis_preserves_branch_decisions(tmp_path: Path) -> None:
    # Flag-live arithmetic against memory (add/sub reg, [mem]) synthesizes its flags
    # too: the result is the register combined with the loaded memory operand via
    # MBA, and the flags are synthesized (no literal op, no pushfq). The branches
    # check the zero flag of the add and the sign flag of the sub.
    fixture = _DATASET / "elf_vm_memarithsynth_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_memarithsynth"
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


def test_incdec_flag_synthesis_preserves_carry_and_branch(tmp_path: Path) -> None:
    # inc/dec preserve CF and set OF/SF/ZF/PF. The handler synthesizes OF/SF/ZF/PF
    # (result via MBA) and carries CF over unchanged. The branches check dec's zero
    # flag and that inc preserves the carry a prior cmp set, so a wrong synthesis or
    # a clobbered carry diverts to a non-42 exit.
    fixture = _DATASET / "elf_vm_incdecsynth_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_incdecsynth"
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


def test_straight_line_memory_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # This function contains a call (so the control-flow VM rejects it) AND its
    # straight-line run mixes register ops with [rsp+disp] store/load. Exercises
    # the fallback engine's memory-operand coverage: the whole run, memory ops
    # included, must virtualize and still produce the same result.
    fixture = _DATASET / "elf_vm_run_memfallback_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_memrun"
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


def test_straight_line_memarith_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call) whose run uses an
    # arithmetic-with-memory-source op (add reg, [rsp+disp]); the memory-source
    # arithmetic handler must virtualize it and preserve the result.
    fixture = _DATASET / "elf_vm_run_memarithfallback_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_memarith"
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


# sub rsp, 0x210 - the engine VM's frame allocation (grown from 0x110 to hold the
# 16-slot xmm save area). Its presence in the mutated binary proves the engine path
# (not the region's 0x280 frame) virtualized the run.
_ENGINE_FP_ENTRY_SIGNATURE = bytes.fromhex("4881EC10020000")


def test_engine_fp_load_store_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # The function contains a call, so the region rejects it and the engine
    # virtualizes the straight-line run before the call. That run carries a movsd
    # load and store through an xmm register, exercising the engine's xmm save area
    # and scalar-FP memory handlers. The decode check first proves the movsd ops
    # lower to FP items - were they silently left native, the run would still exit
    # 42 (a native movsd works), so the exit code alone would be a false green.
    assert isinstance(_decode_run_item("movsd xmm3, qword ptr [rsp - 8]"), VirtualizedFpMemOp)
    fixture = _DATASET / "elf_vm_fpenginemove_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpengine"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_engine_fp_arithmetic_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run materializes 20.0 and 22.0,
    # loads them into xmm and adds them with a reg-reg addsd, exercising the engine's
    # scalar FP arithmetic handler. The decode check proves addsd lowers to an FP
    # arith item (else, left native, it would still exit 69 - a false green). The
    # exit code is the IEEE high byte of 42.0 (0x45 == 69); sub/mul/div would differ.
    assert isinstance(_decode_run_item("addsd xmm0, xmm1"), VirtualizedFpArithOp)
    fixture = _DATASET / "elf_vm_fpenginearith_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparith"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 69


def test_engine_fp_convert_roundtrip_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run converts int 42 to a double
    # and back (cvtsi2sd / cvttsd2si), exercising the engine's 64-bit int<->float
    # convert handlers. The decode check proves the conversions lower to FP convert
    # items (else left native, the value would still round-trip to 42 - a false
    # green). The 64-bit value round-trips to exit 42.
    assert isinstance(_decode_run_item("cvtsi2sd xmm0, rax"), VirtualizedFpConvertOp)
    assert isinstance(_decode_run_item("cvttsd2si rdi, xmm0"), VirtualizedFpConvertOp)
    fixture = _DATASET / "elf_vm_fpengineconvert_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpconvert"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_engine_fp_convert_32bit_saturation_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Pins GP-width faithfulness: the run truncates 2147483690.0 (= 2^31 + 42, out
    # of int32 range) into edi with a 32-bit cvttsd2si. x86 saturates to 0x80000000,
    # so the exit code (low byte) is 0. A width-blind handler using rax would give
    # 2147483690 (low byte 0x2A = 42), so this discriminates the 32-bit convert path.
    assert isinstance(_decode_run_item("cvttsd2si edi, xmm0"), VirtualizedFpConvertOp)
    fixture = _DATASET / "elf_vm_fpengineconvert32_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpconvert32"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 0


def test_engine_fp_arithmetic_memory_source_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run loads 20.0 into xmm0 and
    # adds 22.0 straight from memory (addsd xmm0, [rsp-16]), exercising the engine's
    # memory-source FP arithmetic handler. The decode check proves addsd-with-memory
    # lowers to an FP arith-mem item (else left native, still exit 69 - a false
    # green). The IEEE high byte of 42.0 is 0x45 == 69; sub/mul/div would differ.
    assert isinstance(_decode_run_item("addsd xmm0, qword ptr [rsp - 16]"), VirtualizedFpArithMemOp)
    fixture = _DATASET / "elf_vm_fpenginearithmem_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithmem"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 69


def test_engine_fp_rip_relative_load_store_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run loads a .rodata double
    # constant via movsd [rip+const], stores it to a .data global via movsd
    # [rip+slot], reloads it, and truncates to an int - exercising the engine's
    # rip-relative FP load/store handlers (the dominant FP memory form). The fixture
    # places .text as the highest-vaddr segment so the large engine blob can be
    # injected past it. The decode check proves the rip movsd lowers to a *rip FP
    # item (else left native, still exit 42 - a false green). Round-trips to exit 42.
    rip_item = _decode_run_item("movsd xmm0, qword ptr [rip + 0x100]", 0x1000, 8)
    assert isinstance(rip_item, VirtualizedFpMemOp) and rip_item.kind.endswith("rip")
    fixture = _DATASET / "elf_vm_fpenginerip_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fprip"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 42


def test_engine_fp_arithmetic_rip_relative_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run loads 20.0 and adds a
    # .rodata double constant straight from the constant pool (addsd xmm0,
    # [rip+c22]) - the compiler's usual float-literal form - exercising the engine's
    # rip-relative FP arithmetic handler. The decode check proves addsd-with-rip
    # lowers to a rip-form FP arith-mem item (base_index < 0); else left native, it
    # would still exit 69 (the IEEE high byte of 42.0). sub/mul/div would differ.
    rip_arith = _decode_run_item("addsd xmm0, qword ptr [rip + 0x40]", 0x500000, 8)
    assert isinstance(rip_arith, VirtualizedFpArithMemOp) and rip_arith.base_index < 0
    fixture = _DATASET / "elf_vm_fpenginearithrip_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithrip"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 69


def test_engine_fp_scaled_index_load_store_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run builds a two-element double
    # array on the stack and accesses it with movsd [rsp+rcx*8-16] (the a[i] form),
    # exercising the engine's scaled-index FP load/store handlers. The decode check
    # proves the indexed movsd lowers to an *idx FP item (else left native, still
    # exit 69 - a false green). The IEEE high byte of 42.0 is 0x45 == 69.
    idx_item = _decode_run_item("movsd xmm0, qword ptr [rsp + rcx*8 - 16]")
    assert isinstance(idx_item, VirtualizedFpMemOp) and idx_item.kind.endswith("idx")
    fixture = _DATASET / "elf_vm_fpengineidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpidx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 69


def test_engine_fp_scaled_index_arithmetic_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run builds a two-element double
    # array on the stack, loads a[0] and adds a[1] straight from the array via
    # addsd xmm0, [rsp+rcx*8-16] (the sum += a[i] form), exercising the engine's
    # scaled-index FP arithmetic handler. The decode check proves the indexed addsd
    # lowers to an indexed FP arith-mem item (index_index >= 0); else left native, it
    # would still exit 69 (the IEEE high byte of 42.0). sub/mul/div would differ.
    idx_arith = _decode_run_item("addsd xmm0, qword ptr [rsp + rcx*8 - 16]")
    assert isinstance(idx_arith, VirtualizedFpArithMemOp) and idx_arith.index_index >= 0
    fixture = _DATASET / "elf_vm_fpenginearithidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithidx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _ENGINE_FP_ENTRY_SIGNATURE in mutated.read_bytes()
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 69


def test_straight_line_lea_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call) whose run uses lea reg, [base+disp];
    # the lea handler must compute the address into the destination (no dereference)
    # and preserve the result.
    fixture = _DATASET / "elf_vm_run_leafallback_x86_64"
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


def test_straight_line_riprel_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call) whose run reads a global via
    # mov reg, [rip+disp]; the rip-relative handler must reach the global from the
    # bytecode base plus the stored offset and preserve the result.
    fixture = _DATASET / "elf_vm_run_riprelfallback_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_riprel"
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


def test_straight_line_riprel_arith_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback whose run uses rip-relative arithmetic (add reg, [rip+g]) and
    # rip-relative lea (lea reg, [rip+g]); both must reach the global from the
    # bytecode base plus the stored offset and preserve the result.
    fixture = _DATASET / "elf_vm_run_riprelarithfallback_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_riprelarith"
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


def test_straight_line_movx_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback whose run uses movzx/movsx of a byte from [rsp+disp]; the
    # byte/word extend handlers must zero-/sign-extend into the destination slot
    # and preserve the result.
    fixture = _DATASET / "elf_vm_run_movxfallback_x86_64"
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


def test_straight_line_indexed_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback whose run uses indexed memory: add reg, [base+index*scale]
    # (array element) and lea reg, [base+index*scale]; the indexed address prologue
    # must compute base + index*scale + disp and preserve the result.
    fixture = _DATASET / "elf_vm_run_idxfallback_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_idx"
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


def test_straight_line_movxidx_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback whose run does movzx reg, byte [base+index] (indexed byte
    # extend from an array); the indexed extend handler must preserve the result.
    fixture = _DATASET / "elf_vm_run_movxidxfallback_x86_64"
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


def test_fp_move_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function moves a value into an xmm register and back via movsd; the VM
    # must spill the xmm context into the frame, virtualize the FP load/store
    # through the xmm save slot, and reload xmm before leaving - preserving the
    # round-tripped byte (exit 42).
    fixture = _DATASET / "elf_vm_fpmove_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fp"
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


def test_fp_arithmetic_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function adds two doubles (20.0 + 22.0 = 42.0) in xmm registers; the VM
    # must virtualize the scalar addsd through the xmm save slots and preserve a
    # distinctive byte of the result's IEEE-754 encoding (0x45 = 69). A wrong
    # arithmetic handler would change that byte.
    fixture = _DATASET / "elf_vm_fparith_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparith"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 69


def test_fp_conversion_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function converts two ints to doubles, adds them, and truncates back to
    # an int (20, 22 -> 20.0, 22.0 -> 42.0 -> 42). The VM must virtualize cvtsi2sd
    # (int->float) and cvttsd2si (float->int), bridging GP and xmm save slots, and
    # preserve the result (exit 42).
    fixture = _DATASET / "elf_vm_fpconvert_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpconvert"
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


def test_fp_compare_branch_virtualization_preserves_decision(tmp_path: Path) -> None:
    # The function compares 3.0 and 2.0 with ucomisd and branches (jbe); 3.0 > 2.0
    # so the branch is not taken and the exit is 42 (a wrong flag capture would take
    # it and exit 99). The VM must run the real compare and route its ZF/PF/CF
    # through the captured-flags slot to the existing branch handler.
    fixture = _DATASET / "elf_vm_fpcmp_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpcmp"
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


def test_fp_register_move_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function copies a double between xmm registers with movaps (full copy)
    # and movsd (scalar reg-reg copy), then adds the copies (21.0 + 21.0 = 42.0)
    # and truncates to an int. The VM must virtualize the xmm-xmm moves through the
    # save slots and preserve the result (exit 42).
    fixture = _DATASET / "elf_vm_fpmov_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpmov"
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


def test_fp_memory_source_arithmetic_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function adds a memory operand to an xmm register (addsd xmm0, [rsp-8]:
    # 20.0 + 22.0 = 42.0) and truncates to an int. The VM must compute the operand
    # address from the captured rsp and run the scalar op against memory (exit 42).
    fixture = _DATASET / "elf_vm_fparithmem_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithmem"
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


def test_fp_riprel_memory_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads an FP constant from .rodata via [rip+disp], stores it to a
    # .data global, loads it back, and truncates to an int. The VM must reach the
    # constant and global via a bytecode-base-relative offset (their absolute
    # addresses change after relocation) and preserve the value (exit 42).
    fixture = _DATASET / "elf_vm_fpriprel_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpriprel"
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


def test_fp_riprel_arithmetic_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads an FP constant from .rodata and adds a second .rodata
    # constant straight from memory (addsd xmm0, [rip+c22]: 20.0 + 22.0 = 42.0),
    # then truncates to an int. The VM must reach the constant via a bytecode-base
    # relative offset and run the scalar op against it (exit 42).
    fixture = _DATASET / "elf_vm_fparithriprel_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithriprel"
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


def test_fp_conversion_32bit_gp_width_saturation_preserved(tmp_path: Path) -> None:
    # Truncating 2147483690.0 (> INT32_MAX) with a 32-bit cvttsd2si saturates to
    # 0x80000000 (exit 0). The VM must honor the 32-bit GP width of the conversion;
    # a 64-bit truncation would give 2147483690 (exit 42). Regression for the
    # convert handler ignoring the GP operand width.
    fixture = _DATASET / "elf_vm_fpconvert32_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpconvert32"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    assert stats["functions_virtualized"] >= 1
    assert _emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 0


def test_fp_indexed_memory_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function reads two elements of a stack double array with movsd
    # xmm, [base+index*8], adds them (20.0 + 22.0 = 42.0) and truncates to an int.
    # The VM must compute base+index*scale+disp for the scalar FP load (exit 42).
    fixture = _DATASET / "elf_vm_fpindexed_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpindexed"
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


def test_fp_indexed_arithmetic_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The accumulation form: load a[0] then add a[1] straight from the array
    # (addsd xmm0, [base+index*8]: 20.0 + 22.0 = 42.0), truncate to an int. The VM
    # must compute base+index*scale+disp for the scalar FP add (exit 42).
    fixture = _DATASET / "elf_vm_fparithidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithidx"
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


def test_fp_packed_simd_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads two 128-bit vectors of doubles with movups (packed load)
    # and adds them lane-wise with addpd ([20,5] + [22,37] = [42,42]), then
    # truncates the low lane. The VM must move whole 128-bit values and run the
    # packed op across all lanes (exit 42).
    fixture = _DATASET / "elf_vm_fppacked_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppacked"
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


def test_fp_packed_memory_source_arith_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # Packed memory-source arithmetic: load a vector then add a second straight from
    # memory (addpd xmm0, [base]: [20,5] + [22,37] = [42,42]), truncate the low
    # lane. The VM must load the 128-bit memory operand and run the packed op across
    # all lanes (exit 42).
    fixture = _DATASET / "elf_vm_fppackedmem_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppackedmem"
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


def test_fp_packed_riprel_move_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads a SIMD constant vector from .rodata via [rip+disp], stores
    # it to a .data global, reloads it, and truncates the low lane. The VM must
    # reach the constant and global via a bytecode-base-relative offset and move the
    # full 128 bits (exit 42).
    fixture = _DATASET / "elf_vm_fppackedrip_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppackedrip"
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


def test_fp_packed_riprel_arith_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads a vector and adds a packed constant vector straight from
    # .rodata (addpd xmm0, [rip+cvec]: [20,5] + [22,37] = [42,42]), then truncates
    # the low lane. The VM must reach the constant via a bytecode-base-relative
    # offset and run the packed op (exit 42).
    fixture = _DATASET / "elf_vm_fppackedariprip_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppackedariprip"
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


def test_fp_packed_indexed_move_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # The function loads two 128-bit halves of a vector array with movups
    # xmm, [base+index*8] and adds them lane-wise ([20,5] + [22,37] = [42,42]),
    # then truncates the low lane. The VM must compute base+index*scale+disp for the
    # packed load (exit 42).
    fixture = _DATASET / "elf_vm_fppackedidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppackedidx"
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


def test_fp_packed_indexed_arith_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # Vectorized accumulation over a vector array: load a 128-bit half then add a
    # second straight from the array (addpd xmm0, [base+index*8]: [20,5] + [22,37] =
    # [42,42]), truncate the low lane. The VM must compute base+index*scale+disp for
    # the packed add (exit 42).
    fixture = _DATASET / "elf_vm_fppackedaridx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppackedaridx"
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


def test_fp_no_base_indexed_load_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # No-base scaled-index FP load: a static binary addresses a global array with
    # index*scale plus an absolute displacement and no base register. The function
    # loads two doubles with movsd xmm, [index*8 + buf] and adds them
    # (20.0 + 22.0 = 42.0). The VM must compute index*scale+disp with no base.
    fixture = _DATASET / "elf_vm_fpidxnb_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fpidxnb"
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


def test_leave_epilogue_virtualization_preserves_frame(tmp_path: Path) -> None:
    # The gcc-style `leave` epilogue (mov rsp,rbp; pop rbp) must restore rsp from
    # the frame pointer and pop the saved rbp off the relocated stack; a snapshot
    # or pop bug changes the returned exit code.
    fixture = _DATASET / "elf_vm_leave_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_leave"
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


def test_mov_rsp_epilogue_virtualization_preserves_frame(tmp_path: Path) -> None:
    # The clang-style explicit `mov rsp, rbp; pop rbp` epilogue must restore the
    # stack pointer from the frame-pointer snapshot tracked by the balance guard.
    fixture = _DATASET / "elf_vm_movtorsp_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_movtorsp"
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


def test_flag_dead_add_is_mba_folded_and_preserves_value(tmp_path: Path) -> None:
    # The add's flags are overwritten by a later cmp, so it is MBA-folded; only
    # its value must survive (exit 42, a wrong sum would exit 99).
    fixture = _DATASET / "elf_vm_addflagdead_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_adddead"
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


def test_flag_dead_boolean_ops_are_mba_folded_and_preserve_value(tmp_path: Path) -> None:
    # Flag-dead xor/and/or are folded with De Morgan / MBA rewrites (no literal
    # boolean op); only their values must survive (exit 42, a wrong result -> 99).
    fixture = _DATASET / "elf_vm_boolflagdead_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_booldead"
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


def test_flag_dead_sub_is_mba_folded_and_preserves_value(tmp_path: Path) -> None:
    # A flag-dead sub is folded as add a,-b via MBA; only its value must survive
    # (50-8=42, a wrong difference would exit 99).
    fixture = _DATASET / "elf_vm_subflagdead_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_subdead"
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


def test_flag_live_add_keeps_flags_for_the_branch(tmp_path: Path) -> None:
    # The add's sign flag is read by jns, so it must NOT be MBA-folded; the
    # branch depends on the real flags (exit 42, a stale-flag bug would exit 99).
    fixture = _DATASET / "elf_vm_addflaglive_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_addlive"
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


def test_frame_prologue_virtualization_preserves_local(tmp_path: Path) -> None:
    # A real prologue/epilogue (push rbp; mov rbp,rsp; sub rsp,N; [rbp-8] local;
    # add rsp,N; pop rbp; ret) must virtualize and return its frame-pointer local
    # through the relocated stack; a frame bug changes the returned exit code.
    fixture = _DATASET / "elf_vm_prologue_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_prologue"
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


def test_balanced_push_pop_virtualization_preserves_saved_registers(tmp_path: Path) -> None:
    # A 3-deep register-save bracket (clobber then restore via pop) plus a 64-bit
    # push/pop round-trip. A naive in-frame stack would corrupt the spilled
    # context; a width bug would drop the high half (42 correct, 99 wrong).
    fixture = _DATASET / "elf_vm_pushpop_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_pushpop"
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


def test_push_immediate_virtualization_preserves_sign_extension(tmp_path: Path) -> None:
    # push imm round-trips a positive and a sign-extended negative immediate; a
    # handler that zero-extended the negative imm would fail the -1 check (42 vs 99).
    fixture = _DATASET / "elf_vm_pushimm_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_pushimm"
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
