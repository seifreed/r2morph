"""
Regression: code virtualization must preserve program semantics.

These tests run the ACTUAL produced binary, not a model: the pass virtualizes
a register run on a real ELF fixture, and a Unicorn emulation of the resulting
file confirms the exit code is unchanged. No mocks, no monkeypatch - a real
Binary, the real radare2-native injection, and the real generated interpreter.
"""

from __future__ import annotations

import importlib
import shutil
import struct
from pathlib import Path

import pytest

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass, _decode_run_item
from r2morph.mutations.code_virtualization_engine import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedOp,
    VMScheme,
    build_vm_scheme,
    decode_instruction,
    encode_bytecode,
)

# Kept under its established private name: sibling test modules import this module
# and call ``vm_real._emulate_exit_code``.
from tests.integration.elf_emulator import emulate_exit_code as _emulate_exit_code
from tests.utils.assertions import expect

_EXPECTED_DECODE_INSTRUCTION_MOV_EAX_1_WIDTH_32 = 32
_EXPECTED_DECODE_INSTRUCTION_MOV_RAX_1_WIDTH_64 = 64
_EXPECTED_DECODE_INSTRUCTION_SHR_EDI_3_WIDTH_32 = 32
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE32_45 = 45
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_171 = 171
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_22 = 22
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_35 = 35
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_10 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_11 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_12 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_13 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_14 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_15 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_16 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_17 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_18 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_19 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_2 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_20 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_21 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_22 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_23 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_24 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_25 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_26 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_27 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_28 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_29 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_3 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_30 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_31 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_32 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_33 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_34 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_35 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_36 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_37 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_38 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_39 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_4 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_40 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_41 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_42 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_43 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_44 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_45 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_46 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_47 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_48 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_49 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_5 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_50 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_51 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_52 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_53 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_54 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_55 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_56 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_57 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_58 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_59 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_6 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_60 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_61 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_62 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_63 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_64 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_65 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_66 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_67 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_68 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_69 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_7 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_70 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_71 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_72 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_73 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_74 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_75 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_76 = 42
_EXPECTED_EMULATE_EXIT_CODE_FPPACKED_INDEXED_NO_BASE = 6
_EXPECTED_EMULATE_EXIT_CODE_FPARITH_INDEXED_NO_BASE = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_8 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_9 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_45 = 45
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_45_2 = 45
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_45_3 = 45
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_2 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_3 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_4 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_5 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_6 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_7 = 69
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_ENGARITHIMM_42 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_ENGARITH_42 = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_INCALL_45 = 45
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_INDEXCALL_NB = 42
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_MULTIRET_17 = 17
_EXPECTED_EMULATE_EXIT_CODE_FIXTURE_SWITCH_ABS_30 = 30
_EXPECTED_EMULATE_EXIT_CODE_MUTATED_45 = 45
_EXPECTED_EMULATE_EXIT_CODE_MUTATED_45_2 = 45
_EXPECTED_EMULATE_EXIT_CODE_MUTATED_45_3 = 45
_EXPECTED_EMULATE_EXIT_CODE_TMP_PATH_FIRST_45 = 45
_EXPECTED_TAMPERED_CODE_45 = 45
_EXPECTED_TAMPERED_CODE_45_2 = 45


_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
FIXTURE = _DATASET / "elf_vm_arith_x86_64"
FIXTURE32 = _DATASET / "elf_vm_arith32_x86_64"
# Multi-block fixture: exercises the basic-block-bounded run extraction so a
# trampoline can never orphan an instruction reached by another edge.
FIXTURE_MULTIBLOCK = _DATASET / "elf_blockswap_x86_64"
# Self-recursive fixture: the recursive call targets the function's own entry (an
# in-function call), exercising the vcall/vret in-VM call-and-return discipline.
FIXTURE_INCALL = _DATASET / "elf_vm_incall_x86_64"
# Non-PIE absolute jump-table switch: r2 resolves the table (switch_op), the CFG
# closure gathers every case block, and the memory-indirect dispatch lowers to an
# ijmpmemnb that re-enters the VM at the virtualized case via the target map.
FIXTURE_SWITCH_ABS = _DATASET / "elf_switch_abs_x86_64"
# Multi-ret jcc diamond: two independent ret blocks, no shared epilogue - the
# multi-terminator region shape the whole-function lifter already supports.
FIXTURE_MULTIRET = _DATASET / "elf_multiret_jccdiamond_x86_64"
# Absolute function-pointer table call: exercises the no-base indexed indirect-call
# bridge, which must preserve both the target load and the native ABI transition.
FIXTURE_INDEXED_CALL_NO_BASE = _DATASET / "elf_vm_idxcallnb_x86_64"

unicorn = pytest.importorskip("unicorn")
UcError = unicorn.UcError


def _selected_padding(scheme: VMScheme, keys: list[tuple[str, bool, int]]) -> int:
    picker = randomness.Random(scheme.junk_seed)
    return sum(scheme.record_padding[picker.choice(scheme.dup[key])] for key in keys)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(FIXTURE) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_45)


def test_virtualized_in_function_call_preserves_exit_code(tmp_path: Path) -> None:
    # A self-recursive function whose recursive call targets its own entry is an
    # in-function call: the pass lowers it to a vcall (push a resume vIP, re-enter
    # the VM at the entry) and each ret to a return-aware vret, so the whole
    # recursion runs inside the VM. recurse(9) = 9+8+...+0 = 45 must survive - a
    # wrong return discipline would corrupt the accumulation or trap.
    if not FIXTURE_INCALL.exists():
        pytest.skip(f"fixture missing: {FIXTURE_INCALL}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE_INCALL, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(
        _emulate_exit_code(FIXTURE_INCALL)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_INCALL_45
    )


def test_virtualized_absolute_switch_preserves_exit_code(tmp_path: Path) -> None:
    # A non-PIE jump-table switch: r2 resolves the table into a switch_op, so the
    # CFG-closure gather pulls in every case block and the memory-indirect dispatch
    # lowers to an ijmpmemnb whose runtime target (loaded from the preserved rodata
    # table) re-enters the VM at the virtualized case. dispatch(2) = 30 must survive.
    if not FIXTURE_SWITCH_ABS.exists():
        pytest.skip(f"fixture missing: {FIXTURE_SWITCH_ABS}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE_SWITCH_ABS, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        binary.analyze()
        dispatch = next(f for f in binary.get_functions() if "dispatch" in (f.get("name") or ""))
        pass_ = CodeVirtualizationPass(config={"probability": 1.0, "virtualize_dispatch": True})
        result = pass_._virtualize_dispatch_function(binary, dispatch)
        binary.save()
    finally:
        binary.close()

    # The switch function itself must virtualize - otherwise exit-code parity would be
    # trivially satisfied by leaving the binary unchanged.
    expect(result is not None)
    expect(
        _emulate_exit_code(FIXTURE_SWITCH_ABS)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_SWITCH_ABS_30
    )


def test_virtualized_multiret_function_preserves_exit_code(tmp_path: Path) -> None:
    # A function whose jcc diamond ends in two independent rets (no shared epilogue)
    # is a genuine multi-terminator region. The whole-function lifter must virtualize
    # it and preserve classify() = 17.
    if not FIXTURE_MULTIRET.exists():
        pytest.skip(f"fixture missing: {FIXTURE_MULTIRET}")

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE_MULTIRET, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        binary.analyze()
        classify = next(f for f in binary.get_functions() if "classify" in (f.get("name") or ""))
        result = CodeVirtualizationPass(config={"probability": 1.0})._virtualize_function(binary, classify)
        binary.save()
    finally:
        binary.close()

    expect(result is not None)
    expect(
        _emulate_exit_code(FIXTURE_MULTIRET)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_MULTIRET_17
    )


# The interpreter's first instruction is a constant-size frame allocation
# The injected blob is appended at end-of-file; these bounded frame encodings mark
# vm_entry, the start of the checksummed region.
_VM_ENTRY_SIGNATURES = tuple(b"\x48\x81\xec" + size.to_bytes(4, "little") for size in (0x300, 0x320, 0x340, 0x360))


def _find_vm_entry(data: bytes) -> int:
    return next((offset for signature in _VM_ENTRY_SIGNATURES if (offset := data.find(signature)) != -1), -1)


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
    vm_entry = _find_vm_entry(data)
    expect(vm_entry != -1, "interpreter not found in mutated binary")
    expect(_emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_MUTATED_45)

    # Flip one byte inside the interpreter body (past the frame allocation, in
    # the spill/dispatch region the checksum covers) and re-emulate.
    data[vm_entry + 0x10] ^= 0xFF
    tampered = tmp_path / "tampered"
    tampered.write_bytes(bytes(data))
    try:
        tampered_code = _emulate_exit_code(tampered)
    except UcError:
        tampered_code = None  # a trap is also a divergence from exit 45
    expect(tampered_code != _EXPECTED_TAMPERED_CODE_45)


# The timing anti-debug fold's final instruction: xor byte ptr [rsp+SLOT], al
# (opcode 30 = XOR r/m8, r8), folding the timing byte into the checksum slot. The
# The timing probe folds its result into the checksum slot with a store-form
# `xor [rsp+disp32], al` (ModRM 84 = [rsp+disp32], opcode 30). The checksum slot is
# now relocated per build, so the displacement varies; match the store opcode
# prefix, which is unique to the probe: the dispatch's own checksum fold *loads* the
# slot (`xor al, [rsp+SLOT]`, opcode 32) and the prologue *stores* it with mov
# (opcode 88), so `30 84 24` is emitted only by the timing fold.
_TIMING_FOLD_STORE = bytes.fromhex("308424")
_RDTSC_BYTES = bytes.fromhex("0f31")
_RDTSCP_BYTES = bytes.fromhex("0f01f9")


def test_timing_probe_keeps_emulated_exit_code_inert(tmp_path: Path) -> None:
    # The timing fold is always emitted, so a benign (Unicorn) run must keep the
    # exit code: the inter-read TSC delta stays below 2**N, the fold contributes
    # xor 0 to the checksum slot, and the decode is bit-identical to a build
    # without the probe. This is the one real risk the always-on probe carries.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    reference = _emulate_exit_code(FIXTURE)

    mutated = tmp_path / "mutated"
    shutil.copy(FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(_emulate_exit_code(mutated) == reference == _EXPECTED_EMULATE_EXIT_CODE_MUTATED_45_2)


def test_timing_probe_is_emitted_into_the_interpreter(tmp_path: Path) -> None:
    # Presence guard so the parity test cannot pass vacuously: the injected blob
    # must actually carry the timing read (rdtsc or the rdtscp variant) and the
    # checksum-slot fold tail. Without this, a skipped or dropped probe would still
    # leave the exit-code parity green.
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

    data = mutated.read_bytes()
    vm_entry = _find_vm_entry(data)
    expect(vm_entry != -1, "interpreter not found in mutated binary")
    blob = data[vm_entry:]
    expect(_RDTSC_BYTES in blob or _RDTSCP_BYTES in blob, "no timing read emitted")
    expect(not (_TIMING_FOLD_STORE not in blob), "checksum-slot fold tail not emitted")


# Fixtures with at least one register-op run to peel into a nested inner VM. The
# flag-synthesis fixture peels flag-live micro-ops (vbinopsynth) into an inner
# layer, exercising that its flags-slot write survives the layer transfer.
_NESTING_FIXTURES = [
    ("elf_vm_arith_x86_64", 45),
    ("elf_vm_isa_x86_64", None),
    ("elf_jumpchain_x86_64", None),
    ("elf_blockswap_x86_64", None),
    ("elf_vm_flagsynth_x86_64", 42),
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

    expect(not (stats["functions_virtualized"] < 1))
    baseline = _emulate_exit_code(fixture)
    expect(_emulate_exit_code(mutated) == baseline)
    expect(not (expected is not None and baseline != expected))


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

    expect(_blob_size(1) < _blob_size(2) <= _blob_size(3))


def test_default_config_nests_when_a_peelable_run_exists(tmp_path: Path) -> None:
    # Nesting is the default path: with no vm_nesting_depth in the config, a
    # fixture with a peelable register-op run must build the larger multi-layer
    # interpreter (not the single-layer blob) and still preserve the exit code.
    # A fixed seed holds handler duplication constant so the layer count is the
    # only variable; the injected blob is appended, so file size tracks it.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    def _mutated_size(label: str, config: dict[str, object]) -> int:
        mutated = tmp_path / label
        shutil.copy(FIXTURE, mutated)
        binary = Binary(str(mutated), writable=True)
        binary.open()
        try:
            CodeVirtualizationPass(config=config).apply(binary)
            binary.save()
        finally:
            binary.close()
        return len(mutated.read_bytes())

    single = _mutated_size("single_layer", {"probability": 1.0, "vm_nesting_depth": 1, "seed": 1234})
    default = _mutated_size("default_layer", {"probability": 1.0, "seed": 1234})
    expect(not (default <= single))
    expect(_emulate_exit_code(tmp_path / "default_layer") == _emulate_exit_code(FIXTURE))


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
    vm_entry = _find_vm_entry(data)
    expect(vm_entry != -1)
    expect(_emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_MUTATED_45_3)
    data[vm_entry + 0x10] ^= 0xFF
    tampered = tmp_path / "tampered"
    tampered.write_bytes(bytes(data))
    try:
        tampered_code = _emulate_exit_code(tampered)
    except UcError:
        tampered_code = None
    expect(tampered_code != _EXPECTED_TAMPERED_CODE_45_2)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated))


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_45_2)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42)


def _region_lowers_kind(fixture: Path, kind: str) -> bool:
    """True if the fixture's entry function region-lowers an item of ``kind``.

    Guards against a false green: a fixture whose instruction is left native would
    still emulate to the expected exit code, so the exit-code assertion alone does
    not prove the new lowering ran.
    """
    extract_region = importlib.import_module("r2morph.mutations.code_virtualization_region").extract_region

    binary = Binary(str(fixture), writable=False)
    binary.open()
    try:
        binary.analyze("aa")
        expect(binary.r2 is not None)
        ops = (binary.r2.cmdj("pdfj @ entry0") or {}).get("ops", [])
    finally:
        binary.close()
    region = extract_region(ops, randomness.Random(1))
    return region is not None and any(item[0] == kind for item in region.instructions)


def test_setcc_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # `sete al` must lower to a virtual setcc that writes only the low byte (the
    # preserved byte1 0xAA contributes 170; the set result 1) -> exit 171.
    fixture = _DATASET / "elf_vm_setcc_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    expect(_region_lowers_kind(fixture, "setcc"))

    mutated = tmp_path / "mutated_setcc"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_171)


def test_cmov_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # A taken 64-bit cmove (22 over 20) and a taken 32-bit cmovne that must
    # zero-extend the destination -> exit 22 (a not-taken bug 20, a lost
    # zero-extend 99).
    fixture = _DATASET / "elf_vm_cmov_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    expect(_region_lowers_kind(fixture, "cmov"))

    mutated = tmp_path / "mutated_cmov"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_22)


def test_movxreg_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # Register-source movsx/movzx: a byte 0xd8 sign-extends negative and zero-extends
    # to 216, and a word 0x8000 zero-extends to 32768; each branches on the full
    # extended value, so a wrong extension exits 99 instead of 42.
    fixture = _DATASET / "elf_vm_movxreg_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    expect(_region_lowers_kind(fixture, "movxreg"))

    mutated = tmp_path / "mutated_movxreg"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_2)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_45_3)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_3)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_4)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_5)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_6)


def test_no_base_indexed_memory_call_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    """An absolute indexed function-pointer call must use the no-base call bridge."""
    if not FIXTURE_INDEXED_CALL_NO_BASE.exists():
        pytest.skip(f"fixture missing: {FIXTURE_INDEXED_CALL_NO_BASE}")

    mutated = tmp_path / "mutated_idxcallnb"
    shutil.copy(FIXTURE_INDEXED_CALL_NO_BASE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(
        _emulate_exit_code(FIXTURE_INDEXED_CALL_NO_BASE)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_INDEXCALL_NB
    )


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_7)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_8)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_9)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_10)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_11)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_12)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_13)


# The engine VM's bounded frame encodings (the xmm save area plus the micro-op
# virtual operand stack below the red zone). Their presence proves the engine path
# (not the region frame) virtualized the run.
_ENGINE_FRAME_SIGNATURES = tuple(b"\x48\x81\xec" + size.to_bytes(4, "little") for size in (0x290, 0x2B0, 0x2D0, 0x2F0))


def _has_engine_frame_signature(data: bytes) -> bool:
    return any(signature in data for signature in _ENGINE_FRAME_SIGNATURES)


def test_engine_fp_load_store_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # The function contains a call, so the region rejects it and the engine
    # virtualizes the straight-line run before the call. That run carries a movsd
    # load and store through an xmm register, exercising the engine's xmm save area
    # and scalar-FP memory handlers. The decode check first proves the movsd ops
    # lower to FP items - were they silently left native, the run would still exit
    # 42 (a native movsd works), so the exit code alone would be a false green.
    expect(isinstance(_decode_run_item("movsd xmm3, qword ptr [rsp - 8]"), VirtualizedFpMemOp))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_14)


def test_engine_fp_arithmetic_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run materializes 20.0 and 22.0,
    # loads them into xmm and adds them with a reg-reg addsd, exercising the engine's
    # scalar FP arithmetic handler. The decode check proves addsd lowers to an FP
    # arith item (else, left native, it would still exit 69 - a false green). The
    # exit code is the IEEE high byte of 42.0 (0x45 == 69); sub/mul/div would differ.
    expect(isinstance(_decode_run_item("addsd xmm0, xmm1"), VirtualizedFpArithOp))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69)


def test_engine_fp_convert_roundtrip_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run converts int 42 to a double
    # and back (cvtsi2sd / cvttsd2si), exercising the engine's 64-bit int<->float
    # convert handlers. The decode check proves the conversions lower to FP convert
    # items (else left native, the value would still round-trip to 42 - a false
    # green). The 64-bit value round-trips to exit 42.
    expect(isinstance(_decode_run_item("cvtsi2sd xmm0, rax"), VirtualizedFpConvertOp))
    expect(isinstance(_decode_run_item("cvttsd2si rdi, xmm0"), VirtualizedFpConvertOp))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_15)


def test_engine_fp_convert_32bit_saturation_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Pins GP-width faithfulness: the run truncates 2147483690.0 (= 2^31 + 42, out
    # of int32 range) into edi with a 32-bit cvttsd2si. x86 saturates to 0x80000000,
    # so the exit code (low byte) is 0. A width-blind handler using rax would give
    # 2147483690 (low byte 0x2A = 42), so this discriminates the 32-bit convert path.
    expect(isinstance(_decode_run_item("cvttsd2si edi, xmm0"), VirtualizedFpConvertOp))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 0)


def test_engine_fp_arithmetic_memory_source_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run loads 20.0 into xmm0 and
    # adds 22.0 straight from memory (addsd xmm0, [rsp-16]), exercising the engine's
    # memory-source FP arithmetic handler. The decode check proves addsd-with-memory
    # lowers to an FP arith-mem item (else left native, still exit 69 - a false
    # green). The IEEE high byte of 42.0 is 0x45 == 69; sub/mul/div would differ.
    expect(isinstance(_decode_run_item("addsd xmm0, qword ptr [rsp - 16]"), VirtualizedFpArithMemOp))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_2)


def test_engine_fp_rip_relative_load_store_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run loads a .rodata double
    # constant via movsd [rip+const], stores it to a .data global via movsd
    # [rip+slot], reloads it, and truncates to an int - exercising the engine's
    # rip-relative FP load/store handlers (the dominant FP memory form). The fixture
    # places .text as the highest-vaddr segment so the large engine blob can be
    # injected past it. The decode check proves the rip movsd lowers to a *rip FP
    # item (else left native, still exit 42 - a false green). Round-trips to exit 42.
    rip_item = _decode_run_item("movsd xmm0, qword ptr [rip + 0x100]", 0x1000, 8)
    expect(isinstance(rip_item, VirtualizedFpMemOp) and rip_item.kind.endswith("rip"))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_16)


def test_engine_fp_arithmetic_rip_relative_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run loads 20.0 and adds a
    # .rodata double constant straight from the constant pool (addsd xmm0,
    # [rip+c22]) - the compiler's usual float-literal form - exercising the engine's
    # rip-relative FP arithmetic handler. The decode check proves addsd-with-rip
    # lowers to a rip-form FP arith-mem item (base_index < 0); else left native, it
    # would still exit 69 (the IEEE high byte of 42.0). sub/mul/div would differ.
    rip_arith = _decode_run_item("addsd xmm0, qword ptr [rip + 0x40]", 0x500000, 8)
    expect(isinstance(rip_arith, VirtualizedFpArithMemOp) and rip_arith.base_index < 0)
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_3)


def test_engine_fp_scaled_index_load_store_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run builds a two-element double
    # array on the stack and accesses it with movsd [rsp+rcx*8-16] (the a[i] form),
    # exercising the engine's scaled-index FP load/store handlers. The decode check
    # proves the indexed movsd lowers to an *idx FP item (else left native, still
    # exit 69 - a false green). The IEEE high byte of 42.0 is 0x45 == 69.
    idx_item = _decode_run_item("movsd xmm0, qword ptr [rsp + rcx*8 - 16]")
    expect(isinstance(idx_item, VirtualizedFpMemOp) and idx_item.kind.endswith("idx"))
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_4)


def test_engine_fp_scaled_index_arithmetic_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run builds a two-element double
    # array on the stack, loads a[0] and adds a[1] straight from the array via
    # addsd xmm0, [rsp+rcx*8-16] (the sum += a[i] form), exercising the engine's
    # scaled-index FP arithmetic handler. The decode check proves the indexed addsd
    # lowers to an indexed FP arith-mem item (index_index >= 0); else left native, it
    # would still exit 69 (the IEEE high byte of 42.0). sub/mul/div would differ.
    idx_arith = _decode_run_item("addsd xmm0, qword ptr [rsp + rcx*8 - 16]")
    expect(isinstance(idx_arith, VirtualizedFpArithMemOp) and idx_arith.index_index >= 0)
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_5)


def test_engine_fp_packed_simd_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run builds two __m128d vectors
    # on the stack, loads them with movups (fppload), adds all lanes with addpd
    # (fppacked), and stores with movups (fppstore), exercising the engine's packed
    # 128-bit SIMD handlers. It reads out the HIGH lane (5.0 + 37.0 = 42.0): a
    # correct packed add gives 42.0 -> exit 69, while a scalar low-lane-only add
    # would leave 5.0 -> 20, so the exit code discriminates packed from scalar. The
    # decode checks prove addpd/movups lower to packed FP items (not left native).
    expect(isinstance(_decode_run_item("addpd xmm0, xmm1"), VirtualizedFpPackedOp))
    packed_mem = _decode_run_item("movups xmm0, xmmword ptr [rsp - 32]")
    expect(isinstance(packed_mem, VirtualizedFpPackedMemOp) and packed_mem.kind == "fppload")
    fixture = _DATASET / "elf_vm_fpenginepacked_x86_64"
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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_6)


def test_region_fp_packed_no_base_indexed_memory_preserves_exit_code(tmp_path: Path) -> None:
    """Packed vector loads, arithmetic, and stores preserve a no-base address."""
    fixture = _DATASET / "elf_vm_fppackedidxnb_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fppackedidxnb"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1)
    expect(
        _emulate_exit_code(fixture)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FPPACKED_INDEXED_NO_BASE
    )


def test_region_fp_scalar_no_base_indexed_memory_preserves_exit_code(tmp_path: Path) -> None:
    """Scalar FP arithmetic preserves an absolute no-base indexed address."""
    fixture = _DATASET / "elf_vm_fparithidxnb_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_fparithidxnb"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1)
    expect(
        _emulate_exit_code(fixture)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FPARITH_INDEXED_NO_BASE
    )


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_17)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_18)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_19)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_20)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_21)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_22)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_23)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_24)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_69_7)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_25)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_26)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_27)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_28)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_29)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_30)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == 0)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_31)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_32)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_33)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_34)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_35)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_36)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_37)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_38)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_39)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_40)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_41)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_42)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_43)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_44)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_45)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_46)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_47)


def test_indexed_mov_load_lowers_to_a_microop() -> None:
    # A scaled-index `mov reg, [base+idx*scale]` must lower to vloadidx, not stay
    # native (a native load would still emulate to the same exit code).
    fixture = _DATASET / "elf_vm_movidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    expect(_region_lowers_kind(fixture, "vloadidx"))


def test_indexed_mov_store_lowers_to_a_microop() -> None:
    # A scaled-index `mov [base+idx*scale], reg` must lower to vstoreidx.
    fixture = _DATASET / "elf_vm_movidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    expect(_region_lowers_kind(fixture, "vstoreidx"))


def test_no_base_indexed_mov_load_store_lower_to_no_base_microops() -> None:
    fixture = _DATASET / "elf_vm_movidxnb_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    expect(_region_lowers_kind(fixture, "vloadidxnb"))
    expect(_region_lowers_kind(fixture, "vstoreidxnb"))


def test_no_base_indexed_mov_load_store_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    fixture = _DATASET / "elf_vm_movidxnb_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_movidxnb"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_35)


def test_indexed_mov_load_store_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    # A stack int/qword array accessed via scaled-index mov: loadidx a[2]=30 stored
    # back to a[0] (storeidx), plus loadidx b[1]=5 (64-bit) -> exit 35. A wrong
    # index/scale/width or a mis-addressed store would change the exit code.
    fixture = _DATASET / "elf_vm_movidx_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_movidx"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_35)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_48)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_49)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_50)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_51)


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
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_52)


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
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_53)


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
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_54)


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
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_55)


def test_shift_micro_op_captures_the_carry_flag_for_the_branch(tmp_path: Path) -> None:
    # shl by 1 shifts bit 31 out -> CF=1 -> jc taken -> exit 42. The shift lowers to
    # the vshift micro-op (proven structurally in the unit suite); here the exit code
    # discriminates its flag capture: a vshift that dropped or mis-timed the pushfq
    # would let jc fall through to 99.
    fixture = _DATASET / "elf_vm_shiftmicroop_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_shiftmicroop"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_56)


def test_rotate_micro_op_merges_program_flags_with_the_rotate_carry(tmp_path: Path) -> None:
    # rol/ror share the vshift handler but, unlike a shift, leave SF/ZF/AF/PF untouched
    # and only define CF, so the handler must merge the program flags with the rotate's
    # CF rather than overwrite them. The fixture requires both: a ZF set before the rol
    # must survive it (jnz not taken) and the ror's carry must be captured (jnc not
    # taken); either rotate-flag error diverges to 99 instead of 42.
    fixture = _DATASET / "elf_vm_rotate_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_rotate"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_57)


def test_byte_register_compare_and_test_preserve_exit_code(tmp_path: Path) -> None:
    # An 8-bit register test/cmp - the byte terminator of a char loop (`test al,al;jz`)
    # and a byte equality (`cmp dl,bl;jne`). The synthesized 8-bit flags key the sign
    # bit off bit 7 and mask the operands to the low byte; a wrong 8-bit ZF/SF would
    # take a branch the native code does not, diverging from 42. The fixture cannot be
    # virtualized at all on a build without 8-bit compare support (functions_virtualized
    # would be 0), so the count assertion also pins the new coverage.
    fixture = _DATASET / "elf_vm_cmp8_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_cmp8"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_58)


def test_variable_count_shift_preserves_exit_code(tmp_path: Path) -> None:
    # Variable-count (cl) shifts/rotates: shl 1<<4=16, shr 0x80>>7=1, rol 1 by 3 = 8,
    # and a cl=0 shift that must leave the flags unchanged (a ZF set before it survives,
    # so jnz is not taken - the handler merges the program flags for the zero-count
    # case). A wrong value or clobbered zero-count flags diverges from 42.
    fixture = _DATASET / "elf_vm_shiftreg_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_shiftreg"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_59)


def test_bit_test_preserves_exit_code(tmp_path: Path) -> None:
    # bt (bit test) sets CF from the selected bit and leaves ZF unchanged. bit 3 of
    # 0x08 is 1 (register index), bit 5 of 0x08 is 0 (immediate index), and a ZF set
    # before `bt rbx, 8` must survive it (the handler merges CF into the flags slot
    # while keeping the program's ZF). A wrong CF or a clobbered ZF diverges from 42.
    fixture = _DATASET / "elf_vm_bt_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_bt"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_60)


def test_division_preserves_exit_code(tmp_path: Path) -> None:
    # div/idiv/cqo virtualized (modulo hashing, index math). Unsigned 100/7 = 14 rem 2
    # and signed -55/4 via cqo+idiv = -13 (truncating toward zero). The handlers run
    # the real division on the implicit rdx:rax pair, which the per-instance register
    # renamer must leave pinned (renaming rax would divide the wrong value). A wrong
    # quotient, remainder or sign diverges from 42 to 99.
    fixture = _DATASET / "elf_vm_div_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_div"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_61)


def test_byte_swap_preserves_exit_code(tmp_path: Path) -> None:
    # `bswap reg` (byte-order reversal, no flags): 32-bit swap of 0x12345678 is
    # 0x78563412 (zero-extends), 64-bit swap of 0x1122334455667788 is
    # 0x8877665544332211. A wrong width or a missed swap diverges from 42.
    fixture = _DATASET / "elf_vm_bswap_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_bswap"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_62)


def test_bitwise_not_preserves_exit_code(tmp_path: Path) -> None:
    # `not reg` (bitwise complement, no flags): 32-bit zero-extends (0x0F -> low byte
    # 0xF0), 64-bit not of 0 is -1, and 8-bit `not dl` flips only the low byte of
    # edx=0x1200 to 0x12FF (upper bytes preserved). A wrong width diverges from 42.
    fixture = _DATASET / "elf_vm_not_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_not"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_63)


def test_word_compare_and_inc_merge_preserve_exit_code(tmp_path: Path) -> None:
    # 16-bit word ops (WORD / wide-char code): `cmp ax, cx` equality, `inc dx`
    # wrapping 0xFFFF->0 (16-bit ZF synthesis), and `inc bx` on ebx=0x00FF0000 keeping
    # the upper 48 bits (0x00FF0001). A wrong 16-bit flag or a whole-cell write
    # diverges from 42 to 99.
    fixture = _DATASET / "elf_vm_word16_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_word16"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_64)


def test_byte_inc_dec_merge_and_flags_preserve_exit_code(tmp_path: Path) -> None:
    # An 8-bit inc/dec writes only the low byte: `inc al` with eax=0x1200 must yield
    # eax=0x1201 (the handler merges the byte back over the preserved upper bytes; a
    # whole-cell write would drop 0x12__), and `inc dl` wrapping 0xFF->0 must set ZF
    # (8-bit synthesis). Either failure diverges from 42 to 99.
    fixture = _DATASET / "elf_vm_incdec8_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_incdec8"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_65)


def test_byte_immediate_compare_preserves_exit_code(tmp_path: Path) -> None:
    # An 8-bit immediate compare - the byte classify `cmp al, 0x30` of a char routine.
    # It exercises the 1-byte immediate read (advance 3, not the 32-bit field's 6) and
    # the 8-bit ZF/CF synthesis: al=0x41 equals 0x41 (je not taken) and is not below
    # 0x30 (jb not taken), so a wrong 1-byte read or 8-bit carry diverges from 42 to 99.
    fixture = _DATASET / "elf_vm_cmp8imm_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_cmp8imm"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_66)


def test_rip_relative_memory_micro_ops_preserve_exit_code(tmp_path: Path) -> None:
    # A global load/store/subtract/RMW through rip-relative operands, all lowered to
    # the vloadrip/vstorerip micro-ops (proven structurally in the unit suite). The
    # opriprel subtract has no borrow (50 - 8), so a wrongly synthesized borrow flag
    # would take `jc fail` to 99; the RMW and store are read back, so a lost write
    # would also diverge. Correct execution nets 42.
    fixture = _DATASET / "elf_vm_riprelmicroop_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    mutated = tmp_path / "mutated_riprelmicroop"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_67)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_68)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_69)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_70)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_71)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_72)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_73)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_74)


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_75)


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
    expect(not (b"\xb8\x01\x00\x00\x00" not in original_body))

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
    expect(mutated_body != original_body)
    expect(b"\xb8\x01\x00\x00\x00" not in mutated_body)
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated))


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
    expect(not (stats["functions_virtualized"] < 1))
    return dst.read_bytes()[original_size:]


def test_virtualization_is_polymorphic_yet_semantically_stable(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    first_region = _virtualize(FIXTURE, tmp_path / "first")
    second_region = _virtualize(FIXTURE, tmp_path / "second")

    # Two builds of the same input share no static VM signature (randomized
    # opcodes + encrypted bytecode) yet both preserve the exit code.
    expect(first_region and second_region)
    expect(first_region != second_region)
    expect(
        _emulate_exit_code(tmp_path / "first")
        == _emulate_exit_code(tmp_path / "second")
        == _EXPECTED_EMULATE_EXIT_CODE_TMP_PATH_FIRST_45
    )


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

    expect(not (stats["functions_virtualized"] < 1))
    expect(_emulate_exit_code(FIXTURE32) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE32_45)


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

    expect(_emulate_exit_code(FIXTURE_MULTIBLOCK) == _emulate_exit_code(mutated))


def test_decode_instruction_widths_and_rejections() -> None:
    expect(decode_instruction("mov eax, 1").width == _EXPECTED_DECODE_INSTRUCTION_MOV_EAX_1_WIDTH_32)
    expect(decode_instruction("mov rax, 1").width == _EXPECTED_DECODE_INSTRUCTION_MOV_RAX_1_WIDTH_64)
    expect(not (decode_instruction("add eax, rbx") is not None))
    expect(not (decode_instruction("mov rsp, rax") is not None))
    expect(not (decode_instruction("mov esp, eax") is not None))
    expect(not (decode_instruction("mov rax, qword ptr [rbx]") is not None))
    expect(not (decode_instruction("jmp 0x400000") is not None))
    expect(decode_instruction("add rbx, rcx") is not None)
    expect(decode_instruction("shl rax, 4") is not None)
    expect(decode_instruction("shr edi, 3").width == _EXPECTED_DECODE_INSTRUCTION_SHR_EDI_3_WIDTH_32)
    expect(not (decode_instruction("shl rax, cl") is not None))
    expect(not (decode_instruction("shl rax") is not None))


def test_engine_shift_run_fallback_preserves_exit_code(tmp_path: Path) -> None:
    # Engine fallback (the function has a call): the run uses immediate-count
    # shifts (shl/sar/shr, 64-bit, plus a 32-bit shl) netting exit 42 in rdi,
    # exercising the engine's shift handlers. The decode checks prove the shifts
    # lower to VM ops - were they left native, the run would still exit 42 (a false
    # green), so the isinstance guards rule that out.
    expect(isinstance(decode_instruction("shl rdi, 3"), VirtualizedOp))
    expect(isinstance(decode_instruction("sar rdi, 1"), VirtualizedOp))
    expect(isinstance(decode_instruction("shr rsi, 2"), VirtualizedOp))
    fixture = _DATASET / "elf_vm_shift_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_shift"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(_emulate_exit_code(fixture) == _emulate_exit_code(mutated) == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_42_76)


FIXTURE_ENGARITH = _DATASET / "elf_vm_engarith_x86_64"


def test_reg_reg_arithmetic_lowers_to_shared_microop_primitives() -> None:
    # Structural proof the 1:1 handler<->native map is broken: a reg-reg arithmetic
    # op no longer encodes as one item but as a push/push/binop/pop micro-op
    # sequence, and distinct native ops (add vs xor) expand identically through the
    # SHARED vpush/vpop primitive opcodes - so identifying a handler no longer
    # identifies a native instruction.
    scheme = build_vm_scheme(randomness.Random(20260801))
    # The shared stack primitives and the per-op folds are real handler keys.
    expect(not (("vpush", False, 64) not in scheme.dup))
    expect(not (("vpop", False, 64) not in scheme.dup))
    expect(("vadd", False, 64) in scheme.dup and ("vxor", False, 64) in scheme.dup)

    add_len = len(encode_bytecode([VirtualizedOp("add", 7, 6, False, 64)], scheme))
    xor_len = len(encode_bytecode([VirtualizedOp("xor", 7, 6, False, 64)], scheme))
    mov_len = len(encode_bytecode([VirtualizedOp("mov", 7, 6, False, 64)], scheme))
    # add and xor expand to the same 4-item shape (vpush+vpush+vbinop+vpop),
    # strictly longer than the single-item mov. Per-instance encrypted padding
    # changes raw lengths, so compare after removing only the measured padding.
    add_padding = _selected_padding(
        scheme,
        [("vpush", False, 64), ("vpush", False, 64), ("vadd", False, 64), ("vpop", False, 64)],
    )
    xor_padding = _selected_padding(
        scheme,
        [("vpush", False, 64), ("vpush", False, 64), ("vxor", False, 64), ("vpop", False, 64)],
    )
    mov_padding = _selected_padding(scheme, [("mov", False, 64)])
    expect(add_len - add_padding == xor_len - xor_padding > mov_len - mov_padding)


def test_engine_reg_reg_arithmetic_microops_preserve_exit_code(tmp_path: Path) -> None:
    # Semantic parity: an engine-path run of reg-reg add/sub/xor/and/or (a call
    # forces the engine over the region VM) nets exit 42 after micro-op lowering. A
    # wrong lowering - especially the order-sensitive sub - would change the code.
    if not FIXTURE_ENGARITH.exists():
        pytest.skip(f"fixture missing: {FIXTURE_ENGARITH}")

    mutated = tmp_path / "mutated_engarith"
    shutil.copy(FIXTURE_ENGARITH, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(
        _emulate_exit_code(FIXTURE_ENGARITH)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_ENGARITH_42
    )


FIXTURE_ENGARITHIMM = _DATASET / "elf_vm_engarithimm_x86_64"


def test_immediate_arithmetic_lowers_to_shared_microop_primitives() -> None:
    # Structural proof the immediate form also breaks the 1:1 map: an immediate
    # arithmetic op encodes as vpush_slot/vpush_imm/vbinop/vpop, sharing the
    # vpush/vpop stack primitives with the reg-reg form, not a single handler.
    scheme = build_vm_scheme(randomness.Random(20260802))
    expect(not (("vpushi", False, 64) not in scheme.dup))
    # Shared with the reg-reg lowering (same stack primitive opcodes).
    expect(("vpush", False, 64) in scheme.dup and ("vpop", False, 64) in scheme.dup)

    add_len = len(encode_bytecode([VirtualizedOp("add", 7, 5, True, 64)], scheme))
    xor_len = len(encode_bytecode([VirtualizedOp("xor", 7, 5, True, 64)], scheme))
    mov_len = len(encode_bytecode([VirtualizedOp("mov", 7, 5, True, 64)], scheme))
    # Immediate add and xor expand to the same multi-item shape, strictly longer
    # than the single-item immediate mov, after removing measured padding. A build
    # may use the new two-fold decomposition, so account for that selected grammar.
    add_keys = [("vpush", False, 64), ("vpushi", False, 64), ("vadd", False, 64)]
    xor_keys = [("vpush", False, 64), ("vpushi", False, 64), ("vxor", False, 64)]
    if scheme.immediate_split:
        add_keys.extend([("vpushi", False, 64), ("vadd", False, 64)])
        xor_keys.extend([("vpushi", False, 64), ("vxor", False, 64)])
    add_keys.append(("vpop", False, 64))
    xor_keys.append(("vpop", False, 64))
    add_padding = _selected_padding(scheme, add_keys)
    xor_padding = _selected_padding(scheme, xor_keys)
    mov_padding = _selected_padding(scheme, [("mov", True, 64)])
    expect(add_len - add_padding == xor_len - xor_padding > mov_len - mov_padding)


def test_immediate_arithmetic_decomposition_varies_by_build() -> None:
    schemes = [build_vm_scheme(randomness.Random(seed)) for seed in range(1, 128)]
    unsplit = next(scheme for scheme in schemes if not scheme.immediate_split)
    split = next(scheme for scheme in schemes if scheme.immediate_split)
    operation = VirtualizedOp("add", 7, 5, True, 64)

    unsplit_size = len(encode_bytecode([operation], unsplit)) - _selected_padding(
        unsplit,
        [("vpush", False, 64), ("vpushi", False, 64), ("vadd", False, 64), ("vpop", False, 64)],
    )
    split_size = len(encode_bytecode([operation], split)) - _selected_padding(
        split,
        [
            ("vpush", False, 64),
            ("vpushi", False, 64),
            ("vadd", False, 64),
            ("vpushi", False, 64),
            ("vadd", False, 64),
            ("vpop", False, 64),
        ],
    )

    expect(not (split_size <= unsplit_size))


def test_immediate_logical_decomposition_varies_by_build() -> None:
    schemes = [build_vm_scheme(randomness.Random(seed)) for seed in range(1, 128)]
    unsplit = next(scheme for scheme in schemes if not scheme.immediate_split)
    split = next(scheme for scheme in schemes if scheme.immediate_split)
    operations = (VirtualizedOp("and", 7, 5, True, 64), VirtualizedOp("or", 7, 5, True, 64))

    unsplit_sizes = tuple(
        len(encode_bytecode([operation], unsplit))
        - _selected_padding(
            unsplit,
            [
                ("vpush", False, 64),
                ("vpushi", False, 64),
                ("v" + operation.mnemonic, False, 64),
                ("vpop", False, 64),
            ],
        )
        for operation in operations
    )
    split_sizes = tuple(
        len(encode_bytecode([operation], split))
        - _selected_padding(
            split,
            [
                ("vpush", False, 64),
                ("vpushi", False, 64),
                ("v" + operation.mnemonic, False, 64),
                ("vpushi", False, 64),
                ("v" + operation.mnemonic, False, 64),
                ("vpop", False, 64),
            ],
        )
        for operation in operations
    )

    expect(all(split_size > unsplit_size for split_size, unsplit_size in zip(split_sizes, unsplit_sizes, strict=True)))


def test_engine_immediate_arithmetic_microops_preserve_exit_code(tmp_path: Path) -> None:
    # Semantic parity: an engine-path run of immediate add/sub/xor/and/or (a call
    # forces the engine over the region VM) nets exit 42 after micro-op lowering,
    # including the order-sensitive immediate sub.
    if not FIXTURE_ENGARITHIMM.exists():
        pytest.skip(f"fixture missing: {FIXTURE_ENGARITHIMM}")

    mutated = tmp_path / "mutated_engarithimm"
    shutil.copy(FIXTURE_ENGARITHIMM, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    expect(_has_engine_frame_signature(mutated.read_bytes()))
    expect(
        _emulate_exit_code(FIXTURE_ENGARITHIMM)
        == _emulate_exit_code(mutated)
        == _EXPECTED_EMULATE_EXIT_CODE_FIXTURE_ENGARITHIMM_42
    )


def test_region_conditional_branch_preserves_exit_code(tmp_path: Path) -> None:
    # A flag-live control-flow fixture: the region VM keeps the conditional branch
    # inside the bytecode, deciding taken/not-taken arithmetically from the captured
    # flags with no native jcc (see the unit test for the structural proof). Exercise
    # both branch outcomes end to end - the exit code must be preserved.
    fixture = _DATASET / "elf_cff_flaglive_x86_64"
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")

    mutated = tmp_path / "mutated_cff"
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(not (stats["functions_virtualized"] < 1))
    baseline = _emulate_exit_code(fixture)
    expect(baseline is not None)
    expect(_emulate_exit_code(mutated) == baseline)
