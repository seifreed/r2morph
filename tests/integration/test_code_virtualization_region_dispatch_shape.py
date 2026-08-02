"""
Regression: the region VM's per-build dispatch shape must not change semantics.

The primary whole-function region VM routes a decoded opcode to its handler with
one of two structurally different mechanisms, chosen per build: a THREADED
offset-table computed goto (the decode inlined at every handler tail, with an
XOR-encrypted jump table) or a SWITCH central dispatcher ending in a
compare/branch (binary-search) ladder with no table. Both must run the same
program - the shape is polymorphism, not a behaviour change - and the SWITCH
build must keep the self-checksum anti-tamper property (a flipped interpreter
byte misdecodes the opcode and the run diverges).

These tests drive the real pass on a real ELF fixture and emulate the produced
binary with Unicorn (no mocks). The emulation harness and region-VM byte
signatures are reused from the sibling code-virtualization suite; importing that
module skips this one too when Unicorn is unavailable. A seed sweep exercises both
shapes, told apart by the threaded computed-goto byte signature the switch build
never emits.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration import test_code_virtualization_real as vm_real

# A whole-function region-path fixture (no call), so the region VM virtualizes it
# and the produced interpreter is a region dispatcher, not the engine fallback.
FIXTURE = vm_real._DATASET / "elf_vm_isa_x86_64"
_EXPECTED_EXIT = 45

# The threaded shape's decode tail: ``movsxd rax, eax`` + ``add rax, r14`` +
# ``jmp rax`` (the offset-table computed goto). The switch shape has no table and
# no computed goto, so this exact byte run appears only in a threaded build - a
# reliable discriminator between the two produced region shapes.
_THREADED_COMPUTED_GOTO = bytes.fromhex("4863C04C01F0FFE0")

# Enough seeds that a fair per-build coin flip yields both shapes with overwhelming
# probability; the sweep stops as soon as it has one build of each.
_SEED_SWEEP = range(64)


def _mutate(fixture: Path, dest: Path, seed: int) -> int:
    """Run the virtualization pass on a copy of ``fixture`` with a fixed seed."""
    shutil.copy(fixture, dest)
    binary = Binary(str(dest), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": seed}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return int(stats["functions_virtualized"])


def _shape_of(binary_bytes: bytes) -> str:
    return "threaded" if _THREADED_COMPUTED_GOTO in binary_bytes else "switch"


def _find_builds(fixture: Path, tmp_path: Path) -> dict[str, Path]:
    """Sweep seeds until one build of each dispatch shape has been produced."""
    builds: dict[str, Path] = {}
    for seed in _SEED_SWEEP:
        dest = tmp_path / f"mutated_{seed}"
        if _mutate(fixture, dest, seed) < 1:
            continue
        builds.setdefault(_shape_of(dest.read_bytes()), dest)
        if len(builds) == 2:
            break
    return builds


def test_region_produces_both_dispatch_shapes(tmp_path: Path) -> None:
    # The dispatch shape is drawn per build, so a seed sweep must yield both the
    # threaded (encrypted jump table) and the switch (binary-search) shape - if only
    # one ever appears the per-build diversity has silently regressed to a fixed shape.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")
    builds = _find_builds(FIXTURE, tmp_path)
    assert set(builds) == {"threaded", "switch"}, f"only produced shapes {set(builds)}"


def test_both_dispatch_shapes_preserve_the_exit_code(tmp_path: Path) -> None:
    # A THREADED build and a SWITCH build of the same fixture must both reproduce the
    # original exit code - the dispatch shape is polymorphism, not a behaviour change.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")
    assert vm_real._emulate_exit_code(FIXTURE) == _EXPECTED_EXIT

    builds = _find_builds(FIXTURE, tmp_path)
    assert set(builds) == {"threaded", "switch"}, f"only produced shapes {set(builds)}"
    assert vm_real._emulate_exit_code(builds["threaded"]) == _EXPECTED_EXIT
    assert vm_real._emulate_exit_code(builds["switch"]) == _EXPECTED_EXIT


def test_switch_build_tampering_diverges_from_the_original(tmp_path: Path) -> None:
    # Anti-tamper on a SWITCH build: the interpreter checksums its own code into
    # every opcode decrypt, so flipping one interpreter byte must change the result -
    # the corrupted checksum misdecodes the opcode and the ladder routes to vm_exit.
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    builds = _find_builds(FIXTURE, tmp_path)
    if "switch" not in builds:
        pytest.skip("no switch-shape build produced in the seed sweep")

    data = bytearray(builds["switch"].read_bytes())
    # The single-layer switch interpreter opens with the constant frame allocation
    # ``sub rsp, 0x300`` (the region vm_entry signature).
    vm_entry = data.find(vm_real._VM_ENTRY_SIGNATURE)
    assert vm_entry != -1, "switch interpreter entry not found"
    assert vm_real._emulate_exit_code(builds["switch"]) == _EXPECTED_EXIT  # faithful build still runs

    # Flip one byte inside the interpreter body (past the frame allocation, in the
    # spill/dispatch region the checksum covers) and re-emulate.
    data[vm_entry + 0x10] ^= 0xFF
    tampered = tmp_path / "tampered_switch"
    tampered.write_bytes(bytes(data))
    try:
        tampered_code = vm_real._emulate_exit_code(tampered)
    except vm_real.UcError:
        tampered_code = None  # a trap is also a divergence from the faithful exit
    assert tampered_code != _EXPECTED_EXIT
