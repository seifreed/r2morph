"""
Regression: every region-VM build ships the threaded, encrypted-table dispatch.

The primary whole-function region VM routes a decoded opcode to its handler
through an XOR-encrypted offset table with the decode inlined at every handler
tail. A second shape - one central dispatcher ending in a compare/branch
(binary-search) ladder - used to be drawn per build and was removed: a decompiler
rebuilds the ladder into a plain ``switch`` and recovers the whole
opcode-to-handler mapping, whereas the encrypted table cannot be resolved
statically. A protector must not ship a reconstructible variant at any rate, so
the floor is that *no* build emits the ladder.

These tests drive the real pass on a real ELF fixture and emulate the produced
binary with Unicorn (no mocks). The emulation harness and region-VM byte
signatures are reused from the sibling code-virtualization suite; importing that
module skips this one too when Unicorn is unavailable.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration import test_code_virtualization_real as vm_real
from tests.utils.assertions import expect

# A whole-function region-path fixture (no call), so the region VM virtualizes it
# and the produced interpreter is a region dispatcher, not the engine fallback.
FIXTURE = vm_real._DATASET / "elf_vm_isa_x86_64"
_EXPECTED_EXIT = 45

# The threaded shape's decode tail: ``movsxd rax, eax`` + ``add rax, r14`` +
# ``jmp rax`` (the offset-table computed goto). Only a threaded build emits it.
_THREADED_COMPUTED_GOTO = bytes.fromhex("4863C04C01F0FFE0")

# Enough seeds that a surviving per-build shape draw would show up with high
# probability (a fair coin flip would miss all eight at ~1 in 256); the asm-level
# unit sweep covers more seeds cheaply.
_SEED_SWEEP = range(8)


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


@pytest.fixture(scope="module")
def seed_sweep_builds(tmp_path_factory: pytest.TempPathFactory) -> list[Path]:
    """Virtualize the fixture once per seed; shared by both assertions below."""
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")
    tmp_path = tmp_path_factory.mktemp("region_dispatch_shape")
    produced: list[Path] = []
    for seed in _SEED_SWEEP:
        dest = tmp_path / f"mutated_{seed}"
        if _mutate(FIXTURE, dest, seed) < 1:
            continue
        produced.append(dest)
    expect(produced, "no seed produced a virtualized build")
    return produced


def test_every_region_build_dispatches_through_the_encrypted_table(seed_sweep_builds: list[Path]) -> None:
    # No build may fall back to the removed compare/branch ladder: every one must
    # carry the offset-table computed goto, the shape a decompiler cannot resolve.
    missing = [b.name for b in seed_sweep_builds if _THREADED_COMPUTED_GOTO not in b.read_bytes()]
    expect(not (missing), f"builds without the threaded computed goto: {missing}")


def test_every_region_build_preserves_the_exit_code(seed_sweep_builds: list[Path]) -> None:
    # The single remaining dispatch shape must run the program faithfully for every
    # seed - the per-build randomization is polymorphism, not a behaviour change.
    expect(vm_real._emulate_exit_code(FIXTURE) == _EXPECTED_EXIT)
    diverged = [b.name for b in seed_sweep_builds if vm_real._emulate_exit_code(b) != _EXPECTED_EXIT]
    expect(not (diverged), f"builds that changed the exit code: {diverged}")
