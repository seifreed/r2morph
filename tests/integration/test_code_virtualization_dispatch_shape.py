"""
Regression: every syscall-bearing region build ships the threaded dispatch.

The region interpreter routes decoded opcodes through its per-build encrypted
table. The syscall fixture is deliberately a whole-function region now, so this
regression also prevents it from silently falling back to the engine VM.

These tests drive the real pass on a real ELF fixture and emulate the produced
binary with Unicorn (no mocks). The emulation harness and engine-VM byte
signature are reused from the sibling code-virtualization suite; importing that
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

# A returning syscall fixture: the syscall is executed inside a whole-function
# region and must resume at the following memory operation.
FIXTURE = vm_real._DATASET / "elf_vm_syscall_x86_64"

# The threaded shape's decode tail: ``movsxd rax, eax`` + ``add rax, r14`` and
# either equivalent indirect transfer. Only a threaded build emits these bytes.
_THREADED_COMPUTED_GOTOS = (bytes.fromhex("4863C04C01F0FFE0"), bytes.fromhex("4863C04C01F050C3"))
_REGION_FRAME_SIGNATURES = tuple(b"\x48\x81\xec" + size.to_bytes(4, "little") for size in (0x400, 0x420, 0x440, 0x460))

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
    tmp_path = tmp_path_factory.mktemp("engine_dispatch_shape")
    produced: list[Path] = []
    for seed in _SEED_SWEEP:
        dest = tmp_path / f"mutated_{seed}"
        if _mutate(FIXTURE, dest, seed) < 1:
            continue
        data = dest.read_bytes()
        expect(any(signature in data for signature in _REGION_FRAME_SIGNATURES), "expected the region VM path")
        expect(not vm_real._has_engine_frame_signature(data), "unexpected engine VM fallback")
        produced.append(dest)
    expect(produced, "no seed produced a virtualized build")
    return produced


def test_every_region_build_avoids_engine_fallback(seed_sweep_builds: list[Path]) -> None:
    # Every seed must keep the returning syscall in the whole-function region.
    missing = [
        b.name
        for b in seed_sweep_builds
        if not any(signature in b.read_bytes() for signature in _REGION_FRAME_SIGNATURES)
        or vm_real._has_engine_frame_signature(b.read_bytes())
        or not any(signature in b.read_bytes() for signature in _THREADED_COMPUTED_GOTOS)
    ]
    expect(not (missing), f"builds without the region frame: {missing}")


def test_every_region_build_preserves_the_exit_code(seed_sweep_builds: list[Path]) -> None:
    # Per-build region randomization must not change the syscall result.
    baseline = vm_real._emulate_exit_code(FIXTURE)
    expect(baseline is not None)
    diverged = [b.name for b in seed_sweep_builds if vm_real._emulate_exit_code(b) != baseline]
    expect(not (diverged), f"builds that changed the exit code: {diverged}")
