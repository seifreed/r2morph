"""
Regression: nested virtualization of an in-function call must survive every VM layout.

The nested split peels a register-op run out of the outer bytecode stream. A
``vcall`` names its callee by item index exactly like a ``jmp`` does, so a run
that swallowed a vcall target left the call transferring to the wrong item: the
self-recursive fixture then ran its body once instead of recursing and exited 0
instead of 45. The layout is drawn from the global random state, so seeding it
reproduces the offending builds deterministically; these seeds all produced the
broken binary before the peel excluded vcall targets.

No mocks: a real Binary, the real injection, and a Unicorn run of the file.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

# Self-recursive fixture: recurse(9) sums 9+8+...+0 = 45.
FIXTURE_INCALL = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_incall_x86_64"
EXPECTED_EXIT_CODE = 45
# Layout seeds that produced a vcall into the middle of a peeled run.
BROKEN_LAYOUT_SEEDS = (20, 37, 52, 74)

pytest.importorskip("unicorn")


@pytest.fixture
def preserved_global_random_state() -> Iterator[None]:
    # The pass derives its rng from the global random state, so a test that seeds it
    # must hand the stream back untouched instead of stealing entropy from its
    # neighbours.
    state = randomness.getstate()
    try:
        yield
    finally:
        randomness.setstate(state)


def _virtualize(seed: int, destination: Path) -> tuple[int, int | None]:
    """Build the fixture under ``seed`` and return (functions virtualized, exit code)."""
    if not FIXTURE_INCALL.exists():
        pytest.skip(f"fixture missing: {FIXTURE_INCALL}")
    randomness.seed(seed)
    shutil.copy(FIXTURE_INCALL, destination)
    binary = Binary(str(destination), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return stats["functions_virtualized"], emulate_exit_code(destination)


@pytest.mark.parametrize("seed", BROKEN_LAYOUT_SEEDS)
def test_virtualized_incall_fixture_under_broken_layout_seed_preserves_exit_code(
    seed: int, tmp_path: Path, preserved_global_random_state: None
) -> None:
    expect(_virtualize(seed, tmp_path / "mutated")[1] == EXPECTED_EXIT_CODE)


@pytest.mark.parametrize("seed", BROKEN_LAYOUT_SEEDS)
def test_virtualized_incall_fixture_under_broken_layout_seed_still_virtualizes(
    seed: int, tmp_path: Path, preserved_global_random_state: None
) -> None:
    # Without this the exit-code assertion above would also pass on a build that
    # quietly virtualized nothing.
    expect(not (_virtualize(seed, tmp_path / "mutated")[0] < 1))
