"""
Flag liveness across ``fsave``: a virtualized ``pushfq`` reads the flags slot.

The dead-flag analysis keeps an ``add``/``sub`` op flag-live (writes its flags into
the flags slot) whenever a downstream reader consumes them. ``fsave`` (the virtualized
``pushfq``) copies the flags slot onto the vstack, so it *is* such a reader: an op
whose flags are saved by a following ``pushfq`` must not be dead-eliminated, or the
save would capture a stale slot. This pins that ``fsave`` counts as a flags reader,
independent of anything after it.

Exercised through the pure analysis with real op items built by ``_classify`` - no r2,
no mocks.
"""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_region import _flag_dead_op_indices
from r2morph.mutations.code_virtualization_region_classification import _classify


def _add(dst: str, src: str) -> list[Any]:
    """A real flag-setting register add item (``["op", VirtualizedOp]``)."""
    item = _classify({"type": "add", "opcode": f"add {dst}, {src}"})
    assert item is not None and item[0] == "op"
    return item


def test_add_saved_by_a_following_fsave_is_not_flag_dead() -> None:
    """An add whose flags a later ``pushfq`` saves stays live even with no jcc after."""
    # add(0) sets flags; fsave(1) reads them; add(2) then overwrites them. Only fsave
    # keeps add(0) live - without treating fsave as a reader, add(0) would be dead.
    items = [_add("rbx", "rcx"), ["fsave"], _add("rbx", "rdx"), ["exit", 0x2000]]
    assert 0 not in _flag_dead_op_indices(items)


def test_add_with_no_reader_before_a_killer_is_flag_dead() -> None:
    """Sanity: an add whose flags nothing reads before an overwrite is dead."""
    # add(0) is overwritten by add(1) with no reader in between -> dead.
    items = [_add("rbx", "rcx"), _add("rbx", "rdx"), ["exit", 0x2000]]
    assert 0 in _flag_dead_op_indices(items)
