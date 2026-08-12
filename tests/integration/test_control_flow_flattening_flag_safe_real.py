"""Regression: control-flow flattening only overwrites flag-dead NOP sleds.

The dead-code sequences CFF inserts clobber status flags (e.g. ``xor reg,reg``
sets ZF). The pass must therefore never overwrite a NOP sled that lies in a
live-flag window between a flag-setter and a flag-consuming conditional jump —
doing so flips the branch. These tests pin that contract at the byte level:

* the flag-live fixture's sled must be left untouched (gate skips it);
* the flag-dead fixture's sled may be rewritten, but nothing outside it may
  change, proving no real instruction is destroyed.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass

_FLAG_LIVE = Path("dataset/elf_cff_flaglive_x86_64")
_FLAG_DEAD = Path("dataset/elf_cff_flagdead_x86_64")
_NOP = 0x90
_MIN_SLED = 5


def _function_region(binary: Binary) -> tuple[int, bytes]:
    func = binary.get_functions()[0]
    start = func["addr"]
    blocks = binary.get_basic_blocks(start)
    end = max(b["addr"] + b["size"] for b in blocks)
    return start, binary.read_bytes(start, end - start)


def _find_nop_sled(data: bytes) -> tuple[int, int]:
    best_off, best_len = -1, 0
    run_start = None
    for i, byte in enumerate(data + b"\x00"):
        if byte == _NOP:
            run_start = i if run_start is None else run_start
        elif run_start is not None:
            run_len = i - run_start
            if run_len > best_len:
                best_off, best_len = run_start, run_len
            run_start = None
    assert best_len >= _MIN_SLED, "fixture must contain a NOP sled"
    return best_off, best_len


def _region_after_cff(fixture: Path, tmp_path: Path, seed: int) -> tuple[int, bytes]:
    temp = tmp_path / f"{fixture.name}_{seed}"
    shutil.copy(fixture, temp)
    with Binary(temp, writable=True) as binary:
        binary.analyze()
        pass_obj = ControlFlowFlatteningPass(
            config={
                "probability": 1.0,
                "seed": seed,
                "min_blocks_required": 3,
                "max_functions_to_flatten": 5,
                "opaque_density": 4,
            }
        )
        pass_obj.apply(binary)
        return _function_region(binary)


def test_flag_live_nop_sled_is_never_overwritten(tmp_path: Path) -> None:
    if not _FLAG_LIVE.exists():
        pytest.skip("CFF flag-live fixture not available")
    with Binary(_FLAG_LIVE, writable=False) as binary:
        binary.analyze()
        _, original = _function_region(binary)
    sled_off, sled_len = _find_nop_sled(original)

    for seed in range(0, 25):
        _, mutated = _region_after_cff(_FLAG_LIVE, tmp_path, seed)
        sled = mutated[sled_off : sled_off + sled_len]
        assert sled == bytes([_NOP]) * sled_len, f"flag-live sled overwritten at seed {seed}: {sled.hex()}"


def test_flag_dead_nop_sled_insertion_leaves_real_instructions_intact(tmp_path: Path) -> None:
    if not _FLAG_DEAD.exists():
        pytest.skip("CFF flag-dead fixture not available")
    with Binary(_FLAG_DEAD, writable=False) as binary:
        binary.analyze()
        _, original = _function_region(binary)
    sled_off, sled_len = _find_nop_sled(original)

    inserted = False
    for seed in range(0, 25):
        _, mutated = _region_after_cff(_FLAG_DEAD, tmp_path, seed)
        assert len(mutated) == len(original), "CFF changed the function byte budget"
        assert mutated[:sled_off] == original[:sled_off], f"bytes before sled changed at seed {seed}"
        assert (
            mutated[sled_off + sled_len :] == original[sled_off + sled_len :]
        ), f"bytes after sled changed at seed {seed}"
        if mutated[sled_off : sled_off + sled_len] != original[sled_off : sled_off + sled_len]:
            inserted = True
    assert inserted, "no seed inserted dead code into the flag-dead sled; test is vacuous"
