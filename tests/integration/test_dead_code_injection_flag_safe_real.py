"""Regression: dead-code injection only overwrites flag-dead NOP padding.

Dead-code injection overwrites NOP padding with filler sequences that can
clobber status flags (e.g. xor reg,reg sets ZF). It must never overwrite
padding lying in a live-flag window between a flag-setter and a flag-consuming
conditional jump, which would flip the branch. These tests pin that at the byte
level on real binaries:

* the flag-live fixture's padding must be left untouched (gate skips it);
* the flag-dead fixture's padding may be rewritten, but nothing outside it may
  change, proving no real instruction is destroyed.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass

_FLAG_LIVE = Path("fixtures/dataset/elf_cff_flaglive_x86_64")
_FLAG_DEAD = Path("fixtures/dataset/elf_cff_flagdead_x86_64")
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
        else:
            if run_start is not None and i - run_start > best_len:
                best_off, best_len = run_start, i - run_start
            run_start = None
    assert best_len >= _MIN_SLED, "fixture must contain a NOP sled"
    return best_off, best_len


def _region_after_injection(fixture: Path, tmp_path: Path, seed: int) -> bytes:
    temp = tmp_path / f"{fixture.name}_{seed}"
    shutil.copy(fixture, temp)
    with Binary(temp, writable=True) as binary:
        binary.analyze()
        DeadCodeInjectionPass(config={"probability": 1.0, "seed": seed}).apply(binary)
        return _function_region(binary)[1]


def test_flag_live_padding_is_never_overwritten(tmp_path: Path) -> None:
    if not _FLAG_LIVE.exists():
        pytest.skip("flag-live fixture not available")
    with Binary(_FLAG_LIVE, writable=False) as binary:
        binary.analyze()
        _, original = _function_region(binary)
    sled_off, sled_len = _find_nop_sled(original)

    for seed in range(0, 25):
        mutated = _region_after_injection(_FLAG_LIVE, tmp_path, seed)
        sled = mutated[sled_off : sled_off + sled_len]
        assert sled == bytes([_NOP]) * sled_len, f"flag-live padding overwritten at seed {seed}: {sled.hex()}"


def test_flag_dead_padding_injection_leaves_real_instructions_intact(tmp_path: Path) -> None:
    if not _FLAG_DEAD.exists():
        pytest.skip("flag-dead fixture not available")
    with Binary(_FLAG_DEAD, writable=False) as binary:
        binary.analyze()
        _, original = _function_region(binary)
    sled_off, sled_len = _find_nop_sled(original)

    inserted = False
    for seed in range(0, 25):
        mutated = _region_after_injection(_FLAG_DEAD, tmp_path, seed)
        assert len(mutated) == len(original), "injection changed the function byte budget"
        assert mutated[:sled_off] == original[:sled_off], f"bytes before padding changed at seed {seed}"
        assert (
            mutated[sled_off + sled_len :] == original[sled_off + sled_len :]
        ), f"bytes after padding changed at seed {seed}"
        if mutated[sled_off : sled_off + sled_len] != original[sled_off : sled_off + sled_len]:
            inserted = True
    assert inserted, "no seed injected dead code into the flag-dead padding; test is vacuous"
