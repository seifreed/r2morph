"""Regression tests for the integrity-dependent direct-threaded bootstrap."""

from __future__ import annotations

import re

from r2morph.mutations.code_virtualization_bootstrap import (
    BOOTSTRAP_STAGE_COUNT,
    BOOTSTRAP_TABLE_SIZE,
    build_bootstrap_asm,
    encrypt_bootstrap_table,
    table_entry_key,
    table_key_mix,
)
from tests.utils.assertions import expect

_CHECKSUM_OFFSET = 0x88


def _bootstrap(seed: int = 7) -> tuple[str, str]:
    return build_bootstrap_asm(_CHECKSUM_OFFSET, seed, "  hlt\n")


def test_bootstrap_entry_jumps_indirectly_before_antidebug_probe() -> None:
    code, _table = _bootstrap()
    first_jump = min(position for marker in ("jmp rax", "push rax") if (position := code.find(marker)) >= 0)

    expect(not (first_jump >= code.index("syscall")))


def test_bootstrap_table_maps_every_state() -> None:
    _code, table = _bootstrap()

    expect(table.count(".long bootstrap_") == BOOTSTRAP_STAGE_COUNT)


def test_bootstrap_state_edges_have_no_direct_targets() -> None:
    code, _table = _bootstrap()

    expect(not (re.search(r"\bj(?:mp|e) bootstrap_", code) is not None))


def test_bootstrap_state_mapping_varies_by_seed() -> None:
    tables = {_bootstrap(seed)[1] for seed in range(16)}

    expect(not (len(tables) <= 1))


def test_encrypt_bootstrap_table_mixes_checksum_by_entry_index() -> None:
    original = bytes(range(BOOTSTRAP_TABLE_SIZE))
    encrypted = bytearray(original)
    checksum = 0x5A
    mix = table_key_mix(7)

    encrypt_bootstrap_table(encrypted, 0, checksum, mix)

    expected = b"".join(
        (int.from_bytes(original[offset : offset + 4], "little") ^ table_entry_key(checksum, index, mix)).to_bytes(
            4, "little"
        )
        for index, offset in enumerate(range(0, BOOTSTRAP_TABLE_SIZE, 4))
    )
    expect(bytes(encrypted) == expected)
