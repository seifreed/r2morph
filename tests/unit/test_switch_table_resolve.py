"""Characterization of SwitchTableAnalyzer.resolve_jump_table.

Drives resolution against an in-memory Binary double (no mock -- CLAUDE.md
sec.4) so the entry-reading loop can be extracted without changing observable
output: the entries, their case values, the table type classification, and the
no-address short circuit.
"""

import struct

from r2morph.analysis.switch_table import IndirectJump, JumpTableType, SwitchTableAnalyzer

from tests._doubles.in_memory_jump_table_binary import InMemoryJumpTableBinary

_TABLE_ADDRESS = 0x405000
_TARGETS = [0x401000, 0x401100, 0x401200]


def _blob(targets: list[int]) -> bytes:
    return b"".join(struct.pack("<Q", target) for target in targets)


def _jump(**overrides: object) -> IndirectJump:
    fields: dict = {
        "address": 0x400500,
        "instruction": "jmp [rax*8+0x405000]",
        "jump_type": "jumptable",
        "index_register": "rax",
        "scale": 8,
        "displacement": _TABLE_ADDRESS,
        "table_address": _TABLE_ADDRESS,
        "function_address": 0x400000,
    }
    fields.update(overrides)
    return IndirectJump(**fields)


def test_resolve_jump_table_reads_entries() -> None:
    binary = InMemoryJumpTableBinary(bits=64, table_address=_TABLE_ADDRESS, blob=_blob(_TARGETS))
    analyzer = SwitchTableAnalyzer(binary)

    table = analyzer.resolve_jump_table(_jump())

    assert table is not None
    assert table.table_address == _TABLE_ADDRESS
    assert table.table_type == JumpTableType.DIRECT
    assert [entry.target_address for entry in table.entries] == _TARGETS
    assert [entry.case_value for entry in table.entries] == [0, 1, 2]
    assert [entry.index for entry in table.entries] == [0, 1, 2]


def test_resolve_jump_table_stops_on_duplicate_target() -> None:
    binary = InMemoryJumpTableBinary(
        bits=64,
        table_address=_TABLE_ADDRESS,
        blob=_blob([0x401000, 0x401000, 0x401200]),
    )
    analyzer = SwitchTableAnalyzer(binary)

    table = analyzer.resolve_jump_table(_jump())

    # The loop breaks at the repeated target, so only the first entry survives.
    assert table is not None
    assert [entry.target_address for entry in table.entries] == [0x401000]


def test_resolve_jump_table_classifies_type() -> None:
    binary = InMemoryJumpTableBinary(bits=64, table_address=_TABLE_ADDRESS, blob=_blob(_TARGETS))
    analyzer = SwitchTableAnalyzer(binary)

    # base + index registers -> INDIRECT
    indirect = analyzer.resolve_jump_table(_jump(base_register="rbx", index_register="rax"))
    assert indirect is not None
    assert indirect.table_type == JumpTableType.INDIRECT

    # scale != pointer size -> COMPACT
    compact = analyzer.resolve_jump_table(_jump(base_register=None, scale=4))
    assert compact is not None
    assert compact.table_type == JumpTableType.COMPACT


def test_resolve_jump_table_without_address_returns_none() -> None:
    binary = InMemoryJumpTableBinary(bits=64, table_address=_TABLE_ADDRESS, blob=_blob(_TARGETS))
    analyzer = SwitchTableAnalyzer(binary)

    no_address = _jump(displacement=0, table_address=None)
    assert analyzer.resolve_jump_table(no_address, table_address=None) is None
