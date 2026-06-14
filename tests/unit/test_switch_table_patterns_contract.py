from r2morph.analysis.switch_table_patterns import JUMP_TABLE_PATTERNS, PLT_PATTERNS, TAIL_CALL_PATTERNS


def test_switch_table_pattern_catalog_contract() -> None:
    assert len(JUMP_TABLE_PATTERNS) >= 3
    assert len(TAIL_CALL_PATTERNS) >= 2
    assert len(PLT_PATTERNS) >= 2
    assert all(isinstance(item, tuple) and len(item) == 2 for item in JUMP_TABLE_PATTERNS)
    assert all(isinstance(item, tuple) and len(item) == 2 for item in TAIL_CALL_PATTERNS)
    assert all(isinstance(item, str) for item in PLT_PATTERNS)
