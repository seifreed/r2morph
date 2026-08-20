from r2morph.analysis.switch_table_patterns import JUMP_TABLE_PATTERNS, PLT_PATTERNS, TAIL_CALL_PATTERNS
from tests.utils.assertions import expect

_EXPECTED_LEN_ITEM_2 = 2
_EXPECTED_LEN_ITEM_2_2 = 2
_EXPECTED_LEN_JUMP_TABLE_PATTERNS_3 = 3
_EXPECTED_LEN_PLT_PATTERNS_2 = 2
_EXPECTED_LEN_TAIL_CALL_PATTERNS_2 = 2


def test_switch_table_pattern_catalog_contract() -> None:
    expect(not (len(JUMP_TABLE_PATTERNS) < _EXPECTED_LEN_JUMP_TABLE_PATTERNS_3))
    expect(not (len(TAIL_CALL_PATTERNS) < _EXPECTED_LEN_TAIL_CALL_PATTERNS_2))
    expect(not (len(PLT_PATTERNS) < _EXPECTED_LEN_PLT_PATTERNS_2))
    expect(all(isinstance(item, tuple) and len(item) == _EXPECTED_LEN_ITEM_2 for item in JUMP_TABLE_PATTERNS))
    expect(all(isinstance(item, tuple) and len(item) == _EXPECTED_LEN_ITEM_2_2 for item in TAIL_CALL_PATTERNS))
    expect(all(isinstance(item, str) for item in PLT_PATTERNS))
