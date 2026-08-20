from __future__ import annotations

from r2morph.analysis.call_graph import CallType
from r2morph.analysis.call_graph_parsing import (
    determine_call_type,
    extract_call_target,
    is_tail_call,
)
from tests.utils.assertions import expect

_EXPECTED_EXTRACT_CALL_TARGET_CALL_0X401000_4198400 = 0x401000


def test_call_graph_parsing_helpers_classify_and_parse_targets() -> None:
    expect(determine_call_type("sym.imp.printf") == CallType.PLT)
    expect(determine_call_type("sub.main") == CallType.DIRECT)
    expect(determine_call_type("foo.bar") == CallType.LIBRARY)
    expect(determine_call_type("main") == CallType.DIRECT)

    expect(extract_call_target("call 0x401000") == _EXPECTED_EXTRACT_CALL_TARGET_CALL_0X401000_4198400)
    expect(extract_call_target("call [rax]") == "indirect:[rax]")
    expect(extract_call_target("call rax") == "indirect:rax")
    expect(extract_call_target("call label") == "label")
    expect(not (is_tail_call("jmp 0x401000") is not True))
    expect(not (is_tail_call("jmp rax") is not True))
    expect(not (is_tail_call("call 0x401000") is not False))
