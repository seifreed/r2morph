from __future__ import annotations

from r2morph.analysis.call_graph import CallType
from r2morph.analysis.call_graph_parsing import (
    determine_call_type,
    extract_call_target,
    is_tail_call,
)


def test_call_graph_parsing_helpers_classify_and_parse_targets() -> None:
    assert determine_call_type("sym.imp.printf") == CallType.PLT
    assert determine_call_type("sub.main") == CallType.DIRECT
    assert determine_call_type("foo.bar") == CallType.LIBRARY
    assert determine_call_type("main") == CallType.DIRECT

    assert extract_call_target("call 0x401000") == 0x401000
    assert extract_call_target("call [rax]") == "indirect:[rax]"
    assert extract_call_target("call rax") == "indirect:rax"
    assert extract_call_target("call label") == "label"
    assert is_tail_call("jmp 0x401000") is True
    assert is_tail_call("jmp rax") is True
    assert is_tail_call("call 0x401000") is False
