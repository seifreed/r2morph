from r2morph.analysis.pointer_analysis_helpers import compute_transitive_aliases, extract_lea_target


def test_pointer_analysis_helpers_contract() -> None:
    assert extract_lea_target("lea rax, [0x401000]") == 0x401000
    assert extract_lea_target("lea rax, [rbx]") is None
    aliases = compute_transitive_aliases({1: {2}, 2: {3}})
    assert aliases[1] == {2, 3}
