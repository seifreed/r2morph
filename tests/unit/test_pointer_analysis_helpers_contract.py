from r2morph.analysis.pointer_analysis_helpers import compute_transitive_aliases, extract_lea_target
from tests.utils.assertions import expect

_EXPECTED_EXTRACT_LEA_TARGET_LEA_RAX_0X401000_4198400 = 0x401000


def test_pointer_analysis_helpers_contract() -> None:
    expect(extract_lea_target("lea rax, [0x401000]") == _EXPECTED_EXTRACT_LEA_TARGET_LEA_RAX_0X401000_4198400)
    expect(not (extract_lea_target("lea rax, [rbx]") is not None))
    aliases = compute_transitive_aliases({1: {2}, 2: {3}})
    expect(aliases[1] == {2, 3})
