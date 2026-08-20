from r2morph.analysis.dependencies import DependencyAnalyzer
from tests.utils.assertions import expect

_EXPECTED_CHAIN_4100 = 0x1004


def test_dependency_analyzer_parse_operands_call_and_stack():
    analyzer = DependencyAnalyzer()

    defines, uses = analyzer._parse_operands({"disasm": "push rax"})
    expect(not ("rax" not in uses))
    expect(not ("rsp" not in uses))
    expect(not ("rsp" not in defines))

    defines, uses = analyzer._parse_operands({"disasm": "pop rbx"})
    expect(not ("rbx" not in defines))
    expect(not ("rsp" not in defines))
    expect(not ("rsp" not in uses))

    defines, uses = analyzer._parse_operands({"disasm": "call 0x401000"})
    expect(not ("rax" not in defines))
    expect(not ("rdi" not in uses))


def test_dependency_analyzer_waw_raw_chain_and_dot_colors():
    analyzer = DependencyAnalyzer()
    instructions = [
        {"offset": 0x1000, "disasm": "mov eax, ebx"},
        {"offset": 0x1002, "disasm": "mov eax, ecx"},
        {"offset": 0x1004, "disasm": "mov edx, eax"},
    ]

    deps = analyzer.analyze_dependencies(instructions)
    expect(deps)

    expect(not (analyzer.has_dependency(0x1000, 0x1002) is not True))
    expect(not (analyzer.has_dependency(0x1002, 0x1004) is not True))

    chain = analyzer.get_dependency_chain(0x1002)
    expect(not (_EXPECTED_CHAIN_4100 not in chain))

    dot = analyzer.to_dot()
    expect(not ("color=green" not in dot))
    expect(not ("color=red" not in dot))
