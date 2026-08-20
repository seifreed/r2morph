from r2morph.analysis.dependencies import DependencyAnalyzer, DependencyType
from tests.utils.assertions import expect

_EXPECTED_CHAIN_0_4096 = 0x1000
_EXPECTED_CHAIN_4100 = 0x1004


def test_dependency_parser_and_dependency_types():
    analyzer = DependencyAnalyzer()
    instructions = [
        {"offset": 0x1000, "disasm": "mov rax, rbx"},
        {"offset": 0x1004, "disasm": "cmp rax, rcx"},
        {"offset": 0x1008, "disasm": "cmp rax, rdx"},
        {"offset": 0x100C, "disasm": "mov rax, rsi"},
        {"offset": 0x1010, "disasm": "mov rax, rdi"},
        {"offset": 0x1014, "disasm": "ret"},
    ]

    deps = analyzer.analyze_dependencies(instructions)
    expect(deps)

    dep_types = {dep.dep_type for dep in deps}
    expect(not (DependencyType.READ_AFTER_WRITE not in dep_types))
    expect(not (DependencyType.READ_AFTER_READ not in dep_types))
    expect(not (DependencyType.WRITE_AFTER_READ not in dep_types))
    expect(not (DependencyType.WRITE_AFTER_WRITE not in dep_types))

    chain = analyzer.get_dependency_chain(0x1000)
    expect(chain[0] == _EXPECTED_CHAIN_0_4096)
    expect(not (_EXPECTED_CHAIN_4100 not in chain))

    dot = analyzer.to_dot()
    expect(not ("color=red" not in dot))
    expect(not ("color=blue" not in dot))
    expect(not ("color=green" not in dot))
    expect(not ("color=gray" not in dot))


def test_dependency_operand_parsing_variants():
    analyzer = DependencyAnalyzer()

    defines, uses = analyzer._parse_operands({"disasm": "push rax"})
    expect(not ("rsp" not in defines))
    expect(not ("rsp" not in uses))
    expect(not ("rax" not in uses))

    defines, uses = analyzer._parse_operands({"disasm": "pop rbx"})
    expect(not ("rbx" not in defines))
    expect(not ("rsp" not in defines))
    expect(not ("rsp" not in uses))

    defines, uses = analyzer._parse_operands({"disasm": "call rax"})
    expect(not ("rax" not in defines))
    expect(not ("rdi" not in uses))

    defines, uses = analyzer._parse_operands({"disasm": "cmp rax, rbx"})
    expect(not ("rax" not in uses))
    expect(not ("rbx" not in uses))

    defines, uses = analyzer._parse_operands({"disasm": "mov rax, [rbp-0x8]"})
    expect(not ("rax" not in defines))
    expect("rbp" not in uses)
