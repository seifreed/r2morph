from r2morph.analysis.dependencies import DependencyAnalyzer, DependencyType


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
    assert deps

    dep_types = {dep.dep_type for dep in deps}
    assert DependencyType.READ_AFTER_WRITE in dep_types
    assert DependencyType.READ_AFTER_READ in dep_types
    assert DependencyType.WRITE_AFTER_READ in dep_types
    assert DependencyType.WRITE_AFTER_WRITE in dep_types

    chain = analyzer.get_dependency_chain(0x1000)
    assert chain[0] == 0x1000
    assert 0x1004 in chain

    dot = analyzer.to_dot()
    assert "color=red" in dot
    assert "color=blue" in dot
    assert "color=green" in dot
    assert "color=gray" in dot


def test_dependency_operand_parsing_variants():
    analyzer = DependencyAnalyzer()

    defines, uses = analyzer._parse_operands({"disasm": "push rax"})
    assert "rsp" in defines
    assert "rsp" in uses
    assert "rax" in uses

    defines, uses = analyzer._parse_operands({"disasm": "pop rbx"})
    assert "rbx" in defines
    assert "rsp" in defines
    assert "rsp" in uses

    defines, uses = analyzer._parse_operands({"disasm": "call rax"})
    assert "rax" in defines
    assert "rdi" in uses

    defines, uses = analyzer._parse_operands({"disasm": "cmp rax, rbx"})
    assert "rax" in uses
    assert "rbx" in uses

    defines, uses = analyzer._parse_operands({"disasm": "mov rax, [rbp-0x8]"})
    assert "rax" in defines
    assert "rbp" not in uses
