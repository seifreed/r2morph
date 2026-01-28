from r2morph.analysis.dependencies import DependencyAnalyzer, DependencyType


def test_dependency_analyzer_parse_operands_call_and_stack():
    analyzer = DependencyAnalyzer()

    defines, uses = analyzer._parse_operands({"disasm": "push rax"})
    assert "rax" in uses
    assert "rsp" in uses
    assert "rsp" in defines

    defines, uses = analyzer._parse_operands({"disasm": "pop rbx"})
    assert "rbx" in defines
    assert "rsp" in defines
    assert "rsp" in uses

    defines, uses = analyzer._parse_operands({"disasm": "call 0x401000"})
    assert "rax" in defines
    assert "rdi" in uses


def test_dependency_analyzer_waw_raw_chain_and_dot_colors():
    analyzer = DependencyAnalyzer()
    instructions = [
        {"offset": 0x1000, "disasm": "mov eax, ebx"},
        {"offset": 0x1002, "disasm": "mov eax, ecx"},
        {"offset": 0x1004, "disasm": "mov edx, eax"},
    ]

    deps = analyzer.analyze_dependencies(instructions)
    assert deps

    assert analyzer.has_dependency(0x1000, 0x1002) is True  # WAW on eax
    assert analyzer.has_dependency(0x1002, 0x1004) is True  # RAW on eax

    chain = analyzer.get_dependency_chain(0x1002)
    assert 0x1004 in chain

    dot = analyzer.to_dot()
    assert "color=green" in dot  # WAW
    assert "color=red" in dot  # RAW
