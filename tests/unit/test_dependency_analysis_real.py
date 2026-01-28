from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.analysis.dependencies import DependencyAnalyzer


def test_dependency_analysis_on_real_function():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        assert functions

        instructions = bin_obj.get_function_disasm(functions[0].get("offset", 0))
        analyzer = DependencyAnalyzer()
        deps = analyzer.analyze_dependencies(instructions)
        assert isinstance(deps, list)

        if instructions:
            addr = instructions[0].get("offset", 0)
            deps_for = analyzer.get_dependencies_for_instruction(addr)
            assert isinstance(deps_for, list)

            chain = analyzer.get_dependency_chain(addr)
            assert chain

        dot = analyzer.to_dot()
        assert "digraph Dependencies" in dot
