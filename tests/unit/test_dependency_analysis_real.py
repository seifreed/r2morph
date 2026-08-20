from pathlib import Path

from r2morph.analysis.dependencies import DependencyAnalyzer
from r2morph.core.binary import Binary
from tests.utils.assertions import expect


def test_dependency_analysis_on_real_function():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        expect(functions)

        instructions = bin_obj.get_function_disasm(functions[0].get("offset", 0))
        analyzer = DependencyAnalyzer()
        deps = analyzer.analyze_dependencies(instructions)
        expect(isinstance(deps, list))

        if instructions:
            addr = instructions[0].get("offset", 0)
            deps_for = analyzer.get_dependencies_for_instruction(addr)
            expect(isinstance(deps_for, list))

            chain = analyzer.get_dependency_chain(addr)
            expect(chain)

        dot = analyzer.to_dot()
        expect(not ("digraph Dependencies" not in dot))
