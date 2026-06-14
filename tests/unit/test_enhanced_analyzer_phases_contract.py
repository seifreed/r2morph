from pathlib import Path

from rich.console import Console

from r2morph.analysis.enhanced_analyzer_lifecycle import load_binary
from r2morph.analysis.enhanced_analyzer_models import AnalysisResults
from r2morph.analysis.enhanced_analyzer_phases import (
    run_binary_rewriting,
    run_cfo_simplification,
    run_dynamic_analysis,
    run_iterative_simplification,
    run_symbolic_analysis,
)


def test_enhanced_analyzer_phase_helpers_basic_flow(tmp_path):
    binary = load_binary(Path("dataset/elf_x86_64"))
    console = Console(record=True)
    results = AnalysisResults()
    try:
        assert isinstance(run_cfo_simplification(binary, console, results), int)
        assert run_iterative_simplification(binary, console, results, max_iterations=1, timeout=5) is not None
        symbolic_result = run_symbolic_analysis(binary, console, results)
        assert symbolic_result is None or isinstance(symbolic_result, int)
        assert isinstance(run_dynamic_analysis(console), bool)
        rewrite_result = run_binary_rewriting(binary, Path("dataset/elf_x86_64"), console, results, output_dir=tmp_path)
        assert rewrite_result is None or isinstance(rewrite_result, str)
    finally:
        binary.__exit__(None, None, None)
