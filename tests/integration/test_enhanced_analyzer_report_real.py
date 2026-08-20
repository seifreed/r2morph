from pathlib import Path

import pytest

from r2morph.analysis.enhanced_analyzer import EnhancedAnalysisOrchestrator
from tests.utils.assertions import expect

pytestmark = [pytest.mark.experimental]


def test_enhanced_analyzer_generate_and_save_report(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    output_dir = tmp_path / "report_out"
    orchestrator = EnhancedAnalysisOrchestrator(binary_path=binary_path, output_dir=output_dir)

    bin_obj = orchestrator._load_binary()
    try:
        orchestrator.run_detection()
        report = orchestrator.generate_report()
        expect(isinstance(report, dict))
        expect(not ("obfuscation_analysis" not in report))

        report_path = orchestrator.save_report(report)
        expect(report_path is not None)
        expect(report_path.exists())
        expect(report_path.name == "analysis_report.json")
    finally:
        orchestrator._cleanup()
        if bin_obj is not None:
            bin_obj.__exit__(None, None, None)


def test_enhanced_analyzer_display_recommendations_no_detection(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    orchestrator = EnhancedAnalysisOrchestrator(binary_path=binary_path, output_dir=tmp_path)
    bin_obj = orchestrator._load_binary()
    try:
        orchestrator.run_detection()
        # Just ensure it doesn't raise when called
        orchestrator.display_recommendations()
        orchestrator.display_analysis_results()
    finally:
        orchestrator._cleanup()
        if bin_obj is not None:
            bin_obj.__exit__(None, None, None)
