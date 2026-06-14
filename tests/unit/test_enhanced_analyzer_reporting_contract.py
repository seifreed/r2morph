from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from r2morph.analysis.enhanced_analyzer_reporting import (
    display_analysis_results,
    display_detection_results,
    display_recommendations,
    generate_report,
    save_report,
)


class _Detector:
    def get_comprehensive_report(self, binary):
        return {"binary": str(binary)}


def test_enhanced_analyzer_reporting_helpers_expose_expected_contract(tmp_path: Path) -> None:
    console = Console(record=True)
    detection_result = SimpleNamespace(
        packer_detected=SimpleNamespace(value="packer"),
        vm_detected=True,
        anti_analysis_detected=False,
        control_flow_flattened=False,
        mba_detected=True,
        confidence_score=0.75,
        obfuscation_techniques=["vm", "mba", "packing"],
        to_dict=lambda: {"status": "ok"},
    )
    results = SimpleNamespace(
        cfo_reduction=3,
        iterative_result={"iteration": 2},
        vm_handlers=1,
        rewrite_output="rewritten.bin",
        report=None,
    )

    display_detection_results(
        console,
        Path("binary.bin"),
        detection_result,
        {"detected": True, "vm_type": "custom", "confidence": 0.9},
        {"layers_detected": 2},
        {"detected": True, "polymorphic_ratio": 0.25},
        verbose=True,
    )
    display_analysis_results(console, results)
    display_recommendations(console, detection_result, {"layers_detected": 2})
    output = console.export_text()
    assert "Enhanced Analysis: binary.bin" in output
    assert "Obfuscation Techniques" in output
    assert "Advanced Analysis Results" in output
    assert "Recommendations" in output

    report = generate_report(_Detector(), "binary.bin", results, console)
    assert report == {"binary": "binary.bin"}
    assert results.report == report

    report_path = save_report(tmp_path, report, console)
    assert report_path.exists()
    assert report_path.name == "analysis_report.json"
