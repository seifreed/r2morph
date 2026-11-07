import json
from io import StringIO
from pathlib import Path

import pytest

from r2morph.analysis.enhanced_analyzer import AnalysisOptions, EnhancedAnalysisOrchestrator
from r2morph.utils.logging import setup_logging, shutdown_logging
from tests.utils.assertions import expect

pytestmark = [pytest.mark.experimental]


def test_enhanced_analysis_orchestrator_paths(tmp_path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    orchestrator = EnhancedAnalysisOrchestrator(binary_path=binary_path, output_dir=tmp_path)

    bin_obj = orchestrator._load_binary()
    try:
        result = orchestrator.run_detection()
        # Augment with fields expected by display/report helpers
        if not hasattr(result, "anti_analysis_detected"):
            result.anti_analysis_detected = False
        if not hasattr(result, "control_flow_flattened"):
            result.control_flow_flattened = False
        if not hasattr(result, "mba_detected"):
            result.mba_detected = False
        if not hasattr(result, "confidence_score"):
            result.confidence_score = 0.0

        orchestrator.display_detection_results(verbose=True)

        orchestrator.run_anti_analysis_bypass()
        orchestrator.run_cfo_simplification()
        orchestrator.run_iterative_simplification(max_iterations=1, timeout=5)
        orchestrator.run_symbolic_analysis()
        orchestrator.run_dynamic_analysis()
        orchestrator.run_binary_rewriting()

        orchestrator.display_analysis_results()
        report = orchestrator.generate_report()
        expect(isinstance(report, dict))

        orchestrator.save_report(report)
        orchestrator.display_recommendations()

        options = AnalysisOptions(
            detect_only=False,
            devirt=True,
            iterative=True,
            dynamic=True,
            rewrite=True,
            bypass=True,
        )
        orchestrator.analyze(options)

    finally:
        orchestrator._cleanup()
        if bin_obj is not None:
            bin_obj.__exit__(None, None, None)


def test_detect_only_analysis_logs_correlated_completion() -> None:
    stream = StringIO()
    setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json", "R2MORPH_LOG_LEVEL": "DEBUG"})
    orchestrator = EnhancedAnalysisOrchestrator(Path("fixtures/dataset/elf_x86_64"))
    try:
        orchestrator.analyze(AnalysisOptions(detect_only=True))
    finally:
        shutdown_logging()

    all_events = [json.loads(line) for line in stream.getvalue().splitlines()]
    operation_events = [
        event
        for event in all_events
        if event.get("event_name") in {"analysis.enhanced.started", "analysis.enhanced.completed"}
    ]
    expect(
        [event["event_name"] for event in operation_events]
        == ["analysis.enhanced.started", "analysis.enhanced.completed"]
        and operation_events[0]["correlation_id"] == operation_events[1]["correlation_id"]
        and operation_events[1]["duration_ms"] >= 0
    )
