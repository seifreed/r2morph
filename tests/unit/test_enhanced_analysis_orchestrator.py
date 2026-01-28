from pathlib import Path

from r2morph.analysis.enhanced_analyzer import EnhancedAnalysisOrchestrator, AnalysisOptions


def test_enhanced_analysis_orchestrator_paths(tmp_path):
    binary_path = Path("dataset/elf_x86_64")
    orchestrator = EnhancedAnalysisOrchestrator(binary_path=binary_path, output_dir=tmp_path)

    assert orchestrator._ensure_dependencies() is True

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
        assert isinstance(report, dict)

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
