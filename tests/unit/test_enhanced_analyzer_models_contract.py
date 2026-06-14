from r2morph.analysis.enhanced_analyzer_models import AnalysisOptions, AnalysisResults


def test_enhanced_analyzer_models_defaults():
    options = AnalysisOptions()
    results = AnalysisResults()

    assert options.verbose is False
    assert options.detect_only is False
    assert options.devirt is False
    assert options.max_functions == 5
    assert options.max_iterations == 5
    assert options.timeout == 60

    assert results.detection_result is None
    assert results.custom_vm == {}
    assert results.layers == {}
    assert results.metamorphic == {}
    assert results.cfo_reduction == 0
    assert results.iterative_result is None
    assert results.vm_handlers == 0
    assert results.rewrite_output is None
    assert results.report is None
