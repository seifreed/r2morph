from r2morph.analysis.enhanced_analyzer_models import AnalysisOptions, AnalysisResults
from tests.utils.assertions import expect

_EXPECTED_OPTIONS_MAX_FUNCTIONS_5 = 5
_EXPECTED_OPTIONS_MAX_ITERATIONS_5 = 5
_EXPECTED_OPTIONS_TIMEOUT_60 = 60


def test_enhanced_analyzer_models_defaults():
    options = AnalysisOptions()
    results = AnalysisResults()

    expect(not (options.verbose is not False))
    expect(not (options.detect_only is not False))
    expect(not (options.devirt is not False))
    expect(options.max_functions == _EXPECTED_OPTIONS_MAX_FUNCTIONS_5)
    expect(options.max_iterations == _EXPECTED_OPTIONS_MAX_ITERATIONS_5)
    expect(options.timeout == _EXPECTED_OPTIONS_TIMEOUT_60)

    expect(not (results.detection_result is not None))
    expect(results.custom_vm == {})
    expect(results.layers == {})
    expect(results.metamorphic == {})
    expect(results.cfo_reduction == 0)
    expect(not (results.iterative_result is not None))
    expect(results.vm_handlers == 0)
    expect(not (results.rewrite_output is not None))
    expect(not (results.report is not None))
