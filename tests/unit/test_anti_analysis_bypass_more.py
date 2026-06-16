from r2morph.detection.anti_analysis_bypass import (
    AntiAnalysisBypass,
    AntiAnalysisPattern,
    AntiAnalysisType,
    BypassTechnique,
)


def test_bypass_methods_and_status():
    bypass = AntiAnalysisBypass()

    methods = bypass._get_bypass_methods(AntiAnalysisType.DEBUGGER_DETECTION)
    assert BypassTechnique.API_REDIRECTION in methods

    empty_methods = bypass._get_bypass_methods(AntiAnalysisType.HARDWARE_FINGERPRINTING)
    assert empty_methods == []

    status = bypass.get_bypass_status()
    assert status["bypass_count"] == 0


def test_check_pattern_match_empty_pattern():
    bypass = AntiAnalysisBypass()
    pattern = AntiAnalysisPattern(
        name="Empty",
        technique_type=AntiAnalysisType.DEBUGGER_DETECTION,
        api_calls=[],
        string_patterns=[],
    )
    confidence = bypass._check_pattern_match(pattern, binary=None)
    assert confidence == 0.0
