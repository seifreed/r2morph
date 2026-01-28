import os

from r2morph.detection.anti_analysis_bypass import (
    AntiAnalysisBypass,
    AntiAnalysisType,
    BypassTechnique,
    AntiAnalysisPattern,
)


def test_bypass_methods_and_status():
    bypass = AntiAnalysisBypass()

    methods = bypass._get_bypass_methods(AntiAnalysisType.DEBUGGER_DETECTION)
    assert BypassTechnique.API_REDIRECTION in methods

    empty_methods = bypass._get_bypass_methods(AntiAnalysisType.HARDWARE_FINGERPRINTING)
    assert empty_methods == []

    status = bypass.get_bypass_status()
    assert status["bypass_count"] == 0


def test_environment_masking_and_restore():
    bypass = AntiAnalysisBypass()
    original = dict(os.environ)

    try:
        assert bypass._apply_environment_masking() is True
        status = bypass.get_bypass_status()
        assert "environment_masking" in status["active_bypasses"]

        restored = bypass.restore_environment()
        assert restored is True
    finally:
        # Ensure environment is restored even if test fails
        os.environ.clear()
        os.environ.update(original)


def test_timing_manipulation_and_environment_state():
    bypass = AntiAnalysisBypass()
    assert bypass._apply_timing_manipulation() is True

    state = bypass._get_environment_state()
    assert "timing_baseline" in state
    assert state["timing_baseline"]


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
