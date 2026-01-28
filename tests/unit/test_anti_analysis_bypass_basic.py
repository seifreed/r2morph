from __future__ import annotations

import os

from r2morph.detection.anti_analysis_bypass import AntiAnalysisBypass, AntiAnalysisType, BypassTechnique


def test_anti_analysis_bypass_methods_and_status() -> None:
    bypass = AntiAnalysisBypass()

    methods = bypass._get_bypass_methods(AntiAnalysisType.DEBUGGER_DETECTION)
    assert BypassTechnique.API_REDIRECTION in methods

    assert bypass._get_bypass_methods(AntiAnalysisType.HARDWARE_FINGERPRINTING) == []

    assert bypass._apply_bypass(BypassTechnique.API_REDIRECTION, 0.9) is True
    assert bypass._apply_bypass(BypassTechnique.TIMING_MANIPULATION, 0.9) is True

    status = bypass.get_bypass_status()
    assert status["bypass_count"] >= 1


def test_environment_masking_restore() -> None:
    bypass = AntiAnalysisBypass()

    original_username = os.environ.get("USERNAME", "")
    try:
        assert bypass._apply_environment_masking() is True
        assert os.environ.get("USERNAME") == "Administrator"
        state = bypass._get_environment_state()
        assert "environment_vars" in state
    finally:
        bypass.restore_environment()
        if original_username:
            assert os.environ.get("USERNAME") == original_username
