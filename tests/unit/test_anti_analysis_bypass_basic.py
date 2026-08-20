from __future__ import annotations

from r2morph.detection.anti_analysis_bypass import AntiAnalysisBypass, AntiAnalysisType, BypassTechnique
from tests.utils.assertions import expect


def test_anti_analysis_bypass_methods_and_status() -> None:
    bypass = AntiAnalysisBypass()

    methods = bypass._get_bypass_methods(AntiAnalysisType.DEBUGGER_DETECTION)
    expect(not (BypassTechnique.API_REDIRECTION not in methods))

    expect(bypass._get_bypass_methods(AntiAnalysisType.HARDWARE_FINGERPRINTING) == [])

    expect(not (bypass._apply_bypass(BypassTechnique.API_REDIRECTION, 0.9) is not True))
    expect(not (bypass._apply_bypass(BypassTechnique.TIMING_MANIPULATION, 0.9) is not True))

    status = bypass.get_bypass_status()
    expect(not (status["bypass_count"] < 1))
