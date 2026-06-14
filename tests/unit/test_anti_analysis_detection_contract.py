from __future__ import annotations

from r2morph.detection.anti_analysis_bypass_models import (
    AntiAnalysisPattern,
    AntiAnalysisType,
)
from r2morph.detection.anti_analysis_detection import (
    check_pattern_match,
    detect_anti_analysis_techniques,
    detect_runtime_anti_analysis,
    load_anti_analysis_patterns,
)


class _FakeR2:
    def cmd(self, command: str) -> str:
        assert command == "izz"
        return "debugger sandbox hook"


class _FakeBinary:
    def __init__(self) -> None:
        self.r2 = _FakeR2()

    def get_imports(self) -> list[dict[str, str]]:
        return [{"name": "IsDebuggerPresent"}, {"name": "LoadLibraryA"}]


def test_load_anti_analysis_patterns_returns_expected_catalog() -> None:
    patterns = load_anti_analysis_patterns()

    assert patterns
    assert any(pattern.name == "IsDebuggerPresent" for pattern in patterns)


def test_check_pattern_match_scores_matching_imports_and_strings() -> None:
    binary = _FakeBinary()
    pattern = AntiAnalysisPattern(
        name="Custom",
        technique_type=AntiAnalysisType.DEBUGGER_DETECTION,
        api_calls=["IsDebuggerPresent"],
        string_patterns=["debugger"],
    )

    confidence = check_pattern_match(pattern, binary)

    assert confidence == 1.0


def test_detect_anti_analysis_techniques_merges_pattern_hits() -> None:
    binary = _FakeBinary()
    pattern = AntiAnalysisPattern(
        name="Custom",
        technique_type=AntiAnalysisType.DEBUGGER_DETECTION,
        api_calls=["IsDebuggerPresent"],
        string_patterns=["debugger"],
    )

    results = detect_anti_analysis_techniques(binary, [pattern])

    assert results[AntiAnalysisType.DEBUGGER_DETECTION] == 1.0


def test_detect_runtime_anti_analysis_merges_runtime_signatures(monkeypatch) -> None:
    import r2morph.detection.anti_analysis_detection as detection

    monkeypatch.setattr(detection, "PSUTIL_AVAILABLE", False)
    monkeypatch.setattr(detection, "check_vm_environment", lambda: 0.25)
    monkeypatch.setattr(detection, "check_timing_manipulation", lambda: 0.75)

    results = detect_runtime_anti_analysis()

    assert results[AntiAnalysisType.VM_DETECTION] == 0.25
    assert results[AntiAnalysisType.TIMING_ATTACKS] == 0.75
