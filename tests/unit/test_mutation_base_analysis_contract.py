"""Regression contract for bounded automatic mutation analysis."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.base import MutationPass
from tests.utils.assertions import expect


class _AnalysisProbePass(MutationPass):
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__("AnalysisProbe", config)

    def apply(self, binary: Any) -> dict[str, Any]:
        return {}


class _AnalysisProbeBinary:
    def __init__(self) -> None:
        self.levels: list[str] = []

    def is_analyzed(self) -> bool:
        return bool(self.levels)

    def analyze(self, level: str = "aa") -> None:
        self.levels.append(level)


def test_mutation_pass_uses_bounded_analysis_by_default() -> None:
    binary = _AnalysisProbeBinary()

    _AnalysisProbePass()._ensure_analyzed(binary)

    expect(binary.levels == ["aa"])


def test_mutation_pass_allows_explicit_deep_analysis_override() -> None:
    binary = _AnalysisProbeBinary()

    _AnalysisProbePass({"analysis_level": "aaa"})._ensure_analyzed(binary)

    expect(binary.levels == ["aaa"])


def test_mutation_pass_rejects_empty_analysis_override() -> None:
    binary = _AnalysisProbeBinary()

    try:
        _AnalysisProbePass({"analysis_level": ""})._ensure_analyzed(binary)
    except ValueError as error:
        expect(str(error) == "analysis_level must be a non-empty string")
    else:
        raise AssertionError("empty analysis level was accepted")
