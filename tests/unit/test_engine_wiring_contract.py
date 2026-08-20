"""Contract tests for engine wiring helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2morph.core.engine_wiring import build_engine_wiring
from tests.utils.assertions import expect


class _FakeSigner:
    def sign_output(self, output_path: Path, config: dict[str, object]) -> None:
        return None


class _FakeReportBuilder:
    def assemble_report(self, result: dict[str, object] | None, **kwargs: object) -> dict[str, object]:
        return {"result": result, **kwargs}


def test_engine_wiring_builds_default_dependencies() -> None:
    wiring = build_engine_wiring()

    expect(hasattr(wiring.pipeline, "passes"))
    expect(hasattr(wiring.binary_signer, "sign_output"))
    expect(hasattr(wiring.report_builder, "assemble_report"))


def test_engine_wiring_honors_injected_dependencies() -> None:
    signer = _FakeSigner()
    report_builder = _FakeReportBuilder()
    gate_failure_reporter = SimpleNamespace()
    report_view_builder = SimpleNamespace()

    wiring = build_engine_wiring(
        binary_signer=signer,
        gate_failure_reporter=gate_failure_reporter,
        report_view_builder=report_view_builder,
        report_builder=report_builder,
    )

    expect(not (wiring.binary_signer is not signer))
    expect(not (wiring.report_builder is not report_builder))
    expect(hasattr(wiring.pipeline, "passes"))
