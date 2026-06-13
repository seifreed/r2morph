"""Contract tests for engine output helpers."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from r2morph.core.engine_output import build_report, save_binary, save_report


class _FakeBinary:
    def __init__(self, path: Path) -> None:
        self.path = path


class _FakeSigner:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, dict[str, object]]] = []

    def sign_output(self, output_path: Path, config: dict[str, object]) -> None:
        self.calls.append((output_path, dict(config)))


class _FakeSession:
    def __init__(self, source: Path) -> None:
        self.source = source
        self.finalized: list[Path] = []

    def finalize(self, output_path: Path) -> None:
        self.finalized.append(output_path)
        output_path.write_bytes(self.source.read_bytes())


class _FakeReportBuilder:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def assemble_report(self, result: dict[str, object] | None, **kwargs: object) -> dict[str, object]:
        payload: dict[str, object] = {"result": result, **kwargs}
        self.calls.append(payload)
        return payload


def test_engine_output_saves_binary_and_signs_without_session(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    output = tmp_path / "output.bin"
    signer = _FakeSigner()
    engine = SimpleNamespace(
        binary=_FakeBinary(source),
        _session=None,
        _binary_signer=signer,
        config={"mode": "test"},
    )

    save_binary(engine, output)

    assert output.read_bytes() == b"abc"
    assert signer.calls == [(output, {"mode": "test"})]


def test_engine_output_saves_binary_through_session_and_builds_report(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    output = tmp_path / "output.bin"
    report_path = tmp_path / "report.json"
    builder = _FakeReportBuilder()
    signer = _FakeSigner()
    session = _FakeSession(source)
    engine = SimpleNamespace(
        binary=_FakeBinary(source),
        _session=session,
        _binary_signer=signer,
        _report_builder=builder,
        pipeline=SimpleNamespace(passes=["pass_a"]),
        _last_result={"status": "ok"},
        config={},
    )

    save_binary(engine, output)
    report = build_report(engine, {"marker": 1})
    saved_report = save_report(engine, report_path, {"marker": 2})

    assert session.finalized == [output]
    assert output.read_bytes() == b"payload"
    assert signer.calls == [(output, {})]
    assert report["result"] == {"marker": 1}
    assert builder.calls[0]["result"] == {"marker": 1}
    assert saved_report == report_path
    assert json.loads(report_path.read_text())["result"] == {"marker": 2}
