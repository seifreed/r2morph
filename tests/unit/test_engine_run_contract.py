"""Contract tests for engine run helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2morph.core.engine_run import run


class _FakeBinary:
    def __init__(self, path: Path, analyzed: bool = False) -> None:
        self.path = path
        self._analyzed = analyzed
        self.reloaded = False

    def is_analyzed(self) -> bool:
        return self._analyzed

    def reload(self) -> None:
        self.reloaded = True


class _FakeRuntimeResult:
    def __init__(self, passed: bool) -> None:
        self.passed = passed

    def to_dict(self) -> dict[str, object]:
        return {"passed": self.passed}


class _FakeRuntimeValidator:
    def __init__(self, passed: bool = True) -> None:
        self.passed = passed
        self.calls: list[tuple[Path, Path]] = []

    def validate(self, original_path: Path, working_path: Path) -> _FakeRuntimeResult:
        self.calls.append((original_path, working_path))
        return _FakeRuntimeResult(self.passed)


class _FakePipeline:
    def __init__(self) -> None:
        self.passes = [SimpleNamespace(config={}), SimpleNamespace(config={})]
        self.calls: list[dict[str, object]] = []

    def run(self, binary: _FakeBinary, **kwargs: object) -> dict[str, object]:
        self.calls.append({"binary": binary, **kwargs})
        return {
            "validation": {"all_passed": True},
            "pass_results": {"pass_a": {}},
        }


def test_engine_run_helper_applies_seed_validation_and_report(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 1024)

    pipeline = _FakePipeline()
    fake_engine = SimpleNamespace(
        binary=_FakeBinary(binary_path, analyzed=False),
        pipeline=pipeline,
        config={},
        _session=SimpleNamespace(),
        _original_path=binary_path,
        _stats={"functions": 2},
        _last_result=None,
        analyze_calls=0,
        saved_reports=[],
    )

    def analyze() -> None:
        fake_engine.analyze_calls += 1
        fake_engine.binary._analyzed = True

    def save_report(output_path: Path, result: dict[str, object]) -> Path:
        fake_engine.saved_reports.append((output_path, result))
        output_path.write_text("{}")
        return output_path

    fake_engine.analyze = analyze
    fake_engine.save_report = save_report

    runtime_validator = _FakeRuntimeValidator()
    report_path = tmp_path / "report.json"

    result = run(
        fake_engine,
        validation_mode="structural",
        runtime_validator=runtime_validator,
        report_path=report_path,
        seed=7,
    )

    assert fake_engine.analyze_calls == 1
    assert fake_engine.config["seed"] == 7
    assert [mutation.config["_pass_seed"] for mutation in pipeline.passes] == [7, 8]
    assert [mutation.config["_use_derived_seed"] for mutation in pipeline.passes] == [True, True]
    assert pipeline.calls[0]["runtime_validate_per_pass"] is False
    assert runtime_validator.calls == [(binary_path, binary_path)]
    assert result["requested_validation_mode"] == "structural"
    assert result["validation_mode"] == "structural"
    assert result["input_path"] == str(binary_path)
    assert result["working_path"] == str(binary_path)
    assert result["config"] == {"seed": 7}
    assert fake_engine.saved_reports and fake_engine.saved_reports[0][0] == report_path
