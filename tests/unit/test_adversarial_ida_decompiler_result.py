"""Regression tests for observable IDA decompiler outcomes."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from scripts.adversarial_benchmark_tools import _read_ida_results
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_IDA_SCRIPT = _ROOT / "scripts" / "ida" / "count_functions.py"
_EXPECTED_IDA_FUNCTION_COUNT = 4


def test_ida_decompiler_failure_result_preserves_error_status(tmp_path: Path) -> None:
    analysis_path = tmp_path / "sample.elf"
    Path(f"{analysis_path}.function-count").write_text(str(_EXPECTED_IDA_FUNCTION_COUNT), encoding="ascii")
    Path(f"{analysis_path}.decompiler").write_text(
        json.dumps(
            {
                "status": "error",
                "entrypoints": 0,
                "lines": 0,
                "bytes": 0,
                "error_count": 1,
                "error_type": "RuntimeError",
            }
        ),
        encoding="utf-8",
    )
    function_count, result = _read_ida_results(analysis_path)

    expect(
        function_count == _EXPECTED_IDA_FUNCTION_COUNT
        and result
        == {
            "status": "error",
            "entrypoints": 0,
            "lines": 0,
            "bytes": 0,
            "error_count": 1,
            "error_type": "RuntimeError",
        }
    )


def test_ida_decompiler_unavailable_result_preserves_reason(tmp_path: Path) -> None:
    analysis_path = tmp_path / "sample.elf"
    Path(f"{analysis_path}.function-count").write_text("0", encoding="ascii")
    Path(f"{analysis_path}.decompiler").write_text(
        json.dumps(
            {
                "status": "unavailable",
                "reason": "decompiler plugin could not be initialized",
                "entrypoints": 0,
                "lines": 0,
                "bytes": 0,
            }
        ),
        encoding="utf-8",
    )
    _, result = _read_ida_results(analysis_path)

    expect(
        result
        == {
            "status": "unavailable",
            "reason": "decompiler plugin could not be initialized",
            "entrypoints": 0,
            "lines": 0,
            "bytes": 0,
            "error_count": 0,
        }
    )


def test_ida_decompiler_result_rejects_untrusted_reason_text(tmp_path: Path) -> None:
    analysis_path = tmp_path / "sample.elf"
    Path(f"{analysis_path}.function-count").write_text("0", encoding="ascii")
    Path(f"{analysis_path}.decompiler").write_text(
        json.dumps(
            {
                "status": "error",
                "reason": "/Users/analyst/private/sample.bin\npassword=secret",
                "error_type": "RuntimeError",
            }
        ),
        encoding="utf-8",
    )
    _, result = _read_ida_results(analysis_path)

    expect("reason" not in result)


def test_ida_script_does_not_silence_decompiler_exceptions() -> None:
    tree = ast.parse(_IDA_SCRIPT.read_text(encoding="utf-8"))
    handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]
    silent_handlers = [
        handler
        for handler in handlers
        if not handler.body or all(isinstance(statement, ast.Pass) for statement in handler.body)
    ]
    diagnostic_keys = {
        node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    expect(bool(handlers) and not silent_handlers and {"status", "error_type", "error_count"} <= diagnostic_keys)


def test_ida_decompiler_result_ignores_invalid_counts(tmp_path: Path) -> None:
    analysis_path = tmp_path / "sample.elf"
    Path(f"{analysis_path}.function-count").write_text("0", encoding="ascii")
    Path(f"{analysis_path}.decompiler").write_text(
        json.dumps(
            {
                "status": "partial",
                "entrypoints": True,
                "lines": -1,
                "bytes": "unknown",
                "error_count": -2,
            }
        ),
        encoding="utf-8",
    )
    _, result = _read_ida_results(analysis_path)

    expect(
        result
        == {
            "status": "partial",
            "entrypoints": 0,
            "lines": 0,
            "bytes": 0,
            "error_count": 0,
        }
    )
