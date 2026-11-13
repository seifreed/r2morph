"""Bounded per-pass execution for adversarial benchmark campaigns."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from r2morph.adapters.process import ProcessContext, ProcessExecutionError, ProcessTimeoutError, run_process
from scripts.adversarial_benchmark_constants import _EXPECTED_TOOLS
from scripts.adversarial_benchmark_metrics import _measure_pair_tools
from scripts.adversarial_benchmark_tools import _file_digest

_MUTATION_WORKER_TIMEOUT_SECONDS = 180.0


class MutationWorkerTimeoutError(ProcessTimeoutError):
    """One mutation worker exceeded its per-pass time budget."""

    def __init__(self, timeout_seconds: float, stage: str) -> None:
        self.stage = stage
        super().__init__(f"Mutation worker exceeded {timeout_seconds:g}s during {stage}")


def _protected_copy(
    original: Path,
    directory: Path,
    pass_name: str,
    timeout_seconds: float = _MUTATION_WORKER_TIMEOUT_SECONDS,
) -> tuple[Path, dict[str, object]]:
    """Apply one pass in a killable process group and keep its result bounded."""
    protected = directory / "protected"
    progress = directory / "worker.progress"
    result_path = directory / "worker.result"
    progress.unlink(missing_ok=True)
    result_path.unlink(missing_ok=True)
    command = [
        sys.executable,
        "-m",
        "scripts.adversarial_benchmark_worker",
        original,
        directory,
        pass_name,
        progress,
        result_path,
    ]
    context = ProcessContext(cwd=Path(__file__).resolve().parents[1])
    try:
        process = run_process(command, timeout=timeout_seconds, context=context)
    except ProcessTimeoutError as error:
        stage = progress.read_text(encoding="utf-8").strip() if progress.is_file() else "worker_startup"
        result_path.unlink(missing_ok=True)
        raise MutationWorkerTimeoutError(timeout_seconds, stage) from error
    finally:
        progress.unlink(missing_ok=True)
    if process.returncode != 0 or not result_path.is_file():
        raise ProcessExecutionError(f"Mutation worker exited with status {process.returncode}")
    try:
        pass_row = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProcessExecutionError("Mutation worker returned invalid result data") from error
    finally:
        result_path.unlink(missing_ok=True)
    if not isinstance(pass_row, dict) or pass_row.get("pass_name") != pass_name or not protected.is_file():
        raise ProcessExecutionError("Mutation worker returned an incomplete result")
    return protected, pass_row


def _failed_pass_rows(
    pass_name: str,
    error_type: str,
    detail: str | None = None,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    pass_row: dict[str, object] = {"pass_name": pass_name, "status": "error", "error_type": error_type}
    if detail is not None:
        pass_row["detail"] = detail
    tool_rows = [
        {
            "tool": tool,
            "status": "error",
            "error_type": error_type,
            **({"detail": detail} if detail is not None else {}),
            "pass_name": pass_name,
            "pass_status": "error",
        }
        for tool in (*_EXPECTED_TOOLS, "custom")
    ]
    return pass_row, tool_rows


def _benchmark_passes(
    original: Path,
    directory: Path,
    pass_names: tuple[str, ...],
    timeout_seconds: float = _MUTATION_WORKER_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    pass_rows: list[dict[str, object]] = []
    tools: list[dict[str, object]] = []
    original_metrics: dict[str, dict[str, object]] = {}
    measurement_cache: dict[tuple[str, str], dict[str, object]] = {}
    for index, pass_name in enumerate(pass_names):
        try:
            protected_path, pass_row = _protected_copy(original, directory, pass_name, timeout_seconds)
        except Exception as error:  # Keep one error row for each expected pass and analyzer.
            detail = str(error) if isinstance(error, MutationWorkerTimeoutError) else None
            pass_row, failed_tools = _failed_pass_rows(pass_name, type(error).__name__, detail)
            pass_rows.append(pass_row)
            tools.extend(failed_tools)
            if isinstance(error, MutationWorkerTimeoutError) and error.stage == "binary_analysis":
                for skipped_pass in pass_names[index + 1 :]:
                    pass_row, failed_tools = _failed_pass_rows(
                        skipped_pass,
                        type(error).__name__,
                        f"Skipped after {error.stage} timeout for this binary",
                    )
                    pass_rows.append(pass_row)
                    tools.extend(failed_tools)
                break
            continue
        pass_rows.append(pass_row)
        tools.extend(
            {
                **tool,
                "pass_name": pass_name,
                "pass_status": pass_row["status"],
            }
            for tool in _measure_pair_tools(
                original,
                protected_path,
                original_metrics,
                measurement_cache,
                _file_digest(protected_path),
            )
        )
    return pass_rows, tools
