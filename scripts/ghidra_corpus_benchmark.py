#!/usr/bin/env python3
"""Run one Ghidra headless analysis over every original/protected corpus pair."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.adapters.process import ProcessTimeoutError, run_process
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from scripts.adversarial_benchmark import _parse_ghidra_function_count, _pass_result, _pass_summary
from scripts.protection_maturity_baseline import discover_executables

_DEFAULT_TIMEOUT_SECONDS = 120
_GHIDRA_ANALYSIS_TIMEOUT_SECONDS = 60
_GHIDRA_WORKERS = 4
_GHIDRA_SCRIPT = Path(__file__).with_name("ghidra")


def _ghidra_executable() -> str:
    executable = os.environ.get("GHIDRA_HEADLESS")
    if not executable or not Path(executable).is_file():
        raise FileNotFoundError("GHIDRA_HEADLESS must point to analyzeHeadless")
    return executable


def _protected_copy(original: Path, destination: Path) -> tuple[Path, dict[str, object]]:
    protected = destination / f"protected__{original.name}"
    shutil.copyfile(original, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260827}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return protected, _pass_result(stats)


def _stage_pairs(fixtures: list[Path], staging: Path) -> list[dict[str, object]]:
    samples: list[dict[str, object]] = []
    for fixture in fixtures:
        original = staging / f"original__{fixture.name}"
        shutil.copyfile(fixture, original)
        protected, pass_row = _protected_copy(fixture, staging)
        samples.append(
            {
                "original": fixture.name,
                "original_program": original.name,
                "protected_program": protected.name,
                "passes": [pass_row],
            }
        )
    return samples


def _run_ghidra_program(staging: Path, program: Path, timeout: int) -> tuple[str, dict[str, object]]:
    try:
        with tempfile.TemporaryDirectory(prefix="r2morph-ghidra-project-") as project:
            result = run_process(
                [
                    _ghidra_executable(),
                    project,
                    "program",
                    "-import",
                    program,
                    "-scriptPath",
                    _GHIDRA_SCRIPT,
                    "-postscript",
                    "CountFunctions.java",
                    "-analysisTimeoutPerFile",
                    str(_GHIDRA_ANALYSIS_TIMEOUT_SECONDS),
                    "-deleteProject",
                    "-okToDelete",
                ],
                timeout=timeout,
            )
        if result.returncode != 0:
            return program.name, {"status": "error", "reason": f"exit status {result.returncode}"}
        return program.name, {
            "status": "completed",
            "functions": _parse_ghidra_function_count(result.stdout_text + result.stderr_text),
        }
    except ProcessTimeoutError:
        return program.name, {"status": "timeout", "reason": f"exceeded {timeout}s"}
    except (OSError, ValueError, RuntimeError) as error:
        return program.name, {"status": "error", "reason": type(error).__name__}


def _run_ghidra(staging: Path, timeout: int) -> dict[str, dict[str, object]]:
    programs = sorted(path for path in staging.iterdir() if path.is_file())
    with ThreadPoolExecutor(max_workers=_GHIDRA_WORKERS) as executor:
        results = executor.map(lambda program: _run_ghidra_program(staging, program, timeout), programs)
        return dict(results)


def benchmark_corpus(dataset: Path, timeout: int = _DEFAULT_TIMEOUT_SECONDS) -> dict[str, object]:
    fixtures = discover_executables(dataset)
    if not fixtures:
        raise ValueError(f"no supported executable fixtures found in {dataset}")
    with tempfile.TemporaryDirectory(prefix="r2morph-ghidra-staging-") as staging_name:
        samples = _stage_pairs(fixtures, Path(staging_name))
        analyses = _run_ghidra(Path(staging_name), timeout)
    for sample in samples:
        original_program = str(sample.pop("original_program"))
        protected_program = str(sample.pop("protected_program"))
        original_analysis = analyses.get(original_program, {"status": "error", "reason": "missing result"})
        protected_analysis = analyses.get(protected_program, {"status": "error", "reason": "missing result"})
        if original_analysis.get("status") == protected_analysis.get("status") == "completed":
            tool = {
                "tool": "ghidra",
                "status": "completed",
                "original": original_analysis,
                "protected": protected_analysis,
                "changed": original_analysis["functions"] != protected_analysis["functions"],
            }
        else:
            statuses = {original_analysis.get("status"), protected_analysis.get("status")}
            tool = {
                "tool": "ghidra",
                "status": "timeout" if "timeout" in statuses else "error",
                "original": original_analysis,
                "protected": protected_analysis,
            }
        sample["tools"] = [tool]
    statuses = [analysis.get("status") for analysis in analyses.values()]
    return {
        "schema_version": 1,
        "measurement": "ghidra-headless-corpus",
        "corpus": dataset.name,
        "sample_count": len(samples),
        "samples": samples,
        "pass_summary": _pass_summary(samples),
        "summary": {
            "completed_analysis_runs": statuses.count("completed"),
            "timeout_analysis_runs": statuses.count("timeout"),
            "error_analysis_runs": statuses.count("error"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=_DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()
    report = benchmark_corpus(args.dataset, args.timeout)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
