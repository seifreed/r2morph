#!/usr/bin/env python3
"""Run bounded native parity checks for the VM semantic fixture corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from r2morph.adapters.process import ProcessContext, ProcessTimeoutError, run_process
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

_MAX_FIXTURES = 256
_DEFAULT_TIMEOUT_SECONDS = 5.0
_DEFAULT_SEEDS = (20260916,)
_TARGET = {"os": "linux", "format": "ELF", "architecture": "x86-64"}
_MAX_CREATED_FILES = 256
_HASH_CHUNK_BYTES = 1024 * 1024


def _load_coverage(path: Path) -> dict[str, set[str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    capabilities = document.get("capabilities", {})
    if not isinstance(capabilities, Mapping):
        raise ValueError("virtualization coverage must contain capabilities")
    coverage: dict[str, set[str]] = {}
    for category, details in capabilities.items():
        if not isinstance(category, str) or not isinstance(details, Mapping):
            continue
        names = details.get("fixtures", [])
        if isinstance(names, list):
            coverage[category] = {name for name in names if isinstance(name, str)}
    return coverage


def _fixture_categories(coverage: Mapping[str, set[str]], fixture: str) -> list[str]:
    categories = sorted(category for category, names in coverage.items() if fixture in names)
    return categories or ["uncategorized"]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _created_file_observations(directory: Path) -> dict[str, dict[str, int | str]]:
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    if len(files) > _MAX_CREATED_FILES:
        raise ValueError(f"execution created more than {_MAX_CREATED_FILES} files")
    return {
        path.relative_to(directory).as_posix(): {
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode),
        }
        for path in files
    }


def _execution_observation(path: Path, timeout: float, workdir: Path) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        completed = run_process([path.resolve()], timeout=timeout, context=ProcessContext(cwd=workdir))
    except ProcessTimeoutError:
        result: dict[str, Any] = {"status": "timeout"}
    except OSError as exc:
        result = {"status": "error", "error_type": type(exc).__name__}
    else:
        returncode = completed.returncode
        result = {
            "status": "completed",
            "returncode": returncode,
            "termination_signal": -returncode if os.name == "posix" and returncode < 0 else None,
            "stdout_size": len(completed.stdout),
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_size": len(completed.stderr),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        }
    result["created_files"] = _created_file_observations(workdir)
    return result


def _run_fixture(source: Path, destination: Path, seed: int, timeout: float, execution_root: Path) -> dict[str, Any]:
    shutil.copy2(source, destination)
    original = _execution_observation(source, timeout, execution_root / "original")
    try:
        with Binary(destination, writable=True) as binary:
            binary.analyze("aa")
            result = CodeVirtualizationPass(config={"probability": 1.0, "seed": seed}).apply(binary)
            binary.save()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return {"status": "error", "error_type": type(exc).__name__}

    functions_virtualized = result.get("functions_virtualized", 0)
    if not isinstance(functions_virtualized, int) or functions_virtualized < 1:
        return {
            "status": "not_virtualized",
            "functions_virtualized": functions_virtualized,
            "functions_skipped": result.get("functions_skipped", 0),
            "unsupported_functions": result.get("unsupported_functions_total", 0),
            "capabilities": result.get("unsupported_function_capabilities", {}),
        }
    mutated = _execution_observation(destination, timeout, execution_root / "mutated")
    if original != mutated:
        return {
            "status": "semantic_mismatch",
            "functions_virtualized": functions_virtualized,
            "original": original,
            "mutated": mutated,
        }
    return {
        "status": "passed",
        "functions_virtualized": functions_virtualized,
        "functions_skipped": result.get("functions_skipped", 0),
        "unsupported_functions": result.get("unsupported_functions_total", 0),
        "observables_equal": True,
        "original": original,
        "mutated": mutated,
    }


def run_campaign(
    dataset: Path,
    coverage: Mapping[str, set[str]],
    seed: int,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    fixture_names: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Virtualize each selected fixture and compare native observables."""
    selected_names = fixture_names or tuple(sorted(path.name for path in dataset.glob("elf_vm_*_x86_64")))
    fixtures = tuple(dataset / name for name in selected_names)
    if not fixtures:
        raise ValueError("VM semantic campaign selected no fixtures")
    if len(fixtures) > _MAX_FIXTURES:
        raise ValueError(f"VM semantic campaign exceeds fixture cap {_MAX_FIXTURES}")
    category_summary: dict[str, dict[str, int]] = {}
    failures: list[dict[str, Any]] = []
    fixture_results: list[dict[str, Any]] = []
    passed = 0
    with tempfile.TemporaryDirectory(prefix="r2morph-vm-semantic-") as temp_dir:
        for source in fixtures:
            if not source.is_file():
                failures.append({"fixture": source.name, "status": "missing"})
                continue
            categories = _fixture_categories(coverage, source.name)
            result = _run_fixture(
                source,
                Path(temp_dir) / source.name,
                seed,
                timeout,
                Path(temp_dir) / "execution" / source.name,
            )
            fixture_result = {"fixture": source.name, "categories": categories, **result}
            fixture_results.append(fixture_result)
            if result["status"] == "passed":
                passed += 1
            else:
                failures.append(fixture_result)
            for category in categories:
                stats = category_summary.setdefault(
                    category,
                    {"fixture_count": 0, "passed_count": 0, "failed_count": 0},
                )
                stats["fixture_count"] += 1
                stats["passed_count"] += result["status"] == "passed"
                stats["failed_count"] += result["status"] != "passed"
    return {
        "schema_version": 1,
        "measurement": "vm-semantic-native-parity-campaign",
        "target": _TARGET,
        "seed": seed,
        "fixture_count": len(fixtures),
        "passed_count": passed,
        "failed_count": len(failures),
        "status": "passed" if not failures else "failed",
        "category_summary": dict(sorted(category_summary.items())),
        "fixture_results": fixture_results,
        "failures": failures,
    }


def merge_campaign_reports(reports: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    """Aggregate deterministic seed runs without hiding a single failure."""
    if not reports:
        raise ValueError("at least one VM semantic campaign report is required")
    target = reports[0].get("target")
    seeds: list[int] = []
    category_summary: dict[str, dict[str, int]] = {}
    fixture_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    fixture_count = passed_count = failed_count = 0
    for report in reports:
        if report.get("target") != target:
            raise ValueError("VM semantic campaign reports have different targets")
        seed = report.get("seed")
        if not isinstance(seed, int) or seed in seeds:
            raise ValueError("VM semantic campaign reports must have unique integer seeds")
        seeds.append(seed)
        fixture_count += int(report["fixture_count"])
        passed_count += int(report["passed_count"])
        failed_count += int(report["failed_count"])
        for fixture_result in report.get("fixture_results", []):
            if isinstance(fixture_result, Mapping):
                fixture_results.append({"seed": seed, **fixture_result})
        for category, summary in report["category_summary"].items():
            aggregate = category_summary.setdefault(
                category,
                {"fixture_count": 0, "passed_count": 0, "failed_count": 0},
            )
            for field in ("fixture_count", "passed_count", "failed_count"):
                aggregate[field] += int(summary[field])
        failures.extend({"seed": seed, **failure} for failure in report["failures"])
    return {
        "schema_version": 1,
        "measurement": "vm-semantic-native-parity-campaign",
        "target": target,
        "seeds": seeds,
        "seed_count": len(seeds),
        "fixture_count": fixture_count,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "status": "passed" if not failures else "failed",
        "category_summary": dict(sorted(category_summary.items())),
        "fixture_results": fixture_results,
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--coverage", type=Path, default=Path("docs/virtualization-coverage.json"))
    parser.add_argument("--seed", type=int, action="append")
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seeds = tuple(args.seed or _DEFAULT_SEEDS)
    reports = tuple(run_campaign(args.dataset, _load_coverage(args.coverage), seed, args.timeout) for seed in seeds)
    report = reports[0] if len(reports) == 1 else merge_campaign_reports(reports)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"VM semantic campaign: {report['passed_count']}/{report['fixture_count']} passed")
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
