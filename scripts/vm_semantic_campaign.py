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
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any

from r2morph.adapters.process import ProcessContext, ProcessTimeoutError, run_process
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

if __package__:
    from scripts.protection_maturity_baseline import _qemu_semantic_artifacts, build_generated_corpus
else:
    from protection_maturity_baseline import _qemu_semantic_artifacts, build_generated_corpus

_MAX_FIXTURES = 512
_MAX_FIXTURE_SHARDS = 8
_DEFAULT_TIMEOUT_SECONDS = 5.0
# CodeVirtualizationPass uses the process-global random generator during codegen;
# serial workers keep each seeded campaign deterministic.
_CAMPAIGN_WORKERS = 1
_DEFAULT_SEEDS = (20260916, 20260917, 20260918)
_PASSABLE_FIXTURE_STATUSES = frozenset({"passed"})
_TARGET = {"os": "linux", "format": "ELF", "architecture": "x86-64"}
_MAX_CREATED_FILES = 256
_MAX_FUNCTION_ANALYSIS_COUNT = 2048
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_ERROR_MESSAGE_LENGTH = 240
_CAPABILITY_CATEGORIES = {
    "memory": ("memory_addressing",),
    "direct-calls": ("direct_calls",),
    "indirect-calls": ("indirect_calls",),
    "abi-varargs": ("abi_varargs",),
    "unwinding-exceptions": ("unwinding_exceptions",),
    "tls-signals": ("tls_accesses", "signals_and_system_calls"),
    "threads": ("thread_safety",),
    "fp-simd": ("floating_point_and_simd",),
    "ssa-liveness": ("ssa_liveness",),
}


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


def _corpus_fixture_counts(fixtures: tuple[Path, ...]) -> dict[str, int]:
    """Count repository and compiler-generated fixtures without retaining payloads."""
    return {
        "generated-corpus": sum(path.name.startswith("generated_") for path in fixtures),
        "repository-fixtures": sum(not path.name.startswith("generated_") for path in fixtures),
    }


def _capability_summary(category_summary: Mapping[str, Mapping[str, int]]) -> dict[str, dict[str, Any]]:
    """Expose each declared VM gap and its campaign-backed category evidence."""
    summary: dict[str, dict[str, Any]] = {}
    for capability, categories in _CAPABILITY_CATEGORIES.items():
        category_rows = [category_summary.get(category, {}) for category in categories]
        fixture_count = sum(int(row.get("fixture_count", 0)) for row in category_rows)
        passed_count = sum(int(row.get("passed_count", 0)) for row in category_rows)
        failed_count = sum(int(row.get("failed_count", 0)) for row in category_rows)
        if fixture_count == 0:
            status = "not-covered-by-fixture-campaign"
        elif fixture_count and failed_count == 0:
            status = "campaign-measured"
        else:
            status = "campaign-incomplete"
        summary[capability] = {
            "categories": list(categories),
            "fixture_count": fixture_count,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "status": status,
        }
    return summary


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


def _error_result(error: BaseException) -> dict[str, str]:
    message = str(error).replace("\n", " ").strip()
    return {
        "status": "error",
        "error_type": type(error).__name__,
        "error_message": message[:_MAX_ERROR_MESSAGE_LENGTH],
    }


def _unsupported_functions_result(
    result: Mapping[str, Any],
    functions_virtualized: int,
    original: dict[str, Any],
    mutated: dict[str, Any],
) -> dict[str, Any]:
    """Keep rejected functions visible even when native observables match."""
    return {
        "status": "passed_with_unsupported",
        "functions_virtualized": functions_virtualized,
        "functions_skipped": result.get("functions_skipped", 0),
        "unsupported_functions": result.get("unsupported_functions_total", 0),
        "unsupported_function_details": result.get("unsupported_functions", []),
        "unsupported_function_capabilities": result.get("unsupported_function_capabilities", {}),
        "observables_equal": original == mutated,
        "original": original,
        "mutated": mutated,
    }


def _not_virtualized_result(result: Mapping[str, Any], functions_virtualized: object) -> dict[str, Any]:
    """Record a fixture that produced no virtualized function."""
    return {
        "status": "not_virtualized",
        "functions_virtualized": functions_virtualized,
        "functions_skipped": result.get("functions_skipped", 0),
        "unsupported_functions": result.get("unsupported_functions_total", 0),
        "capabilities": result.get("unsupported_function_capabilities", {}),
    }


def _semantic_failure_result(
    result: Mapping[str, Any],
    functions_virtualized: int,
    original: dict[str, Any],
    mutated: dict[str, Any],
) -> dict[str, Any]:
    """Classify unsupported functions before falling back to parity mismatch."""
    observables_equal = original == mutated
    if result.get("unsupported_functions_total", 0) and observables_equal:
        return _unsupported_functions_result(result, functions_virtualized, original, mutated)
    return {
        "status": "semantic_mismatch",
        "functions_virtualized": functions_virtualized,
        "unsupported_functions": result.get("unsupported_functions_total", 0),
        "unsupported_function_details": result.get("unsupported_functions", []),
        "unsupported_function_capabilities": result.get("unsupported_function_capabilities", {}),
        "observables_equal": observables_equal,
        "original": original,
        "mutated": mutated,
    }


def _qemu_observables_equal(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    """Compare the independent oracle when both executions are available."""
    expected_status = expected.get("status")
    actual_status = actual.get("status")
    if expected_status == actual_status == "unavailable":
        return True
    if expected_status != "completed" or actual_status != "completed":
        return False
    return expected.get("exit_code") == actual.get("exit_code")


def _qemu_summary(fixture_results: list[dict[str, Any]]) -> dict[str, int | str]:
    completed = unavailable = divergent = missing = 0
    for row in fixture_results:
        evidence = row.get("qemu")
        if not isinstance(evidence, Mapping):
            missing += 1
            continue
        expected = evidence.get("original")
        actual = evidence.get("mutated")
        if not isinstance(expected, Mapping) or not isinstance(actual, Mapping):
            missing += 1
            continue
        if expected.get("status") == actual.get("status") == "completed":
            if evidence.get("observables_equal") is True:
                completed += 1
            else:
                divergent += 1
        elif expected.get("status") == actual.get("status") == "unavailable":
            unavailable += 1
        else:
            divergent += 1
    return {
        "oracle": "qemu-x86_64",
        "completed_pairs": completed,
        "unavailable_pairs": unavailable,
        "divergent_pairs": divergent,
        "missing_pairs": missing,
    }


def _run_fixture(source: Path, destination: Path, seed: int, timeout: float, execution_root: Path) -> dict[str, Any]:
    shutil.copy2(source, destination)
    original = _execution_observation(source, timeout, execution_root / "original")
    if original.get("status") != "completed":
        return {
            "status": "execution_unavailable",
            "functions_virtualized": 0,
            "original": original,
        }
    original_qemu = _qemu_semantic_artifacts(source)
    try:
        with Binary(destination, writable=True) as binary:
            binary.analyze("aa")
            result = CodeVirtualizationPass(
                config={
                    "probability": 1.0,
                    "seed": seed,
                    "max_function_analysis_count": _MAX_FUNCTION_ANALYSIS_COUNT,
                }
            ).apply(binary)
            binary.save()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _error_result(exc)

    functions_virtualized = result.get("functions_virtualized", 0)
    if not isinstance(functions_virtualized, int) or functions_virtualized < 1:
        return _not_virtualized_result(result, functions_virtualized)
    mutated = _execution_observation(destination, timeout, execution_root / "mutated")
    if mutated.get("status") != "completed":
        return {
            "status": "execution_unavailable",
            "functions_virtualized": functions_virtualized,
            "original": original,
            "mutated": mutated,
        }
    mutated_qemu = _qemu_semantic_artifacts(destination)
    qemu_evidence = {
        "original": original_qemu,
        "mutated": mutated_qemu,
        "observables_equal": _qemu_observables_equal(original_qemu, mutated_qemu),
    }
    unsupported_functions = result.get("unsupported_functions_total", 0)
    if unsupported_functions or original != mutated or not qemu_evidence["observables_equal"]:
        failure = _semantic_failure_result(result, functions_virtualized, original, mutated)
        failure["qemu"] = qemu_evidence
        return failure
    return {
        "status": "passed",
        "functions_virtualized": functions_virtualized,
        "functions_skipped": result.get("functions_skipped", 0),
        "unsupported_functions": unsupported_functions,
        "observables_equal": True,
        "original": original,
        "mutated": mutated,
        "qemu": qemu_evidence,
    }


def _run_selected_fixture(
    source: Path,
    temp_dir: Path,
    seed: int,
    timeout: float,
) -> tuple[Path, dict[str, Any]]:
    """Run one fixture with paths isolated from other workers."""
    result = _run_fixture(
        source,
        temp_dir / source.name,
        seed,
        timeout,
        temp_dir / "execution" / source.name,
    )
    return source, result


def _select_fixture_shard(
    fixtures: tuple[Path, ...],
    shard_index: int,
    shard_count: int,
) -> tuple[Path, ...]:
    """Select a deterministic, non-overlapping slice of the fixture corpus."""
    if shard_count < 1 or shard_count > _MAX_FIXTURE_SHARDS:
        raise ValueError(f"VM semantic fixture shard count must be between 1 and {_MAX_FIXTURE_SHARDS}")
    if shard_index < 0 or shard_index >= shard_count:
        raise ValueError("VM semantic fixture shard index must be within the shard count")
    selected = tuple(fixtures[shard_index::shard_count])
    if not selected:
        raise ValueError("VM semantic fixture shard selected no fixtures")
    return selected


def run_campaign(
    dataset: Path,
    coverage: Mapping[str, set[str]],
    seed: int,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    fixture_selection: tuple[str | Path, ...] | None = None,
) -> dict[str, Any]:
    """Virtualize each selected fixture and compare native observables."""
    if fixture_selection is None:
        selected_names = tuple(sorted(path.name for path in dataset.glob("elf_vm_*_x86_64")))
        fixtures = tuple(dataset / name for name in selected_names)
    elif all(isinstance(item, str) for item in fixture_selection):
        fixtures = tuple(dataset / item for item in fixture_selection)
    elif all(isinstance(item, Path) for item in fixture_selection):
        fixtures = tuple(fixture_selection)
    else:
        raise ValueError("VM semantic campaign fixture selection must contain names or paths")
    if not fixtures:
        raise ValueError("VM semantic campaign selected no fixtures")
    if len(fixtures) > _MAX_FIXTURES:
        raise ValueError(f"VM semantic campaign exceeds fixture cap {_MAX_FIXTURES}")
    category_summary: dict[str, dict[str, int]] = {}
    failures: list[dict[str, Any]] = []
    fixture_results: list[dict[str, Any]] = []
    passed = 0
    with tempfile.TemporaryDirectory(prefix="r2morph-vm-semantic-") as temp_dir:
        run_fixture = partial(
            _run_selected_fixture,
            temp_dir=Path(temp_dir),
            seed=seed,
            timeout=timeout,
        )
        with ThreadPoolExecutor(max_workers=_CAMPAIGN_WORKERS) as executor:
            results = executor.map(run_fixture, fixtures)
            for source, result in results:
                if not source.is_file():
                    failures.append({"fixture": source.name, "status": "missing"})
                    continue
                categories = _fixture_categories(coverage, source.name)
                fixture_result = {"fixture": source.name, "categories": categories, **result}
                fixture_results.append(fixture_result)
                if result["status"] in _PASSABLE_FIXTURE_STATUSES:
                    passed += 1
                else:
                    failures.append(fixture_result)
                for category in categories:
                    stats = category_summary.setdefault(
                        category,
                        {"fixture_count": 0, "passed_count": 0, "failed_count": 0},
                    )
                    stats["fixture_count"] += 1
                    stats["passed_count"] += result["status"] in _PASSABLE_FIXTURE_STATUSES
                    stats["failed_count"] += result["status"] not in _PASSABLE_FIXTURE_STATUSES
    return {
        "schema_version": 1,
        "measurement": "vm-semantic-native-parity-campaign",
        "target": _TARGET,
        "seed": seed,
        "fixture_count": len(fixtures),
        "corpus_fixture_counts": _corpus_fixture_counts(fixtures),
        "passed_count": passed,
        "failed_count": len(failures),
        "status": "passed" if not failures else "failed",
        "category_summary": dict(sorted(category_summary.items())),
        "capability_summary": _capability_summary(category_summary),
        "qemu_summary": _qemu_summary(fixture_results),
        "fixture_results": fixture_results,
        "failures": failures,
    }


def merge_campaign_reports(
    reports: tuple[dict[str, Any], ...],
    allow_duplicate_seeds: bool = False,
) -> dict[str, Any]:
    """Aggregate deterministic seed runs without hiding a single failure."""
    if not reports:
        raise ValueError("at least one VM semantic campaign report is required")
    target = reports[0].get("target")
    seeds: list[int] = []
    fixture_keys: set[tuple[int, str]] = set()
    category_summary: dict[str, dict[str, int]] = {}
    fixture_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    fixture_count = passed_count = failed_count = 0
    corpus_fixture_counts = {"generated-corpus": 0, "repository-fixtures": 0}
    for report in reports:
        if report.get("target") != target:
            raise ValueError("VM semantic campaign reports have different targets")
        seed = report.get("seed")
        if not isinstance(seed, int) or (seed in seeds and not allow_duplicate_seeds):
            raise ValueError("VM semantic campaign reports must have unique integer seeds")
        seeds.append(seed)
        fixture_count += int(report["fixture_count"])
        for family, count in report.get("corpus_fixture_counts", {}).items():
            if family in corpus_fixture_counts:
                corpus_fixture_counts[family] += int(count)
        passed_count += int(report["passed_count"])
        failed_count += int(report["failed_count"])
        for fixture_result in report.get("fixture_results", []):
            if isinstance(fixture_result, Mapping):
                fixture_name = fixture_result.get("fixture")
                if not isinstance(fixture_name, str):
                    raise ValueError("VM semantic campaign fixture result is missing its name")
                fixture_key = (seed, fixture_name)
                if fixture_key in fixture_keys:
                    raise ValueError(f"VM semantic campaign fixture overlap: {fixture_key}")
                fixture_keys.add(fixture_key)
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
        "seeds": list(dict.fromkeys(seeds)),
        "seed_count": len(dict.fromkeys(seeds)),
        "fixture_count": fixture_count,
        "corpus_fixture_counts": corpus_fixture_counts,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "status": "passed" if not failures else "failed",
        "category_summary": dict(sorted(category_summary.items())),
        "capability_summary": _capability_summary(category_summary),
        "qemu_summary": _qemu_summary(fixture_results),
        "fixture_results": fixture_results,
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--coverage", type=Path, default=Path("docs/virtualization-coverage.json"))
    parser.add_argument("--seed", type=int, action="append")
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--generated-corpus",
        action="store_true",
        help="compile and include the reproducible Linux ELF x86-64 C/C++ corpus",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture-shard-index", type=int, default=0)
    parser.add_argument("--fixture-shard-count", type=int, default=1)
    args = parser.parse_args()
    seeds = tuple(args.seed or _DEFAULT_SEEDS)
    coverage = _load_coverage(args.coverage)
    with tempfile.TemporaryDirectory(prefix="r2morph-vm-semantic-corpus-") as temp_dir:
        fixtures = tuple(sorted(args.dataset.glob("elf_vm_*_x86_64")))
        if args.generated_corpus:
            fixtures += tuple(build_generated_corpus(Path(temp_dir) / "generated-corpus"))
        if args.fixture_shard_count > 1:
            fixtures = _select_fixture_shard(
                fixtures,
                args.fixture_shard_index,
                args.fixture_shard_count,
            )
        reports = tuple(
            run_campaign(
                args.dataset,
                coverage,
                seed,
                args.timeout,
                fixture_selection=fixtures,
            )
            for seed in seeds
        )
    report = reports[0] if len(reports) == 1 else merge_campaign_reports(reports)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"VM semantic campaign: {report['passed_count']}/{report['fixture_count']} passed")
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
