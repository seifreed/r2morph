#!/usr/bin/env python3
"""Run bounded native parity checks for the VM semantic fixture corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from r2morph.adapters.process import ProcessTimeoutError, run_process
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

_MAX_FIXTURES = 256
_DEFAULT_TIMEOUT_SECONDS = 5.0
_TARGET = {"os": "linux", "format": "ELF", "architecture": "x86-64"}


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


def _execution_observation(path: Path, timeout: float) -> dict[str, Any]:
    try:
        completed = run_process([path], timeout=timeout)
    except ProcessTimeoutError:
        return {"status": "timeout"}
    except OSError as exc:
        return {"status": "error", "error_type": type(exc).__name__}
    return {
        "status": "completed",
        "returncode": completed.returncode,
        "stdout_size": len(completed.stdout),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_size": len(completed.stderr),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def _run_fixture(source: Path, destination: Path, seed: int, timeout: float) -> dict[str, Any]:
    shutil.copy2(source, destination)
    original = _execution_observation(source, timeout)
    try:
        with Binary(destination, writable=True) as binary:
            binary.analyze("aa")
            result = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1, "seed": seed}).apply(binary)
            binary.save()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return {"status": "error", "error_type": type(exc).__name__}

    if result.get("functions_virtualized") != 1:
        return {
            "status": "not_virtualized",
            "capabilities": result.get("unsupported_function_capabilities", {}),
        }
    mutated = _execution_observation(destination, timeout)
    if original != mutated:
        return {"status": "semantic_mismatch", "original": original, "mutated": mutated}
    return {"status": "passed"}


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
    passed = 0
    with tempfile.TemporaryDirectory(prefix="r2morph-vm-semantic-") as temp_dir:
        for source in fixtures:
            if not source.is_file():
                failures.append({"fixture": source.name, "status": "missing"})
                continue
            categories = _fixture_categories(coverage, source.name)
            result = _run_fixture(source, Path(temp_dir) / source.name, seed, timeout)
            if result["status"] == "passed":
                passed += 1
            else:
                failures.append({"fixture": source.name, "categories": categories, **result})
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
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--coverage", type=Path, default=Path("docs/virtualization-coverage.json"))
    parser.add_argument("--seed", type=int, default=20260916)
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_campaign(args.dataset, _load_coverage(args.coverage), args.seed, args.timeout)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"VM semantic campaign: {report['passed_count']}/{report['fixture_count']} passed")
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
