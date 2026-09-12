#!/usr/bin/env python3
"""Record reproducible corpus, runtime, and virtualization measurements."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import shlex
import shutil
import struct
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.core.binary import Binary
from r2morph.mutations import (
    BlockReorderingPass,
    ConstantUnfoldingPass,
    ControlFlowFlatteningPass,
    DeadCodeInjectionPass,
    InstructionExpansionPass,
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)
from r2morph.mutations.base import MutationPass
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass
from tests.integration.elf_emulator import emulate_exit_code

_ELF_MAGIC = b"\x7fELF"
_ET_EXEC = 2
_ET_DYN = 3
_EM_X86_64 = 62
_ELFCLASS64 = 2
_BITS_64 = 64
_ELF_IDENT_HEADER_BYTES = 20
_RUNTIME_TIMEOUT_SECONDS = 5.0
_PREVIEW_BYTES = 32
_FULL_COVERAGE_PERCENT = 100.0
DEFAULT_MUTATION_NAME = "CodeVirtualization"
CORPUS_PASS_NAMES = (
    "BlockReordering",
    "CodeVirtualization",
    "ConstantUnfolding",
    "ControlFlowFlattening",
    "DeadCodeInjection",
    "InstructionExpansion",
    "InstructionSubstitution",
    "NopInsertion",
    "PatternSubstitution",
    "RegisterSubstitution",
)
_PASS_TYPES: dict[str, type[MutationPass]] = {
    "BlockReordering": BlockReorderingPass,
    "CodeVirtualization": CodeVirtualizationPass,
    "ConstantUnfolding": ConstantUnfoldingPass,
    "ControlFlowFlattening": ControlFlowFlatteningPass,
    "DeadCodeInjection": DeadCodeInjectionPass,
    "InstructionExpansion": InstructionExpansionPass,
    "InstructionSubstitution": InstructionSubstitutionPass,
    "NopInsertion": NopInsertionPass,
    "PatternSubstitution": PatternSubstitutionPass,
    "RegisterSubstitution": RegisterSubstitutionPass,
}
_PASS_LABELS = {
    "BlockReordering": "block-reordering",
    "CodeVirtualization": "code-virtualization",
    "ConstantUnfolding": "constant-unfolding",
    "ControlFlowFlattening": "control-flow-flattening",
    "DeadCodeInjection": "dead-code-injection",
    "InstructionExpansion": "instruction-expansion",
    "InstructionSubstitution": "instruction-substitution",
    "NopInsertion": "nop-insertion",
    "PatternSubstitution": "pattern-substitution",
    "RegisterSubstitution": "register-substitution",
}


class _ArtifactAccumulator:
    """Hash a process stream incrementally while retaining only its preview."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._preview = bytearray()
        self._size = 0

    def update(self, chunk: bytes) -> None:
        self._digest.update(chunk)
        self._size += len(chunk)
        remaining = _PREVIEW_BYTES - len(self._preview)
        if remaining > 0:
            self._preview.extend(chunk[:remaining])

    def result(self) -> dict[str, object]:
        return {
            "sha256": self._digest.hexdigest(),
            "size": self._size,
            "preview_hex": bytes(self._preview).hex(),
        }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_artifact(value: bytes) -> dict[str, object]:
    accumulator = _ArtifactAccumulator()
    accumulator.update(value)
    return accumulator.result()


def _snapshot_created_files(directory: Path) -> dict[str, dict[str, object]]:
    """Return bounded hashes and sizes for files created in a runtime directory."""
    files: dict[str, dict[str, object]] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != "program":
            files[path.relative_to(directory).as_posix()] = {
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
    return files


def _runtime_command(path: Path) -> list[str]:
    with path.open("rb") as handle:
        first_line = handle.readline(4096)
    if not first_line.startswith(b"#!"):
        return [str(path)]
    interpreter = shlex.split(first_line[2:].decode("utf-8", errors="replace"))
    return [*interpreter, str(path)] if interpreter else [str(path)]


async def _capture_runtime_stream(stream: asyncio.StreamReader) -> dict[str, object]:
    accumulator = _ArtifactAccumulator()
    while chunk := await stream.read(4096):
        accumulator.update(chunk)
    return accumulator.result()


async def _run_runtime(command: list[str], workdir: Path) -> dict[str, object]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as error:
        return {
            "status": "error",
            "error_type": type(error).__name__,
            "stdout": _digest_artifact(b""),
            "stderr": _digest_artifact(b""),
        }
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("Runtime process did not expose captured streams")
    stdout_task = asyncio.create_task(_capture_runtime_stream(process.stdout))
    stderr_task = asyncio.create_task(_capture_runtime_stream(process.stderr))
    try:
        return_code = await asyncio.wait_for(process.wait(), _RUNTIME_TIMEOUT_SECONDS)
    except TimeoutError:
        process.kill()
        await process.wait()
        await asyncio.gather(stdout_task, stderr_task)
        return {"status": "timeout", "stdout": stdout_task.result(), "stderr": stderr_task.result()}
    stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
    return {"status": "completed", "return_code": return_code, "stdout": stdout, "stderr": stderr}


def _runtime_artifacts(path: Path) -> dict[str, object]:
    """Run a fixture in isolation and retain bounded, reproducible observables."""
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r2morph-runtime-") as temporary:
        workdir = Path(temporary)
        runtime_path = workdir / "program"
        shutil.copyfile(path, runtime_path)
        runtime_path.chmod(0o700)
        result = asyncio.run(_run_runtime(_runtime_command(runtime_path), workdir))
        result["duration_seconds"] = time.perf_counter() - started
        result["created_files"] = _snapshot_created_files(workdir)
        return result


def _command_count(binary: Binary, command: str) -> int:
    value = binary.r2.cmdj(command)
    return len(value) if isinstance(value, list) else 0


def _static_metrics(binary: Binary) -> dict[str, object]:
    started = time.perf_counter()
    binary.analyze("aa")
    functions = binary.get_functions()
    basic_blocks = 0
    cfg_edges = 0
    instructions = 0
    for function in functions:
        address = function.get("addr")
        if not isinstance(address, int):
            continue
        blocks = binary.get_basic_blocks(address)
        basic_blocks += len(blocks)
        cfg_edges += sum(
            1
            for block in blocks
            for edge_name in ("jump", "fail")
            if isinstance(block.get(edge_name), int) and block[edge_name] >= 0
        )
        instructions += len(binary.get_function_disasm(address))

    info = binary.info.get("bin", {})
    raw_arch = str(info.get("arch", "unknown"))
    bits = int(info.get("bits", 0) or 0)
    architecture = "x86_64" if raw_arch in {"x86", "x64"} and bits == _BITS_64 else raw_arch
    return {
        "format": str(info.get("bintype", "unknown")).upper(),
        "architecture": architecture,
        "bits": bits,
        "number_of_functions": len(functions),
        "number_of_basic_blocks": basic_blocks,
        "number_of_cfg_edges": cfg_edges,
        "number_of_instructions": instructions,
        "number_of_strings": _command_count(binary, "izj"),
        "number_of_imports": _command_count(binary, "iij"),
        "number_of_references": _command_count(binary, "axlj"),
        "analysis_duration_seconds": time.perf_counter() - started,
    }


def _inspect(path: Path) -> dict[str, object]:
    binary = Binary(path)
    binary.open()
    try:
        return _static_metrics(binary)
    finally:
        binary.close()


def _safe_inspect(path: Path) -> dict[str, object]:
    try:
        return {"status": "completed", "metrics": _inspect(path)}
    except Exception as error:  # Measurement boundary records per-artifact failures.
        return {"status": "error", "error_type": type(error).__name__}


def _semantic_artifacts(path: Path) -> dict[str, object]:
    started = time.perf_counter()
    try:
        exit_code = emulate_exit_code(path)
    except Exception as error:  # Measurement boundary records emulator failures per artifact.
        return {
            "status": "error",
            "error_type": type(error).__name__,
            "error": str(error),
            "duration_seconds": time.perf_counter() - started,
        }
    return {
        "status": "completed" if exit_code is not None else "no_exit_syscall",
        "exit_code": exit_code,
        "duration_seconds": time.perf_counter() - started,
    }


def _runtime_observables_equal(expected: object, actual: object) -> bool:
    """Compare bounded native-runtime observables without retaining raw output."""
    if (
        not isinstance(expected, Mapping)
        or not isinstance(actual, Mapping)
        or expected.get("status") != "completed"
        or actual.get("status") != "completed"
    ):
        return False
    for field in ("status", "return_code", "error_type"):
        if expected.get(field) != actual.get(field):
            return False
    for stream in ("stdout", "stderr"):
        expected_digest = expected.get(stream)
        actual_digest = actual.get(stream)
        if not isinstance(expected_digest, Mapping) or not isinstance(actual_digest, Mapping):
            return False
        if expected_digest.get("sha256") != actual_digest.get("sha256"):
            return False
        if expected_digest.get("size") != actual_digest.get("size"):
            return False
    return expected.get("created_files") == actual.get("created_files")


def _semantic_run_matches(baseline: object, baseline_runtime: object, run: object) -> bool:
    """Require native runtime parity and use emulation when it supports both files."""
    if not isinstance(baseline, Mapping) or not isinstance(baseline_runtime, Mapping):
        return False
    if not isinstance(run, Mapping) or run.get("status") != "passed":
        return False
    if not _runtime_observables_equal(baseline_runtime, run.get("runtime")):
        return False
    unicorn = run.get("unicorn")
    if baseline.get("status") == "completed" and isinstance(unicorn, Mapping) and unicorn.get("status") == "completed":
        return unicorn.get("exit_code") == baseline.get("exit_code")
    return True


def _build_mutation_pass(pass_name: str, seed: int) -> MutationPass:
    pass_type = _PASS_TYPES.get(pass_name)
    if pass_type is None:
        raise ValueError(f"unsupported corpus pass: {pass_name}")
    return pass_type(config={"probability": 1.0, "seed": seed})


def _transformation_evidence(
    status: str,
    stats: object,
    error: object = None,
    pass_name: str = DEFAULT_MUTATION_NAME,
) -> dict[str, object]:
    """Describe whether the selected pass changed the fixture and why not."""
    label = _PASS_LABELS[pass_name]
    if status == "error":
        if isinstance(error, Mapping):
            reason = error.get("error") or error.get("error_type") or "transformation failed"
        else:
            reason = "transformation failed"
        return {"pass_name": label, "status": "error", "reason": str(reason)}

    if not isinstance(stats, Mapping):
        return {"pass_name": label, "status": "omitted", "reason": "no pass statistics"}
    virtualized = stats.get("functions_virtualized")
    applied = virtualized if isinstance(virtualized, int) and virtualized > 0 else stats.get("mutations_applied")
    if isinstance(applied, int) and applied > 0:
        count_field = "functions_virtualized" if pass_name == DEFAULT_MUTATION_NAME else "mutations_applied"
        return {
            "pass_name": label,
            "status": "applied",
            count_field: applied,
        }
    diagnostics = stats.get("unsupported_functions")
    if isinstance(diagnostics, list) and diagnostics and isinstance(diagnostics[0], Mapping):
        capability = diagnostics[0].get("capability", "unsupported capability")
        reason = diagnostics[0].get("reason", "pass precondition was not met")
        evidence = {
            "pass_name": label,
            "status": "omitted",
            "reason": f"{capability}: {reason}",
        }
        severity = diagnostics[0].get("severity")
        if isinstance(severity, str) and severity:
            evidence["severity"] = severity
        return evidence
    return {
        "pass_name": label,
        "status": "omitted",
        "reason": "no eligible function was transformed",
    }


def _measure_seed(fixture: Path, seed: int, output_dir: Path, pass_name: str) -> dict[str, object]:
    output = output_dir / f"seed-{seed}"
    shutil.copyfile(fixture, output)
    started = time.perf_counter()
    try:
        binary = Binary(output, writable=True)
        binary.open()
        try:
            stats = _build_mutation_pass(pass_name, seed).apply(binary)
            binary.save()
        finally:
            binary.close()
        status = "passed"
        error: dict[str, object] = {}
    except Exception as error_value:  # Measurement boundary records per-fixture failures.
        stats = {}
        status = "error"
        error = {"error_type": type(error_value).__name__, "error": str(error_value)}

    run: dict[str, object] = {
        "seed": seed,
        "status": status,
        "transformation": _transformation_evidence(status, stats, error if status == "error" else None, pass_name),
        "output_sha256": sha256(output),
        "output_size": output.stat().st_size,
        "transform_duration_seconds": time.perf_counter() - started,
        "runtime": _runtime_artifacts(output),
        "unicorn": _semantic_artifacts(output),
    }
    if status == "passed":
        run.update(
            {
                "functions_virtualized": stats.get("functions_virtualized", 0),
                "mutations_applied": stats.get("mutations_applied", 0),
                "total_instructions": stats.get("total_instructions", 0),
                "total_bytecode_bytes": stats.get("total_bytecode_bytes", 0),
                "after": _safe_inspect(output),
            }
        )
    else:
        run["error"] = error
    return run


def measure_fixture(
    fixture: Path,
    seeds: range,
    output_root: Path,
    pass_name: str = DEFAULT_MUTATION_NAME,
) -> dict[str, object]:
    baseline_runtime = _runtime_artifacts(fixture)
    baseline_unicorn = _semantic_artifacts(fixture)
    baseline = _safe_inspect(fixture)
    output_dir = output_root / _PASS_LABELS[pass_name] / fixture.name
    output_dir.mkdir(parents=True)
    runs = [_measure_seed(fixture, seed, output_dir, pass_name) for seed in seeds]
    semantic_runs = []
    for run in runs:
        runtime_equal = _runtime_observables_equal(baseline_runtime, run.get("runtime"))
        run["runtime_observable_equal"] = runtime_equal
        if _semantic_run_matches(baseline_unicorn, baseline_runtime, run):
            semantic_runs.append(run)
    return {
        "sample": fixture.name,
        "baseline_sha256": sha256(fixture),
        "baseline_size": fixture.stat().st_size,
        "baseline": baseline,
        "baseline_runtime": baseline_runtime,
        "baseline_unicorn": baseline_unicorn,
        "seeds": [run["seed"] for run in runs],
        "runs": runs,
        "all_semantic_equal": bool(runs) and len(semantic_runs) == len(runs),
        "successful_runs": len(semantic_runs),
        "failed_runs": len(runs) - len(semantic_runs),
    }


def discover_executables(dataset: Path) -> list[Path]:
    """Return supported ELF executable files, excluding source and relocatable objects."""
    executables: list[Path] = []
    for path in sorted(dataset.iterdir()):
        if not path.is_file():
            continue
        header = path.read_bytes()[:_ELF_IDENT_HEADER_BYTES]
        if len(header) < _ELF_IDENT_HEADER_BYTES or header[:4] != _ELF_MAGIC or header[4] != _ELFCLASS64:
            continue
        elf_type, machine = struct.unpack_from("<HH", header, 16)
        if elf_type in {_ET_EXEC, _ET_DYN} and machine == _EM_X86_64:
            executables.append(path)
    return executables


def _static_metric_deltas(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    deltas: dict[str, int] = {}
    for fixture, run in seed_runs:
        baseline = fixture.get("baseline")
        after = run.get("after")
        if not isinstance(baseline, Mapping) or not isinstance(after, Mapping):
            continue
        baseline_metrics = baseline.get("metrics")
        after_metrics = after.get("metrics")
        if not isinstance(baseline_metrics, Mapping) or not isinstance(after_metrics, Mapping):
            continue
        for key, baseline_value in baseline_metrics.items():
            after_value = after_metrics.get(key)
            if key.startswith("number_of_") and isinstance(baseline_value, int) and isinstance(after_value, int):
                deltas[f"total_static_{key}_delta"] = deltas.get(f"total_static_{key}_delta", 0) + (
                    after_value - baseline_value
                )
    return deltas


def _has_static_metrics(value: object) -> bool:
    return (
        isinstance(value, Mapping) and value.get("status") == "completed" and isinstance(value.get("metrics"), Mapping)
    )


def _static_metric_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if _has_static_metrics(fixture.get("baseline")) and _has_static_metrics(run.get("after"))
    )
    return {
        "static_metric_complete_runs": complete,
        "static_metric_missing_runs": len(seed_runs) - complete,
    }


def _has_completed_runtime(value: object) -> bool:
    return isinstance(value, Mapping) and value.get("status") == "completed"


def _runtime_observable_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if _has_completed_runtime(fixture.get("baseline_runtime")) and _has_completed_runtime(run.get("runtime"))
    )
    return {
        "runtime_observable_complete_runs": complete,
        "runtime_observable_missing_runs": len(seed_runs) - complete,
    }


def _numeric_metric_coverage(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]],
    summary_prefix: str,
    baseline_field: str | None,
    run_field: str,
) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if (baseline_field is None or isinstance(fixture.get(baseline_field), int | float))
        and isinstance(run.get(run_field), int | float)
    )
    return {
        f"{summary_prefix}_complete_runs": complete,
        f"{summary_prefix}_missing_runs": len(seed_runs) - complete,
    }


def _runtime_duration_coverage(seed_runs: list[tuple[dict[str, object], Mapping[str, object]]]) -> dict[str, int]:
    complete = sum(
        1
        for fixture, run in seed_runs
        if isinstance(baseline_runtime := fixture.get("baseline_runtime"), Mapping)
        and isinstance(runtime := run.get("runtime"), Mapping)
        and isinstance(baseline_runtime.get("duration_seconds"), int | float)
        and isinstance(runtime.get("duration_seconds"), int | float)
    )
    return {
        "runtime_duration_complete_runs": complete,
        "runtime_duration_missing_runs": len(seed_runs) - complete,
    }


def _coverage_percent(complete: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(complete / total * 100.0, 2)


def _transformation_reason_counts(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]], status: str
) -> dict[str, int]:
    reasons: dict[str, int] = {}
    for _, run in seed_runs:
        transformation = run.get("transformation")
        if not isinstance(transformation, Mapping) or transformation.get("status") != status:
            continue
        reason = str(transformation.get("reason", "unspecified"))
        reasons[reason] = reasons.get(reason, 0) + 1
    return dict(sorted(reasons.items()))


def _transformation_severity_counts(
    seed_runs: list[tuple[dict[str, object], Mapping[str, object]]], status: str
) -> dict[str, int]:
    severities: dict[str, int] = {}
    for _, run in seed_runs:
        transformation = run.get("transformation")
        if not isinstance(transformation, Mapping) or transformation.get("status") != status:
            continue
        severity = transformation.get("severity")
        if isinstance(severity, str) and severity:
            severities[severity] = severities.get(severity, 0) + 1
    return dict(sorted(severities.items()))


def _render_result(fixtures: list[dict[str, object]], pass_name: str = DEFAULT_MUTATION_NAME) -> dict[str, object]:
    seed_runs = [(fixture, run) for fixture in fixtures for run in fixture.get("runs", []) if isinstance(run, Mapping)]
    successful_seed_runs = sum(
        value if isinstance(value := fixture.get("successful_runs"), int) else 0 for fixture in fixtures
    )
    failed_seed_runs = sum(value if isinstance(value := fixture.get("failed_runs"), int) else 0 for fixture in fixtures)
    applied_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping)
        and transformation.get("status") == "applied"
    )
    omitted_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping)
        and transformation.get("status") == "omitted"
    )
    error_runs = sum(
        1
        for _, run in seed_runs
        if isinstance(transformation := run.get("transformation"), Mapping) and transformation.get("status") == "error"
    )
    output_size_delta_bytes = sum(
        run["output_size"] - fixture["baseline_size"]
        for fixture, run in seed_runs
        if isinstance(fixture.get("baseline_size"), int) and isinstance(run.get("output_size"), int)
    )
    transform_duration_seconds = sum(
        duration for _, run in seed_runs if isinstance(duration := run.get("transform_duration_seconds"), int | float)
    )
    runtime_duration_delta_seconds = sum(
        runtime["duration_seconds"] - baseline_runtime["duration_seconds"]
        for fixture, run in seed_runs
        if isinstance(baseline_runtime := fixture.get("baseline_runtime"), Mapping)
        and isinstance(runtime := run.get("runtime"), Mapping)
        and isinstance(baseline_runtime.get("duration_seconds"), int | float)
        and isinstance(runtime.get("duration_seconds"), int | float)
    )
    runtime_observable_passes = sum(1 for _, run in seed_runs if run.get("runtime_observable_equal") is True)
    runtime_observable_failures = sum(1 for _, run in seed_runs if run.get("runtime_observable_equal") is False)
    output_size_deltas = tuple(
        run["output_size"] - fixture["baseline_size"]
        for fixture, run in seed_runs
        if isinstance(fixture.get("baseline_size"), int) and isinstance(run.get("output_size"), int)
    )
    runtime_observable_coverage = _runtime_observable_coverage(seed_runs)
    output_size_coverage = _numeric_metric_coverage(seed_runs, "output_size", "baseline_size", "output_size")
    transform_duration_coverage = _numeric_metric_coverage(
        seed_runs,
        "transform_duration",
        None,
        "transform_duration_seconds",
    )
    runtime_duration_coverage = _runtime_duration_coverage(seed_runs)
    static_metric_deltas = _static_metric_deltas(seed_runs)
    static_metric_coverage = _static_metric_coverage(seed_runs)
    seed_run_count = len(seed_runs)
    omission_reasons = _transformation_reason_counts(seed_runs, "omitted")
    error_reasons = _transformation_reason_counts(seed_runs, "error")
    omission_severities = _transformation_severity_counts(seed_runs, "omitted")
    error_severities = _transformation_severity_counts(seed_runs, "error")
    return {
        "schema_version": 2,
        "measurement": "protection-maturity-corpus",
        "pass_name": pass_name,
        "compatible_fixture_count": len(fixtures),
        "fixtures": fixtures,
        "summary": {
            "semantic_passes": sum(1 for fixture in fixtures if fixture["all_semantic_equal"]),
            "semantic_failures": sum(1 for fixture in fixtures if not fixture["all_semantic_equal"]),
            "successful_seed_runs": successful_seed_runs,
            "failed_seed_runs": failed_seed_runs,
            "applied_runs": applied_runs,
            "omitted_runs": omitted_runs,
            "error_runs": error_runs,
            "runtime_observable_passes": runtime_observable_passes,
            "runtime_observable_failures": runtime_observable_failures,
            **runtime_observable_coverage,
            "runtime_observable_coverage_percent": _coverage_percent(
                runtime_observable_coverage["runtime_observable_complete_runs"],
                seed_run_count,
            ),
            **output_size_coverage,
            "output_size_coverage_percent": _coverage_percent(
                output_size_coverage["output_size_complete_runs"],
                seed_run_count,
            ),
            "total_output_size_delta_bytes": output_size_delta_bytes,
            "max_output_size_delta_bytes": max(output_size_deltas, default=0),
            "min_output_size_delta_bytes": min(output_size_deltas, default=0),
            **transform_duration_coverage,
            "transform_duration_coverage_percent": _coverage_percent(
                transform_duration_coverage["transform_duration_complete_runs"],
                seed_run_count,
            ),
            "total_transform_duration_seconds": transform_duration_seconds,
            **runtime_duration_coverage,
            "runtime_duration_coverage_percent": _coverage_percent(
                runtime_duration_coverage["runtime_duration_complete_runs"],
                seed_run_count,
            ),
            "total_runtime_duration_delta_seconds": runtime_duration_delta_seconds,
            "omission_reasons": omission_reasons,
            "error_reasons": error_reasons,
            "omission_severities": omission_severities,
            "error_severities": error_severities,
            **static_metric_coverage,
            "static_metric_coverage_percent": _coverage_percent(
                static_metric_coverage["static_metric_complete_runs"],
                seed_run_count,
            ),
            **static_metric_deltas,
        },
    }


def _parse_pass_names(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "all":
        return CORPUS_PASS_NAMES
    names = tuple(item.strip() for item in value.split(",") if item.strip())
    if not names or any(name not in _PASS_TYPES for name in names):
        valid = ", ".join((*CORPUS_PASS_NAMES, "all"))
        raise ValueError(f"unknown pass in {value!r}; choose from {valid}")
    if len(set(names)) != len(names):
        raise ValueError("--passes must not contain duplicates")
    return names


def _render_multi_pass_result(
    measurements: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
    rendered = {name: _render_result(fixtures, name) for name, fixtures in measurements.items()}
    summaries = {name: result["summary"] for name, result in rendered.items()}
    return {
        "schema_version": 3,
        "measurement": "protection-maturity-corpus-by-pass",
        "pass_names": list(rendered),
        "passes": rendered,
        "summary": summaries,
        "campaign_summary": _multi_pass_campaign_summary(summaries),
    }


def _average_percent(summaries: dict[str, object], field: str) -> float:
    values = [
        summary[field]
        for summary in summaries.values()
        if isinstance(summary, dict) and isinstance(summary.get(field), int | float)
    ]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def _sum_summary_field(summaries: dict[str, object], field: str) -> int:
    return sum(
        value
        for summary in summaries.values()
        if isinstance(summary, dict) and isinstance(value := summary.get(field), int)
    )


def _multi_pass_campaign_summary(summaries: dict[str, object]) -> dict[str, object]:
    return {
        "pass_count": len(summaries),
        "passes_without_applied_runs": _passes_with_zero_runs(summaries, "applied_runs"),
        "passes_with_omitted_runs": _passes_with_positive_runs(summaries, "omitted_runs"),
        "passes_with_error_runs": _passes_with_positive_runs(summaries, "error_runs"),
        "passes_with_incomplete_coverage": _passes_with_incomplete_coverage(summaries),
        "passes_with_semantic_failures": _passes_with_positive_runs(summaries, "semantic_failures"),
        "passes_with_runtime_observable_failures": _passes_with_positive_runs(
            summaries,
            "runtime_observable_failures",
        ),
        "omission_reasons_by_pass": _reason_map_by_pass(summaries, "omission_reasons"),
        "error_reasons_by_pass": _reason_map_by_pass(summaries, "error_reasons"),
        "total_applied_runs": _sum_summary_field(summaries, "applied_runs"),
        "total_omitted_runs": _sum_summary_field(summaries, "omitted_runs"),
        "total_error_runs": _sum_summary_field(summaries, "error_runs"),
        "average_runtime_observable_coverage_percent": _average_percent(
            summaries,
            "runtime_observable_coverage_percent",
        ),
        "average_output_size_coverage_percent": _average_percent(summaries, "output_size_coverage_percent"),
        "average_transform_duration_coverage_percent": _average_percent(
            summaries,
            "transform_duration_coverage_percent",
        ),
        "average_runtime_duration_coverage_percent": _average_percent(
            summaries,
            "runtime_duration_coverage_percent",
        ),
        "average_static_metric_coverage_percent": _average_percent(summaries, "static_metric_coverage_percent"),
    }


def _passes_with_zero_runs(summaries: dict[str, object], field: str) -> list[str]:
    return sorted(name for name, summary in summaries.items() if isinstance(summary, dict) and summary.get(field) == 0)


def _passes_with_positive_runs(summaries: dict[str, object], field: str) -> list[str]:
    return sorted(
        name
        for name, summary in summaries.items()
        if isinstance(summary, dict) and isinstance(value := summary.get(field), int) and value > 0
    )


def _reason_map_by_pass(summaries: dict[str, object], field: str) -> dict[str, dict[str, int]]:
    return {
        name: dict(sorted(reasons.items()))
        for name, summary in summaries.items()
        if isinstance(summary, dict)
        and isinstance(reasons := summary.get(field), dict)
        and reasons
        and all(isinstance(reason, str) and isinstance(count, int) for reason, count in reasons.items())
    }


def _passes_with_incomplete_coverage(summaries: dict[str, object]) -> dict[str, list[str]]:
    fields = {
        "runtime_observable": "runtime_observable_coverage_percent",
        "output_size": "output_size_coverage_percent",
        "transform_duration": "transform_duration_coverage_percent",
        "runtime_duration": "runtime_duration_coverage_percent",
        "static_metric": "static_metric_coverage_percent",
    }
    incomplete: dict[str, list[str]] = {}
    for name, field in fields.items():
        passes = _passes_below_full_coverage(summaries, field)
        if passes:
            incomplete[name] = passes
    return incomplete


def _passes_below_full_coverage(summaries: dict[str, object], field: str) -> list[str]:
    return sorted(
        name
        for name, summary in summaries.items()
        if isinstance(summary, dict)
        and isinstance(value := summary.get(field), int | float)
        and value < _FULL_COVERAGE_PERCENT
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", nargs="*", type=Path)
    parser.add_argument("--all", action="store_true", dest="all_fixtures")
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument("--first-seed", type=int, default=20260820)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument(
        "--passes",
        default=DEFAULT_MUTATION_NAME,
        help="comma-separated pass names or 'all' (default: CodeVirtualization)",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-applied",
        action="store_true",
        help="fail when a selected pass does not apply to any fixture",
    )
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    if args.all_fixtures and args.fixtures:
        parser.error("pass either --all or explicit fixture paths")
    fixtures = discover_executables(args.dataset) if args.all_fixtures else args.fixtures
    if not fixtures:
        parser.error("no executable fixtures selected")
    try:
        pass_names = _parse_pass_names(args.passes)
    except ValueError as error:
        parser.error(str(error))

    seeds = range(args.first_seed, args.first_seed + args.count)
    with tempfile.TemporaryDirectory(prefix="r2morph-maturity-") as temp_dir:
        measurements = {
            pass_name: [measure_fixture(fixture, seeds, Path(temp_dir), pass_name) for fixture in fixtures]
            for pass_name in pass_names
        }
    report = _render_result(measurements[pass_names[0]], pass_names[0])
    if len(pass_names) > 1:
        report = _render_multi_pass_result(measurements)
    if args.require_applied:
        passes_without_mutations = [
            name
            for name, fixtures_for_pass in measurements.items()
            if _render_result(fixtures_for_pass, name)["summary"]["applied_runs"] == 0
        ]
        if passes_without_mutations:
            parser.error("selected passes did not apply to any fixture: " + ", ".join(passes_without_mutations))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
