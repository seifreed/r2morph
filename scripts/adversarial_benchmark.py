#!/usr/bin/env python3
"""Run a bounded, evidence-preserving analysis benchmark on a binary pair."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.adversarial_benchmark_campaign import (
    _adversarial_evidence_blockers,
    _blocker_totals,
    _campaign_summary,
    _incomplete_tool_coverage,
    _pass_reason_map,
    _pass_status_count,
    _pass_status_counts,
    _release_signoff_blockers,
    _tool_reason_map,
    _tool_run_coverage_by_tool,
    _tool_status_counts,
    _tools_with_status,
)
from scripts.adversarial_benchmark_constants import (
    _ADVERSARIAL_ALL_PASS_NAMES,
    _ANGR_DECOMPILER_FUNCTION_LIMIT,
    _ANSI_ESCAPE,
    _BINARY_NINJA_PYTHON_PATH_ENV,
    _BINARY_NINJA_PYTHON_PATHS,
    _COMMAND_ENVIRONMENT,
    _COMMAND_TIMEOUT_SECONDS,
    _COMMANDS,
    _DISASSEMBLY_LINE,
    _EXPECTED_TOOLS,
    _FULL_COVERAGE_PERCENT,
    _GHIDRA_ANALYSIS_TIMEOUT_SECONDS,
    _GHIDRA_COUNT_PATTERN,
    _GHIDRA_DECOMPILER_PATTERN,
    _GHIDRA_PROCESS_TIMEOUT_SECONDS,
    _GHIDRA_SCRIPT,
    _IDA_RESULT_SUFFIX,
    _IDA_SCRIPT,
    _IN_PROCESS_TOOL_TIMEOUT_SECONDS,
    _IN_PROCESS_TOOLS,
    _MAX_X86_INSTRUCTION_BYTES,
    _PASS_STATUS_FIELDS,
    _PF_EXECUTE,
    _PYTHON_MODULES,
    _TRITON_INSTRUCTION_BUDGET,
)
from scripts.adversarial_benchmark_execution import _benchmark_passes, _protected_copy
from scripts.adversarial_benchmark_metrics import (
    _accumulate_effectiveness_tool,
    _analyzer_effectiveness_by_pass,
    _coverage_percent,
    _decompiler_baseline_unavailable_by_pass,
    _decompiler_evidence_complete,
    _decompiler_observations,
    _finalize_effectiveness_tool_summary,
    _measure_pair_tools,
    _merge_tool_reason,
    _missing_tool_slot_error,
    _new_effectiveness_tool_summary,
    _passes_without_applications,
    _tool_duration_pair_count,
    _tool_duration_seconds,
    _tool_metric_deltas,
    _tool_metric_pair_counts,
    _tool_summary,
)
from scripts.adversarial_benchmark_models import BenchmarkOptions
from scripts.adversarial_benchmark_passes import (
    _capability_counts,
    _diagnostic_reason,
    _merge_capability_summary,
    _merge_pass_reason,
    _pass_result,
    _pass_summary,
    _severity_counts,
)
from scripts.adversarial_benchmark_tools import (
    _METRICS,
    _angr_metric,
    _availability,
    _binary_metric,
    _binary_ninja_decompiler_metrics,
    _binary_ninja_metric,
    _configured_executable,
    _executable_segment_bytes,
    _file_digest,
    _ghidra_metric,
    _ida_metric,
    _is_binary_ninja_license_error,
    _measure_tool,
    _measure_tool_bounded,
    _measure_tool_unbounded,
    _measure_tool_worker,
    _objdump_metric,
    _parse_adversarial_pass_names,
    _parse_ghidra_decompiler_metrics,
    _parse_ghidra_function_count,
    _parse_ghidra_function_counts,
    _prepare_optional_module_path,
    _radare2_metric,
    _tool_failure_result,
    _ToolCapabilityUnavailableError,
    _triton_metric,
    _unicorn_metric,
)

__all__ = (
    "CORPUS_PASS_NAMES",
    "EXTENDED_MATURITY_PASS_NAMES",
    "_ADVERSARIAL_ALL_PASS_NAMES",
    "_ANGR_DECOMPILER_FUNCTION_LIMIT",
    "_ANSI_ESCAPE",
    "_APPLIED_COUNT_FIELDS",
    "_BINARY_NINJA_PYTHON_PATHS",
    "_BINARY_NINJA_PYTHON_PATH_ENV",
    "_COMMANDS",
    "_COMMAND_ENVIRONMENT",
    "_COMMAND_TIMEOUT_SECONDS",
    "_DISASSEMBLY_LINE",
    "_EXPECTED_TOOLS",
    "_FULL_COVERAGE_PERCENT",
    "_GHIDRA_ANALYSIS_TIMEOUT_SECONDS",
    "_GHIDRA_COUNT_PATTERN",
    "_GHIDRA_DECOMPILER_PATTERN",
    "_GHIDRA_PROCESS_TIMEOUT_SECONDS",
    "_GHIDRA_SCRIPT",
    "_IDA_RESULT_SUFFIX",
    "_IDA_SCRIPT",
    "_IN_PROCESS_TOOLS",
    "_IN_PROCESS_TOOL_TIMEOUT_SECONDS",
    "_MAX_X86_INSTRUCTION_BYTES",
    "_METRICS",
    "_PASS_STATUS_FIELDS",
    "_PF_EXECUTE",
    "_PYTHON_MODULES",
    "_TRITON_INSTRUCTION_BUDGET",
    "_ToolCapabilityUnavailableError",
    "_accumulate_effectiveness_tool",
    "_adversarial_evidence_blockers",
    "_analyzer_effectiveness_by_pass",
    "_angr_metric",
    "_availability",
    "_binary_metric",
    "_binary_ninja_decompiler_metrics",
    "_binary_ninja_metric",
    "_blocker_totals",
    "_campaign_summary",
    "_capability_counts",
    "_configured_executable",
    "_coverage_percent",
    "_decompiler_baseline_unavailable_by_pass",
    "_decompiler_evidence_complete",
    "_decompiler_observations",
    "_diagnostic_reason",
    "_executable_segment_bytes",
    "_file_digest",
    "_finalize_effectiveness_tool_summary",
    "_ghidra_metric",
    "_ida_metric",
    "_incomplete_tool_coverage",
    "_is_binary_ninja_license_error",
    "_measure_pair_tools",
    "_measure_tool",
    "_measure_tool_bounded",
    "_measure_tool_unbounded",
    "_measure_tool_worker",
    "_merge_capability_summary",
    "_merge_pass_reason",
    "_merge_tool_reason",
    "_missing_tool_slot_error",
    "_new_effectiveness_tool_summary",
    "_objdump_metric",
    "_parse_adversarial_pass_names",
    "_parse_ghidra_decompiler_metrics",
    "_parse_ghidra_function_count",
    "_parse_ghidra_function_counts",
    "_pass_reason_map",
    "_pass_result",
    "_pass_status_count",
    "_pass_status_counts",
    "_pass_summary",
    "_passes_without_applications",
    "_prepare_optional_module_path",
    "_protected_copy",
    "_radare2_metric",
    "_release_signoff_blockers",
    "_severity_counts",
    "_tool_duration_pair_count",
    "_tool_duration_seconds",
    "_tool_failure_result",
    "_tool_metric_deltas",
    "_tool_metric_pair_counts",
    "_tool_reason_map",
    "_tool_run_coverage_by_tool",
    "_tool_status_counts",
    "_tool_summary",
    "_tools_with_status",
    "_triton_metric",
    "_unicorn_metric",
)

from scripts.protection_maturity_baseline import (
    _APPLIED_COUNT_FIELDS,
    CORPUS_PASS_NAMES,
    DEFAULT_MUTATION_NAME,
    EXTENDED_MATURITY_PASS_NAMES,
    _select_fixture_shard,
    build_generated_corpus,
    discover_executables,
)

_ADVERSARIAL_REPORT_SCHEMA_VERSION = 3


def benchmark_pair(
    original: Path,
    protected: Path | None = None,
    pass_names: tuple[str, ...] = (DEFAULT_MUTATION_NAME,),
    options: BenchmarkOptions | None = None,
) -> dict[str, object]:
    """Benchmark every configured analyzer and preserve unavailable evidence."""
    if not original.is_file():
        raise ValueError(f"original binary does not exist: {original}")
    if protected is not None and not protected.is_file():
        raise ValueError(f"protected binary does not exist: {protected}")
    original_sha256 = _file_digest(original)
    if protected is not None and len(pass_names) != 1:
        raise ValueError("protected-binary replay requires exactly one pass name")
    with tempfile.TemporaryDirectory(prefix="r2morph-adversarial-") as directory:
        if protected is None:
            pass_rows, tools = _benchmark_passes(
                original,
                Path(directory),
                pass_names,
                options=options,
            )
            protected_path = Path(directory) / "protected"
            protected_sha256 = None
        else:
            protected_path = protected
            protected_sha256 = _file_digest(protected_path)
            tools = _measure_pair_tools(original, protected_path, None, None, protected_sha256, options)
            tools = [{**tool, "pass_name": pass_names[0]} for tool in tools]
    tool_summary = _tool_summary([{"tools": tools}])
    release_signoff_blockers = _release_signoff_blockers(tool_summary)
    report: dict[str, object] = {
        "schema_version": _ADVERSARIAL_REPORT_SCHEMA_VERSION,
        "measurement": "protection-adversarial-pair",
        "measurement_environment": _measurement_environment(),
        "original": original.name,
        "original_sha256": original_sha256,
        "protected": protected_path.name,
        "tools": tools,
        "tool_summary": tool_summary,
        "release_signoff_blockers": release_signoff_blockers,
        "release_signoff_blocker_totals": _blocker_totals(
            release_signoff_blockers,
            "total_release_signoff_blockers",
        ),
        "pass_names": list(pass_names),
        "tool_selection": list(
            options.tool_names if options is not None and options.tool_names else (*_EXPECTED_TOOLS, "custom")
        ),
    }
    if protected is None:
        report["passes"] = pass_rows
        if options is not None and options.artifact_directory is not None:
            original_sha256 = _file_digest(original)
            original_relative = Path("originals") / f"{original_sha256}.bin"
            _export_original_artifact(original, options.artifact_directory, original_relative, original_sha256)
            report["artifacts"] = [
                {
                    **pass_row["artifacts"],
                    "original": original_relative.as_posix(),
                }
                for pass_row in pass_rows
                if isinstance(pass_row.get("artifacts"), dict)
            ]
    else:
        report["protected_sha256"] = protected_sha256
    return report


def benchmark_corpus(  # noqa: PLR0913
    dataset: Path,
    pass_names: tuple[str, ...] = (DEFAULT_MUTATION_NAME,),
    fixture_shard_index: int = 0,
    fixture_shard_count: int = 1,
    generated_corpus: bool = False,
    options: BenchmarkOptions | None = None,
) -> dict[str, object]:
    """Run the pair benchmark for every supported executable in the corpus."""
    if fixture_shard_count < 1:
        raise ValueError("fixture shard count must be positive")
    if fixture_shard_index < 0 or fixture_shard_index >= fixture_shard_count:
        raise ValueError("fixture shard index must be within the shard count")
    if not pass_names:
        raise ValueError("at least one corpus pass is required")
    with tempfile.TemporaryDirectory(prefix="r2morph-adversarial-corpus-") as temporary_directory:
        effective_dataset = dataset
        generated_fixtures: list[Path] = []
        if generated_corpus:
            effective_dataset = Path(temporary_directory) / dataset.name
            effective_dataset.mkdir()
            for fixture in discover_executables(dataset):
                shutil.copy2(fixture, effective_dataset / fixture.name)
            generated_fixtures = build_generated_corpus(Path(temporary_directory) / "generated-corpus")
            for fixture in generated_fixtures:
                shutil.copy2(fixture, effective_dataset / fixture.name)
        fixtures = discover_executables(effective_dataset)
        generated_fixture_names = sorted(fixture.name for fixture in generated_fixtures)
        generated_fixture_count = len(generated_fixture_names)
        if fixture_shard_count > 1:
            fixtures = _select_fixture_shard(fixtures, fixture_shard_index, fixture_shard_count)
        if not fixtures:
            raise ValueError(f"no supported executable fixtures found in {dataset}")
        samples = [
            benchmark_pair(
                fixture,
                pass_names=pass_names,
                options=options,
            )
            for fixture in fixtures
        ]
    report: dict[str, object] = {
        "schema_version": _ADVERSARIAL_REPORT_SCHEMA_VERSION,
        "measurement": "protection-adversarial-corpus",
        "measurement_environment": _measurement_environment(),
        "corpus": dataset.name,
        "corpus_scope": {
            "families": (
                ["repository-fixtures", "generated-elf-x86-64", "generated-cpp-x86-64"]
                if generated_corpus
                else ["repository-fixtures"]
            ),
            "generated_fixture_count": generated_fixture_count,
            "generated_fixture_names": generated_fixture_names,
        },
        "pass_names": list(pass_names),
        "tool_selection": list(
            options.tool_names if options is not None and options.tool_names else (*_EXPECTED_TOOLS, "custom")
        ),
        "fixture_shard": {"index": fixture_shard_index, "count": fixture_shard_count},
        "sample_count": len(samples),
        "samples": samples,
        "pass_summary": _pass_summary(samples),
        "tool_summary": _tool_summary(samples),
        "summary": _campaign_summary(samples, len(fixtures), pass_names),
    }
    if options is not None and options.artifact_directory is not None:
        report["artifacts"] = [
            artifact for sample in samples for artifact in sample.get("artifacts", []) if isinstance(artifact, dict)
        ]
    return report


def _export_original_artifact(original: Path, artifact_directory: Path, relative_path: Path, digest: str) -> None:
    """Write and verify a content-addressed original binary artifact."""
    destination = artifact_directory / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if _file_digest(destination) != digest:
            raise ValueError(f"original artifact digest collision at {relative_path}")
        return
    temporary = destination.with_suffix(f".tmp-{os.getpid()}")
    try:
        shutil.copyfile(original, temporary)
        if _file_digest(temporary) != digest:
            raise ValueError(f"exported original artifact digest mismatch at {relative_path}")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _measurement_environment() -> dict[str, str | None]:
    """Capture host and disassembler versions that can affect mutation output."""
    radare2_version: str | None = None
    radare2_path = shutil.which("r2")
    if radare2_path is not None:
        try:
            result = subprocess.run(  # noqa: S603 - trusted PATH binary, fixed -v argument
                [radare2_path, "-v"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        else:
            output = result.stdout or result.stderr
            if result.returncode == 0 and output:
                radare2_version = output.splitlines()[0].strip()
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python_hash_seed": os.environ.get("PYTHONHASHSEED"),
        "radare2_version": radare2_version,
    }


def _common_measurement_environment(reports: list[dict[str, object]]) -> dict[str, object] | None:
    environments = [report.get("measurement_environment") for report in reports]
    if not any(environment is not None for environment in environments):
        return None
    first = environments[0]
    if not isinstance(first, dict) or not all(
        isinstance(environment, dict) and environment == first for environment in environments
    ):
        raise ValueError("adversarial reports use different measurement environments")
    return first


def _validate_shard_metadata(reports: list[dict[str, object]]) -> None:
    shard_metadata = [report.get("fixture_shard") for report in reports]
    if not any(metadata is not None for metadata in shard_metadata):
        return
    if not all(
        isinstance(metadata, dict)
        and isinstance(metadata.get("index"), int)
        and isinstance(metadata.get("count"), int)
        and metadata["count"] > 0
        and 0 <= metadata["index"] < metadata["count"]
        for metadata in shard_metadata
    ):
        raise ValueError("adversarial reports have incomplete fixture shard metadata")
    valid_shards = cast(list[dict[str, int]], shard_metadata)
    shard_count = valid_shards[0]["count"]
    shard_indices = [metadata["index"] for metadata in valid_shards]
    if any(metadata["count"] != shard_count for metadata in valid_shards):
        raise ValueError("adversarial reports use different fixture shard counts")
    if len(set(shard_indices)) != len(shard_indices) or set(shard_indices) != set(range(shard_count)):
        raise ValueError("adversarial reports do not cover every fixture shard")


def merge_adversarial_reports(reports: list[dict[str, object]]) -> dict[str, object]:
    """Merge disjoint adversarial corpus reports before evaluating campaign gates."""
    if not reports:
        raise ValueError("at least one adversarial report is required")
    first_pass_names = reports[0].get("pass_names")
    if not isinstance(first_pass_names, list) or not all(isinstance(name, str) for name in first_pass_names):
        raise ValueError("adversarial report is missing pass names")
    corpus = reports[0].get("corpus")
    corpus_scope = reports[0].get("corpus_scope")
    environment = _common_measurement_environment(reports)
    _validate_shard_metadata(reports)
    samples: list[dict[str, object]] = []
    seen_samples: set[str] = set()
    for report in reports:
        if (
            report.get("corpus") != corpus
            or report.get("pass_names") != first_pass_names
            or report.get("corpus_scope") != corpus_scope
        ):
            raise ValueError("adversarial reports do not share corpus and pass scope")
        report_samples = report.get("samples")
        if not isinstance(report_samples, list) or not all(isinstance(sample, dict) for sample in report_samples):
            raise ValueError("adversarial report has invalid samples")
        for sample in report_samples:
            name = sample.get("original")
            if not isinstance(name, str) or name in seen_samples:
                raise ValueError(f"adversarial reports overlap sample: {name}")
            seen_samples.add(name)
        samples.extend(report_samples)
    pass_names = tuple(first_pass_names)
    merged: dict[str, object] = {
        "schema_version": _ADVERSARIAL_REPORT_SCHEMA_VERSION,
        "measurement": "protection-adversarial-corpus",
        "corpus": corpus,
        "pass_names": first_pass_names,
        "sample_count": len(samples),
        "samples": samples,
        "pass_summary": _pass_summary(samples),
        "tool_summary": _tool_summary(samples),
        "summary": _campaign_summary(samples, len(samples), pass_names),
    }
    if corpus_scope is not None:
        merged["corpus_scope"] = corpus_scope
    if environment is not None:
        merged["measurement_environment"] = environment
    return merged


def _replay_report_identity(
    report: dict[str, object],
) -> tuple[str, str, str, dict[str, object], list[str], list[dict[str, object]]]:
    if report.get("schema_version") != _ADVERSARIAL_REPORT_SCHEMA_VERSION:
        raise ValueError("replay report uses an unsupported schema version")
    original_sha256 = report.get("original_sha256")
    protected_sha256 = report.get("protected_sha256")
    pass_names = report.get("pass_names")
    tool_selection = report.get("tool_selection")
    environment = report.get("measurement_environment")
    tools = report.get("tools")
    if not isinstance(original_sha256, str) or not isinstance(protected_sha256, str):
        raise ValueError("replay report is missing original/protected hashes")
    if (
        not isinstance(pass_names, list)
        or len(pass_names) != 1
        or not isinstance(pass_names[0], str)
        or not isinstance(tool_selection, list)
        or not tool_selection
        or not all(isinstance(tool, str) for tool in tool_selection)
    ):
        raise ValueError("replay report must identify exactly one pass and selected analyzer tools")
    if (
        not isinstance(environment, dict)
        or not isinstance(tools, list)
        or not all(isinstance(row, dict) for row in tools)
    ):
        raise ValueError("replay report is missing environment or analyzer rows")
    row_tools = [row.get("tool") for row in tools]
    if (
        any(tool not in tool_selection for tool in row_tools)
        or len(set(row_tools)) != len(row_tools)
        or set(row_tools) != set(tool_selection)
    ):
        raise ValueError("replay report rows do not match its declared analyzer selection")
    if not _is_sha256(original_sha256) or not _is_sha256(protected_sha256):
        raise ValueError("replay report contains invalid binary hashes")
    return original_sha256, protected_sha256, pass_names[0], environment, tool_selection, tools


def _is_sha256(value: str) -> bool:
    return len(value) == _SHA256_HEX_LENGTH and all(character in "0123456789abcdef" for character in value)


_SHA256_HEX_LENGTH = 64


def _find_replay_target(
    samples_by_hash: dict[str, dict[str, object]],
    original_sha256: str,
    pass_name: str,
    protected_sha256: str,
) -> tuple[dict[str, object], dict[str, object]]:
    sample = samples_by_hash.get(original_sha256)
    if sample is None:
        raise ValueError(f"replay original hash is absent from base corpus: {original_sha256}")
    if not _is_sha256(original_sha256) or not _is_sha256(protected_sha256):
        raise ValueError("base corpus contains an invalid binary hash")
    pass_rows = sample.get("passes")
    if not isinstance(pass_rows, list) or not all(isinstance(row, dict) for row in pass_rows):
        raise ValueError("base corpus sample has invalid pass rows")
    matching = [row for row in pass_rows if row.get("pass_name") == pass_name]
    if len(matching) != 1 or matching[0].get("protected_sha256") != protected_sha256:
        raise ValueError("replay hashes do not match the base sample and pass")
    return sample, matching[0]


@dataclass
class _ReplayMergeContext:
    original_sha256: str
    pass_name: str
    pass_status: str
    environment: dict[str, object]
    base_environment: object
    seen_rows: set[tuple[str, str, str]]
    diagnostics: list[object]
    history: list[object]


def _merge_one_replay_row(
    sample_tools: list[dict[str, object]],
    row: dict[str, object],
    context: _ReplayMergeContext,
) -> None:
    tool_name = row.get("tool")
    if not isinstance(tool_name, str):
        raise ValueError("replay analyzer row has no tool name")
    identity = (context.original_sha256, context.pass_name, tool_name)
    if identity in context.seen_rows:
        raise ValueError(f"duplicate replay for {tool_name} on {context.original_sha256}/{context.pass_name}")
    context.seen_rows.add(identity)
    replay_row = {**row, "pass_name": context.pass_name, "pass_status": context.pass_status}
    if row.get("status") != "completed":
        context.diagnostics.append({"row": replay_row, "measurement_environment": context.environment})
        return
    replay_row["measurement_environment"] = context.environment
    existing = [
        index
        for index, base_row in enumerate(sample_tools)
        if base_row.get("tool") == tool_name and base_row.get("pass_name") == context.pass_name
    ]
    if len(existing) > 1:
        raise ValueError(f"base corpus has duplicate analyzer rows for {tool_name}/{context.pass_name}")
    if existing:
        index = existing[0]
        if sample_tools[index].get("status") == "completed":
            raise ValueError(f"base corpus already has a completed {tool_name} measurement")
        context.history.append({"row": sample_tools[index], "measurement_environment": context.base_environment})
        sample_tools[index] = replay_row
        return
    sample_tools.append(replay_row)


def _replay_sample_state(
    sample: dict[str, object],
    pass_row: dict[str, object],
) -> tuple[list[dict[str, object]], str, str, list[object], list[object]]:
    sample_tools = sample.get("tools")
    if not isinstance(sample_tools, list) or not all(isinstance(row, dict) for row in sample_tools):
        raise ValueError("base corpus sample has invalid analyzer rows")
    original_sha256 = sample.get("original_sha256")
    if not isinstance(original_sha256, str) or not isinstance(pass_row.get("protected_sha256"), str):
        raise ValueError("base corpus sample is missing binary hashes")
    pass_status = pass_row.get("status")
    if not isinstance(pass_status, str):
        raise ValueError("base corpus pass has no status")
    diagnostics = sample.setdefault("tool_replay_diagnostics", [])
    history = sample.setdefault("tool_replay_history", [])
    if not isinstance(diagnostics, list) or not isinstance(history, list):
        raise ValueError("base corpus replay metadata has an invalid shape")
    return sample_tools, original_sha256, pass_status, diagnostics, history


def merge_adversarial_replay_reports(
    base_report: dict[str, object],
    replay_reports: list[dict[str, object]],
) -> dict[str, object]:
    """Fill incomplete analyzer rows only when replayed binary/pass hashes match."""
    if not replay_reports:
        raise ValueError("at least one analyzer replay report is required")
    if base_report.get("measurement") != "protection-adversarial-corpus":
        raise ValueError("base report is not an adversarial corpus report")
    samples = base_report.get("samples")
    pass_names = base_report.get("pass_names")
    if (
        not isinstance(samples, list)
        or not all(isinstance(sample, dict) for sample in samples)
        or not isinstance(pass_names, list)
        or not all(isinstance(name, str) for name in pass_names)
    ):
        raise ValueError("base corpus report has invalid samples or pass scope")
    merged = copy.deepcopy(base_report)
    merged_samples = cast(list[dict[str, object]], merged["samples"])
    samples_by_hash: dict[str, dict[str, object]] = {}
    for sample in merged_samples:
        original_sha256 = sample.get("original_sha256")
        if (
            not isinstance(original_sha256, str)
            or not _is_sha256(original_sha256)
            or original_sha256 in samples_by_hash
        ):
            raise ValueError("base corpus has missing or duplicate original hashes")
        samples_by_hash[original_sha256] = sample
    base_environment = merged.get("measurement_environment")
    existing_replay_measurements = merged.get("replay_measurements", [])
    if not isinstance(existing_replay_measurements, list) or not all(
        isinstance(item, dict) for item in existing_replay_measurements
    ):
        raise ValueError("base report has invalid replay measurement metadata")
    replay_measurements: list[dict[str, object]] = list(existing_replay_measurements)
    seen_rows: set[tuple[str, str, str]] = set()
    for replay in replay_reports:
        if replay.get("measurement") not in (None, "protection-adversarial-pair"):
            raise ValueError("replay report has an unexpected measurement type")
        original_sha256, protected_sha256, pass_name, environment, tool_selection, replay_tools = (
            _replay_report_identity(replay)
        )
        if pass_name not in pass_names:
            raise ValueError(f"replay pass is absent from the base corpus: {pass_name}")
        sample, pass_row = _find_replay_target(samples_by_hash, original_sha256, pass_name, protected_sha256)
        sample_tools, sample_sha256, pass_status, diagnostics, history = _replay_sample_state(sample, pass_row)
        context = _ReplayMergeContext(
            original_sha256=sample_sha256,
            pass_name=pass_name,
            pass_status=pass_status,
            environment=environment,
            base_environment=base_environment,
            seen_rows=seen_rows,
            diagnostics=diagnostics,
            history=history,
        )
        for row in replay_tools:
            _merge_one_replay_row(sample_tools, row, context)
        fingerprint = hashlib.sha256(
            json.dumps(replay, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        replay_measurements.append(
            {
                "report_sha256": fingerprint,
                "original_sha256": original_sha256,
                "protected_sha256": protected_sha256,
                "pass_name": pass_name,
                "tools": tool_selection,
                "measurement_environment": environment,
            }
        )
    for sample in merged_samples:
        sample_tools = sample.get("tools")
        if not isinstance(sample_tools, list):
            raise ValueError("merged sample has invalid analyzer rows")
        sample_tool_summary = _tool_summary([{"tools": sample_tools}])
        sample["tool_summary"] = sample_tool_summary
        sample["release_signoff_blockers"] = _release_signoff_blockers(sample_tool_summary)
        sample["release_signoff_blocker_totals"] = _blocker_totals(
            sample["release_signoff_blockers"],
            "total_release_signoff_blockers",
        )
    merged["replay_measurements"] = replay_measurements
    merged["tool_summary"] = _tool_summary(merged_samples)
    merged["pass_summary"] = _pass_summary(merged_samples)
    merged["summary"] = _campaign_summary(merged_samples, len(merged_samples), tuple(pass_names))
    return merged


def _parse_adversarial_tool_names(value: str) -> tuple[str, ...] | None:
    """Parse analyzer selection, with ``None`` representing all supported tools."""
    if value.strip().lower() == "all":
        return None
    allowed = (*_EXPECTED_TOOLS, "custom")
    selected = tuple(dict.fromkeys(name.strip() for name in value.split(",") if name.strip()))
    if not selected:
        raise ValueError("at least one analyzer tool is required")
    unknown = sorted(set(selected).difference(allowed))
    if unknown:
        raise ValueError("unknown analyzer tools: " + ", ".join(unknown))
    return selected


def _run_selected_benchmark(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, object]:
    if args.all_fixtures and args.protected:
        parser.error("--protected is valid only with one original binary")
    if args.require_tool_slots and not args.all_fixtures:
        parser.error("--require-tool-slots requires --all")
    if args.require_tool_slots and args.tools.strip().lower() != "all":
        parser.error("--require-tool-slots requires --tools all")
    if args.fixture_shard_count > 1 and not args.all_fixtures:
        parser.error("fixture sharding requires --all")
    if args.protected and args.artifact_dir:
        parser.error("--artifact-dir is only valid when the benchmark generates protected binaries")
    if args.protected and not args.pass_name:
        parser.error("--protected replay requires an explicit --pass-name")
    if args.pass_name and not args.protected:
        parser.error("--pass-name is only valid with --protected")
    try:
        pass_names = _parse_adversarial_pass_names(args.pass_name or args.passes)
    except ValueError as error:
        parser.error(str(error))
    try:
        tool_names = _parse_adversarial_tool_names(args.tools)
    except ValueError as error:
        parser.error(str(error))
    options = BenchmarkOptions(tool_names=tool_names, artifact_directory=args.artifact_dir)
    if args.all_fixtures:
        return benchmark_corpus(
            args.dataset,
            pass_names,
            args.fixture_shard_index,
            args.fixture_shard_count,
            args.generated_corpus,
            options,
        )
    return benchmark_pair(args.original, args.protected, pass_names, options)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("original", type=Path, nargs="?")
    selection.add_argument("--all", action="store_true", dest="all_fixtures")
    parser.add_argument("--dataset", type=Path, default=Path("fixtures/dataset"))
    parser.add_argument(
        "--generated-corpus",
        action="store_true",
        help="compile synthetic Linux ELF x86-64 fixtures and include them in the corpus",
    )
    parser.add_argument("--protected", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--tools",
        default="all",
        help="comma-separated analyzer tool names or 'all' (default: all configured analyzers)",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help="export hash-verified original/protected pairs and a replay manifest",
    )
    parser.add_argument(
        "--passes",
        default=DEFAULT_MUTATION_NAME,
        help="comma-separated pass names or 'all' (default: CodeVirtualization)",
    )
    parser.add_argument(
        "--pass-name",
        help="explicit single pass associated with --protected analyzer replay",
    )
    parser.add_argument(
        "--require-applied",
        action="store_true",
        help="fail when a selected pass does not apply to any corpus fixture",
    )
    parser.add_argument(
        "--require-tool-slots",
        action="store_true",
        help="fail when an expected analyzer slot is missing from a corpus benchmark",
    )
    parser.add_argument(
        "--fixture-shard-index",
        type=int,
        default=0,
        help="zero-based corpus shard index for parallel campaigns",
    )
    parser.add_argument(
        "--fixture-shard-count",
        type=int,
        default=1,
        help="number of deterministic corpus shards for parallel campaigns",
    )
    args = parser.parse_args(argv)
    report = _run_selected_benchmark(args, parser)
    if args.require_applied and args.fixture_shard_count == 1:
        passes_without_mutations = _passes_without_applications(report)
        if passes_without_mutations:
            parser.error("selected passes did not apply to any fixture: " + ", ".join(passes_without_mutations))
    if args.require_tool_slots and (error := _missing_tool_slot_error(report)):
        parser.error(error)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.artifact_dir:
        args.artifact_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": 1,
            "measurement": "protection-adversarial-artifacts",
            "report_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "artifacts": report.get("artifacts", []),
        }
        (args.artifact_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
