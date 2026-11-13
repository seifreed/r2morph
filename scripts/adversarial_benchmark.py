#!/usr/bin/env python3
"""Run a bounded, evidence-preserving analysis benchmark on a binary pair."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
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


def benchmark_pair(
    original: Path,
    protected: Path | None = None,
    pass_names: tuple[str, ...] = (DEFAULT_MUTATION_NAME,),
) -> dict[str, object]:
    """Benchmark every configured analyzer and preserve unavailable evidence."""
    if not original.is_file():
        raise ValueError(f"original binary does not exist: {original}")
    with tempfile.TemporaryDirectory(prefix="r2morph-adversarial-") as directory:
        if protected is None:
            pass_rows, tools = _benchmark_passes(original, Path(directory), pass_names)
            protected_path = Path(directory) / "protected"
        else:
            protected_path = protected
            tools = _measure_pair_tools(original, protected_path)
    tool_summary = _tool_summary([{"tools": tools}])
    release_signoff_blockers = _release_signoff_blockers(tool_summary)
    report: dict[str, object] = {
        "schema_version": 3,
        "original": original.name,
        "protected": protected_path.name,
        "tools": tools,
        "tool_summary": tool_summary,
        "release_signoff_blockers": release_signoff_blockers,
        "release_signoff_blocker_totals": _blocker_totals(
            release_signoff_blockers,
            "total_release_signoff_blockers",
        ),
    }
    if protected is None:
        report["passes"] = pass_rows
        report["pass_names"] = list(pass_names)
    return report


def benchmark_corpus(
    dataset: Path,
    pass_names: tuple[str, ...] = (DEFAULT_MUTATION_NAME,),
    fixture_shard_index: int = 0,
    fixture_shard_count: int = 1,
    generated_corpus: bool = False,
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
        samples = [benchmark_pair(fixture, pass_names=pass_names) for fixture in fixtures]
    return {
        "schema_version": 3,
        "measurement": "protection-adversarial-corpus",
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
        "fixture_shard": {"index": fixture_shard_index, "count": fixture_shard_count},
        "sample_count": len(samples),
        "samples": samples,
        "pass_summary": _pass_summary(samples),
        "tool_summary": _tool_summary(samples),
        "summary": _campaign_summary(samples, len(fixtures), pass_names),
    }


def merge_adversarial_reports(reports: list[dict[str, object]]) -> dict[str, object]:
    """Merge disjoint adversarial corpus reports before evaluating campaign gates."""
    if not reports:
        raise ValueError("at least one adversarial report is required")
    first_pass_names = reports[0].get("pass_names")
    if not isinstance(first_pass_names, list) or not all(isinstance(name, str) for name in first_pass_names):
        raise ValueError("adversarial report is missing pass names")
    corpus = reports[0].get("corpus")
    corpus_scope = reports[0].get("corpus_scope")
    shard_metadata = [report.get("fixture_shard") for report in reports]
    if any(metadata is not None for metadata in shard_metadata):
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
        "schema_version": 3,
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
    return merged


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
        "--passes",
        default=DEFAULT_MUTATION_NAME,
        help="comma-separated pass names or 'all' (default: CodeVirtualization)",
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
    if args.all_fixtures and args.protected:
        parser.error("--protected is valid only with one original binary")
    if args.require_tool_slots and not args.all_fixtures:
        parser.error("--require-tool-slots requires --all")
    if args.fixture_shard_count > 1 and not args.all_fixtures:
        parser.error("fixture sharding requires --all")
    try:
        pass_names = _parse_adversarial_pass_names(args.passes)
    except ValueError as error:
        parser.error(str(error))
    report = (
        benchmark_corpus(
            args.dataset,
            pass_names,
            args.fixture_shard_index,
            args.fixture_shard_count,
            args.generated_corpus,
        )
        if args.all_fixtures
        else benchmark_pair(args.original, args.protected, pass_names)
    )
    if args.require_applied and args.fixture_shard_count == 1:
        passes_without_mutations = _passes_without_applications(report)
        if passes_without_mutations:
            parser.error("selected passes did not apply to any fixture: " + ", ".join(passes_without_mutations))
    if args.require_tool_slots and (error := _missing_tool_slot_error(report)):
        parser.error(error)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
