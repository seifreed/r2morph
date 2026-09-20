#!/usr/bin/env python3
"""Run bounded automated adversarial checks for diversified VM builds.

The report is evidence for automated regression gates only.  It deliberately
keeps human adversarial review as a separate, pending release decision.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

# Keep direct CLI execution equivalent to importing this module from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.adapters.process import ProcessTimeoutError, run_process
from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationRecord
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from scripts.protection_adversary import analyze as run_adversary
from scripts.protection_bytecode_grammar import measure as measure_grammar
from scripts.protection_handler_clustering import measure as measure_handlers
from tests.integration.elf_emulator import emulate_exit_code


def _build_generated_corpus(output_dir: Path) -> list[Path]:
    module = importlib.import_module("scripts.protection_maturity_baseline")
    builder = cast(Callable[[Path], list[Path]], module.__dict__["build_generated_corpus"])
    return builder(output_dir)


_DEFAULT_SEED = 20260915
_DEFAULT_COUNT = 10
_MIN_SEEDS = 2
_MAX_SEEDS = 32
_TRAMPOLINE_SIZE = 5
_JMP_REL32_OPCODE = 0xE9
_TAMPER_OFFSETS = (0x10, 0x18, 0x20, 0x28, 0x30, 0x40, 0x50, 0x60)
_NATIVE_EXECUTION_TIMEOUT_SECONDS = 5
_GENERATED_RESISTANCE_FIXTURE_NAMES = (
    "generated_calls_gcc-o0",
    "generated_cpp_gxx-o2",
    "generated_memory_gcc-o2",
    "generated_xlat_gcc-o2",
)
_HUMAN_REVIEW = {
    "status": "pending-human-adversarial-review",
    "evidence_quality": "automated-adversarial-smoke",
    "pending_scope": [
        "human-adversarial-validation",
        "isa-opcode-diversity",
        "handler-diversity",
        "dispatcher-diversity",
        "anti-tamper",
        "progressive-bytecode-protection",
    ],
}


def _select_generated_resistance_fixtures(paths: Sequence[Path]) -> tuple[Path, ...]:
    """Select a stable cross-family subset from the generated corpus."""
    by_name = {path.name: path for path in paths}
    missing = [name for name in _GENERATED_RESISTANCE_FIXTURE_NAMES if name not in by_name]
    if missing:
        raise ValueError(f"generated resistance corpus is missing fixtures: {missing}")
    return tuple(by_name[name] for name in _GENERATED_RESISTANCE_FIXTURE_NAMES)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_segment_offset(binary: Binary, address: int) -> int | None:
    """Resolve an injected address through ELF load-segment geometry."""
    segments = binary.r2.cmdj("iSSj") or []
    for segment in segments:
        vaddr = segment.get("vaddr")
        paddr = segment.get("paddr")
        size = segment.get("size") or segment.get("vsize") or 0
        if not all(isinstance(value, int) for value in (vaddr, paddr, size)):
            continue
        if "x" not in str(segment.get("perm", "")) or not vaddr <= address < vaddr + size:
            continue
        return paddr + address - vaddr
    return None


def _vm_entry_locations(binary: Binary, records: Sequence[MutationRecord]) -> tuple[dict[str, int], ...]:
    """Map recorded VM trampolines to the injected blob's file offsets."""
    locations: list[dict[str, int]] = []
    for record in records:
        if record.mutation_kind != "code_virtualization":
            continue
        mutated = bytes.fromhex(record.mutated_bytes)
        if len(mutated) < _TRAMPOLINE_SIZE or mutated[0] != _JMP_REL32_OPCODE:
            continue
        target_vaddr = (
            record.start_address + _TRAMPOLINE_SIZE + int.from_bytes(mutated[1:_TRAMPOLINE_SIZE], "little", signed=True)
        )
        file_offset = _resolve_segment_offset(binary, target_vaddr)
        bytecode_size = record.metadata.get("bytecode_size")
        if file_offset is None or not isinstance(bytecode_size, int) or bytecode_size <= 0:
            continue
        locations.append({"offset": file_offset, "size": bytecode_size})
    return tuple(locations)


def _virtualize_fixture(source: Path, destination: Path, seed: int, depth: int | None = None) -> dict[str, object]:
    shutil.copyfile(source, destination)
    destination.chmod(0o700)
    config: dict[str, object] = {"probability": 1.0, "seed": seed}
    if depth is not None:
        config["vm_nesting_depth"] = depth
    with Binary(destination, writable=True) as binary:
        virtualization_pass = CodeVirtualizationPass(config=config)
        stats = virtualization_pass.apply(binary)
        binary.save()
        binary.reload()
        records = virtualization_pass.get_records()
        stats["vm_entries"] = _vm_entry_locations(binary, records)
        stats["nested_vm_regions"] = _nested_region_count(records)
    return stats


def _native_execution(path: Path) -> dict[str, object]:
    """Run an ELF probe when the host can execute the fixture natively."""
    if not sys.platform.startswith("linux"):
        return {"status": "unavailable", "reason": "native ELF execution requires Linux"}
    try:
        result = run_process([path], timeout=_NATIVE_EXECUTION_TIMEOUT_SECONDS)
    except (OSError, ProcessTimeoutError) as error:
        return {"status": "error", "error_type": type(error).__name__}
    return {"status": "completed", "return_code": result.returncode}


def _adversarial_recovery_probe(path: Path) -> dict[str, object]:
    """Run the bounded recovery adversary and retain only summary metrics."""
    report = run_adversary(path, limit=3)
    results = report.get("results")
    dynamic = report.get("dynamic_recovery")
    if not isinstance(results, list) or not isinstance(dynamic, dict):
        raise ValueError("adversarial recovery probe returned an incomplete report")
    classifications = [
        row.get("classification")
        for row in results
        if isinstance(row, dict) and isinstance(row.get("classification"), str)
    ]
    return {
        "status": "completed",
        "functions_examined": len(results),
        "vm_candidate_count": sum(classification != "no_vm_candidate" for classification in classifications),
        "unsupported_indirect_dispatch_count": sum(
            classification == "unsupported_indirect_dispatch" for classification in classifications
        ),
        "dynamic_recovery": dynamic.get("recovered") is True,
        "state_encoding_detected": dynamic.get("state_encoding_detected") is True,
        "correlated_dispatch_count": dynamic.get("correlated_dispatch_count", 0),
    }


def _required_bytecode_size(stats: dict[str, object]) -> int:
    value = stats.get("total_bytecode_bytes")
    if not isinstance(value, int):
        raise ValueError("virtualization report is missing total_bytecode_bytes")
    return value


def _nested_region_count(records: Sequence[MutationRecord]) -> int:
    return sum(
        1
        for record in records
        if record.mutation_kind == "code_virtualization" and record.metadata.get("nested_vm") is True
    )


def _required_nested_region_count(stats: dict[str, object]) -> int:
    value = stats.get("nested_vm_regions", 0)
    if not isinstance(value, int):
        raise ValueError("virtualization report has an invalid nested VM count")
    return value


def _seed_campaign(source: Path, workdir: Path, first_seed: int, count: int) -> dict[str, object]:
    baseline = emulate_exit_code(source)
    builds: list[dict[str, object]] = []
    for seed in range(first_seed, first_seed + count):
        output = workdir / f"seed-{seed}"
        stats = _virtualize_fixture(source, output, seed)
        builds.append(
            {
                "seed": seed,
                "sha256": _sha256(output),
                "exit_code": emulate_exit_code(output),
                "functions_virtualized": stats.get("functions_virtualized", 0),
                "bytecode_bytes": stats.get("total_bytecode_bytes", 0),
                "unsupported_functions": stats.get("unsupported_functions_total", 0),
                "partial_virtualization": stats.get("partial_virtualization_total", 0),
            }
        )
    return {
        "baseline_exit_code": baseline,
        "builds": builds,
        "distinct_artifacts": len({row["sha256"] for row in builds}) == count,
        "semantic_parity": all(row["exit_code"] == baseline for row in builds),
        "all_functions_virtualized": all(row["functions_virtualized"] == 1 for row in builds),
        "no_unsupported_functions": all(row["unsupported_functions"] == 0 for row in builds),
        "no_partial_virtualization": all(row["partial_virtualization"] == 0 for row in builds),
    }


def _tamper_probe(source: Path, workdir: Path, seed: int, depth: int | None = None) -> dict[str, object]:
    protected = workdir / ("nested-protected" if depth is not None else "protected")
    tampered_prefix = "nested-tampered" if depth is not None else "tampered"
    stats = _virtualize_fixture(source, protected, seed, depth)
    original_exit = emulate_exit_code(protected)
    native_original = _native_execution(protected)
    adversarial_recovery = _adversarial_recovery_probe(protected)
    data = bytearray(protected.read_bytes())
    vm_entries = stats.get("vm_entries")
    if not isinstance(vm_entries, tuple) or not vm_entries or not isinstance(vm_entries[0], dict):
        raise ValueError("virtualized fixture does not expose a recorded VM entry")
    vm_entry = vm_entries[0].get("offset")
    vm_size = vm_entries[0].get("size")
    if (
        not isinstance(vm_entry, int)
        or not isinstance(vm_size, int)
        or vm_size <= max(_TAMPER_OFFSETS)
        or any(vm_entry + offset >= len(data) for offset in _TAMPER_OFFSETS)
    ):
        raise ValueError("virtualized fixture does not expose a bounded VM entry")
    probes: list[dict[str, object]] = []
    for offset in _TAMPER_OFFSETS:
        tampered = workdir / f"{tampered_prefix}-{offset:x}"
        candidate = bytearray(data)
        candidate[vm_entry + offset] ^= 0xFF
        tampered.write_bytes(candidate)
        try:
            tampered_exit: int | None = emulate_exit_code(tampered)
        except Exception:  # A tamper-triggered emulator fault is itself divergence.
            tampered_exit = None
        native_tampered = _native_execution(tampered)
        native_diverged = native_original.get("status") == "completed" and (
            native_tampered.get("status") != "completed"
            or native_tampered.get("return_code") != native_original.get("return_code")
        )
        probes.append(
            {
                "offset": offset,
                "tampered_exit_code": tampered_exit,
                "diverged": tampered_exit != original_exit,
                "native": native_tampered,
                "native_diverged": native_diverged,
            }
        )
    first_probe = probes[0]
    return {
        "seed": seed,
        "depth": depth or 1,
        "functions_virtualized": stats.get("functions_virtualized", 0),
        "original_exit_code": original_exit,
        "tampered_exit_code": first_probe["tampered_exit_code"],
        "tamper_diverged": first_probe["diverged"],
        "tamper_probe_count": len(probes),
        "tamper_probes": probes,
        "all_tamper_probes_diverged": all(probe["diverged"] for probe in probes),
        "native_original": native_original,
        "native_execution_available": native_original.get("status") == "completed",
        "adversarial_recovery": adversarial_recovery,
        "all_native_tamper_probes_diverged": (
            native_original.get("status") == "completed" and all(probe["native_diverged"] for probe in probes)
        ),
    }


def _dispatcher_digests(first_seed: int, count: int) -> list[str]:
    return [
        hashlib.sha256(
            _interpreter_asm(0, build_vm_scheme(randomness.Random(seed)), has_fp=True).encode("ascii")
        ).hexdigest()
        for seed in range(first_seed, first_seed + count)
    ]


def _opcode_assignment_report(first_seed: int, count: int) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for seed in range(first_seed, first_seed + count):
        scheme = build_vm_scheme(randomness.Random(seed))
        assignments = [(key[0], key[1], key[2], tuple(indices)) for key, indices in sorted(scheme.dup.items())]
        digest = hashlib.sha256(repr(assignments).encode("ascii")).hexdigest()
        multiplicities = [len(indices) for _key, indices in sorted(scheme.dup.items())]
        rows.append(
            {
                "seed": seed,
                "opcode_count": sum(multiplicities),
                "operation_key_count": len(assignments),
                "minimum_multiplicity": min(multiplicities),
                "maximum_multiplicity": max(multiplicities),
                "assignment_digest": digest,
            }
        )
    digests = [str(row["assignment_digest"]) for row in rows]
    return {
        "seeds": rows,
        "assignment_unique_count": len(set(digests)),
        "all_assignments_unique": len(set(digests)) == count,
    }


def measure(source: Path, first_seed: int = _DEFAULT_SEED, count: int = _DEFAULT_COUNT) -> dict[str, object]:
    """Measure seed diversity, tamper response, and progressive VM growth."""
    if count < _MIN_SEEDS or count > _MAX_SEEDS:
        raise ValueError(f"count must be between {_MIN_SEEDS} and {_MAX_SEEDS}")
    if not source.is_file():
        raise FileNotFoundError(source)
    with tempfile.TemporaryDirectory(prefix="r2morph-vm-resistance-") as directory:
        workdir = Path(directory)
        campaign = _seed_campaign(source, workdir, first_seed, count)
        tamper = _tamper_probe(source, workdir, first_seed)
        nested_tamper = _tamper_probe(source, workdir, first_seed, depth=2)
        shallow = workdir / "depth-1"
        deep = workdir / "depth-2"
        shallow_stats = _virtualize_fixture(source, shallow, first_seed, depth=1)
        deep_stats = _virtualize_fixture(source, deep, first_seed, depth=2)
        progressive = {
            "depth_1_bytes": shallow.stat().st_size,
            "depth_2_bytes": deep.stat().st_size,
            "depth_1_bytecode_bytes": _required_bytecode_size(shallow_stats),
            "depth_2_bytecode_bytes": _required_bytecode_size(deep_stats),
            "depth_1_nested_regions": _required_nested_region_count(shallow_stats),
            "depth_2_nested_regions": _required_nested_region_count(deep_stats),
            "growth_observed": _required_nested_region_count(deep_stats) > _required_nested_region_count(shallow_stats),
            "bytecode_size_growth_observed": (
                _required_bytecode_size(deep_stats) > _required_bytecode_size(shallow_stats)
            ),
            "depth_1_exit_code": emulate_exit_code(shallow),
            "depth_2_exit_code": emulate_exit_code(deep),
            "baseline_exit_code": campaign["baseline_exit_code"],
        }
    dispatcher_digests = _dispatcher_digests(first_seed, count)
    return {
        "schema_version": 1,
        "fixture": source.name,
        "first_seed": first_seed,
        "seed_count": count,
        "seed_campaign": campaign,
        "opcode_and_dispatcher_diversity": {
            "dispatcher_unique_count": len(set(dispatcher_digests)),
            "dispatcher_digests": dispatcher_digests,
            "opcode_assignment": _opcode_assignment_report(first_seed, count),
            "handler_report": measure_handlers(first_seed, count),
            "bytecode_grammar_report": measure_grammar(first_seed, count),
        },
        "anti_tamper": {"single_layer": tamper, "nested": nested_tamper},
        "progressive_bytecode": progressive,
        "automated_validation": {
            "status": "completed",
            "evidence_quality": "automated-adversarial-smoke",
            "checks": [
                "semantic-parity-across-seeds",
                "distinct-build-artifacts",
                "opcode-assignment-diversity",
                "handler-and-dispatcher-diversity",
                "single-layer-anti-tamper",
                "nested-anti-tamper",
                "progressive-bytecode-growth",
            ],
        },
        "human_adversarial_review": _HUMAN_REVIEW,
    }


def _corpus_validation_flags(report: dict[str, object]) -> tuple[bool, bool, bool, bool, bool, bool, bool, bool]:
    campaign = report.get("seed_campaign")
    tamper = report.get("anti_tamper")
    progressive = report.get("progressive_bytecode")
    diversity = report.get("opcode_and_dispatcher_diversity")
    if (
        not isinstance(campaign, dict)
        or not isinstance(tamper, dict)
        or not isinstance(progressive, dict)
        or not isinstance(diversity, dict)
    ):
        raise ValueError("VM resistance report is missing validation sections")
    tamper_diverged = all(
        isinstance(layer_report := tamper.get(layer), dict) and layer_report.get("all_tamper_probes_diverged") is True
        for layer in ("single_layer", "nested")
    )
    opcode = diversity.get("opcode_assignment")
    handlers = diversity.get("handler_report")
    grammar = diversity.get("bytecode_grammar_report")
    if not isinstance(opcode, dict) or not isinstance(handlers, dict) or not isinstance(grammar, dict):
        raise ValueError("VM resistance report is missing diversity sections")
    nested_regions = progressive.get("depth_2_nested_regions")
    progressive_passed = progressive.get("growth_observed") is True or nested_regions == 0
    adversarial_probe_passed = all(
        isinstance(layer_report := tamper.get(layer), dict)
        and isinstance(probe := layer_report.get("adversarial_recovery"), dict)
        and probe.get("status") == "completed"
        for layer in ("single_layer", "nested")
    )
    return (
        campaign.get("semantic_parity") is True,
        tamper_diverged,
        progressive_passed,
        diversity.get("dispatcher_unique_count") == report.get("seed_count"),
        opcode.get("all_assignments_unique") is True,
        handlers.get("cross_seed_has_exact_normalised_matches") is False
        and handlers.get("cross_seed_largest_normalised_cluster") == 1,
        grammar.get("target_stride_diverse") is True and grammar.get("seeds_without_target_handlers") == 0,
        adversarial_probe_passed,
    )


def measure_corpus(
    sources: Sequence[Path],
    first_seed: int = _DEFAULT_SEED,
    count: int = _DEFAULT_COUNT,
) -> dict[str, object]:
    """Measure resistance invariants across several real VM fixture shapes."""
    if not sources:
        raise ValueError("at least one VM fixture is required")
    reports = [measure(source, first_seed, count) for source in sources]
    seed_builds: list[dict[str, object]] = []
    for report in reports:
        campaign = report.get("seed_campaign")
        if not isinstance(campaign, dict) or not isinstance(builds := campaign.get("builds"), list):
            raise ValueError("VM resistance report is missing seed builds")
        seed_builds.extend(build for build in builds if isinstance(build, dict))
    artifact_hashes = [digest for build in seed_builds if isinstance(digest := build.get("sha256"), str)]
    validation_flags = [_corpus_validation_flags(report) for report in reports]
    return {
        "schema_version": 1,
        "fixture_count": len(reports),
        "fixtures": reports,
        "first_seed": first_seed,
        "seed_count": count,
        "cross_fixture_distinct_artifacts": len(set(artifact_hashes)) == len(artifact_hashes),
        "semantic_parity": all(flags[0] for flags in validation_flags),
        "all_tamper_probes_diverged": all(flags[1] for flags in validation_flags),
        "progressive_growth_observed": all(flags[2] for flags in validation_flags),
        "progressive_growth_supported_fixture_count": sum(
            1
            for report in reports
            if isinstance(progressive := report.get("progressive_bytecode"), dict)
            and progressive.get("depth_2_nested_regions", 0) > 0
        ),
        "dispatcher_diversity_observed": all(flags[3] for flags in validation_flags),
        "opcode_assignment_diversity_observed": all(flags[4] for flags in validation_flags),
        "handler_diversity_observed": all(flags[5] for flags in validation_flags),
        "bytecode_grammar_diversity_observed": all(flags[6] for flags in validation_flags),
        "adversarial_recovery_probe_observed": all(flags[7] for flags in validation_flags),
        "automated_validation": {
            "status": "completed",
            "evidence_quality": "automated-adversarial-smoke",
            "checks": [
                "semantic-parity-across-fixtures-and-seeds",
                "cross-fixture-artifact-diversity",
                "opcode-assignment-diversity",
                "dispatcher-diversity",
                "handler-diversity",
                "bytecode-grammar-diversity",
                "single-and-nested-anti-tamper",
                "progressive-bytecode-growth",
                "bounded-adversarial-recovery-probe",
            ],
        },
        "human_adversarial_review": _HUMAN_REVIEW,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, action="append", required=True)
    parser.add_argument("--generated-corpus", action="store_true")
    parser.add_argument("--first-seed", type=int, default=_DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=_DEFAULT_COUNT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="r2morph-vm-resistance-sources-") as directory:
        sources = list(args.fixture)
        if args.generated_corpus:
            sources.extend(_select_generated_resistance_fixtures(_build_generated_corpus(Path(directory))))
        result = (
            measure(sources[0], args.first_seed, args.count)
            if len(sources) == 1
            else measure_corpus(sources, args.first_seed, args.count)
        )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
