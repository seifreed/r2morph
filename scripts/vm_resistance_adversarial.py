#!/usr/bin/env python3
"""Run bounded automated adversarial checks for diversified VM builds.

The report is evidence for automated regression gates only.  It deliberately
keeps human adversarial review as a separate, pending release decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

# Keep direct CLI execution equivalent to importing this module from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from scripts.protection_bytecode_grammar import measure as measure_grammar
from scripts.protection_handler_clustering import measure as measure_handlers
from tests.integration.elf_emulator import emulate_exit_code

_DEFAULT_SEED = 20260915
_DEFAULT_COUNT = 10
_MIN_SEEDS = 2
_MAX_SEEDS = 32
_VM_ENTRY_SIGNATURES = tuple(b"\x48\x81\xec" + size.to_bytes(4, "little") for size in (0x400, 0x420, 0x440, 0x460))
_TAMPER_OFFSETS = (0x10, 0x18, 0x20, 0x28, 0x30, 0x40, 0x50, 0x60)
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _find_vm_entry(data: bytes) -> int:
    return next((offset for signature in _VM_ENTRY_SIGNATURES if (offset := data.find(signature)) >= 0), -1)


def _virtualize_fixture(source: Path, destination: Path, seed: int, depth: int | None = None) -> dict[str, object]:
    shutil.copyfile(source, destination)
    config: dict[str, object] = {"probability": 1.0, "seed": seed}
    if depth is not None:
        config["vm_nesting_depth"] = depth
    with Binary(destination, writable=True) as binary:
        stats = CodeVirtualizationPass(config=config).apply(binary)
        binary.save()
    return stats


def _required_bytecode_size(stats: dict[str, object]) -> int:
    value = stats.get("total_bytecode_bytes")
    if not isinstance(value, int):
        raise ValueError("virtualization report is missing total_bytecode_bytes")
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
    data = bytearray(protected.read_bytes())
    vm_entry = _find_vm_entry(bytes(data))
    if vm_entry < 0 or any(vm_entry + offset >= len(data) for offset in _TAMPER_OFFSETS):
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
        probes.append(
            {
                "offset": offset,
                "tampered_exit_code": tampered_exit,
                "diverged": tampered_exit != original_exit,
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
            "growth_observed": _required_bytecode_size(deep_stats) > _required_bytecode_size(shallow_stats),
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


def _corpus_validation_flags(report: dict[str, object]) -> tuple[bool, bool, bool]:
    campaign = report.get("seed_campaign")
    tamper = report.get("anti_tamper")
    progressive = report.get("progressive_bytecode")
    if not isinstance(campaign, dict) or not isinstance(tamper, dict) or not isinstance(progressive, dict):
        raise ValueError("VM resistance report is missing validation sections")
    tamper_diverged = all(
        isinstance(layer_report := tamper.get(layer), dict) and layer_report.get("all_tamper_probes_diverged") is True
        for layer in ("single_layer", "nested")
    )
    return (
        campaign.get("semantic_parity") is True,
        tamper_diverged,
        progressive.get("growth_observed") is True,
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
        "automated_validation": {
            "status": "completed",
            "evidence_quality": "automated-adversarial-smoke",
            "checks": [
                "semantic-parity-across-fixtures-and-seeds",
                "cross-fixture-artifact-diversity",
                "opcode-assignment-diversity",
                "single-and-nested-anti-tamper",
                "progressive-bytecode-growth",
            ],
        },
        "human_adversarial_review": _HUMAN_REVIEW,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, action="append", required=True)
    parser.add_argument("--first-seed", type=int, default=_DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=_DEFAULT_COUNT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = (
        measure(args.fixture[0], args.first_seed, args.count)
        if len(args.fixture) == 1
        else measure_corpus(args.fixture, args.first_seed, args.count)
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
