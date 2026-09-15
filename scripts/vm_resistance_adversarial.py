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
import tempfile
from collections.abc import Sequence
from pathlib import Path

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
            "depth_1_bytecode_bytes": shallow_stats.get("total_bytecode_bytes", 0),
            "depth_2_bytecode_bytes": deep_stats.get("total_bytecode_bytes", 0),
            "growth_observed": deep_stats.get("total_bytecode_bytes", 0) > shallow_stats.get("total_bytecode_bytes", 0),
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
                "handler-and-dispatcher-diversity",
                "single-layer-anti-tamper",
                "nested-anti-tamper",
                "progressive-bytecode-growth",
            ],
        },
        "human_adversarial_review": _HUMAN_REVIEW,
    }


def measure_corpus(
    sources: Sequence[Path],
    first_seed: int = _DEFAULT_SEED,
    count: int = _DEFAULT_COUNT,
) -> dict[str, object]:
    """Measure resistance invariants across several real VM fixture shapes."""
    if not sources:
        raise ValueError("at least one VM fixture is required")
    reports = [measure(source, first_seed, count) for source in sources]
    seed_builds = [
        build for report in reports for build in report["seed_campaign"]["builds"] if isinstance(build, dict)
    ]
    artifact_hashes = [build["sha256"] for build in seed_builds]
    return {
        "schema_version": 1,
        "fixture_count": len(reports),
        "fixtures": reports,
        "first_seed": first_seed,
        "seed_count": count,
        "cross_fixture_distinct_artifacts": len(set(artifact_hashes)) == len(artifact_hashes),
        "semantic_parity": all(report["seed_campaign"]["semantic_parity"] for report in reports),
        "all_tamper_probes_diverged": all(
            report["anti_tamper"][layer]["all_tamper_probes_diverged"]
            for report in reports
            for layer in ("single_layer", "nested")
        ),
        "progressive_growth_observed": all(report["progressive_bytecode"]["growth_observed"] for report in reports),
        "automated_validation": {
            "status": "completed",
            "evidence_quality": "automated-adversarial-smoke",
            "checks": [
                "semantic-parity-across-fixtures-and-seeds",
                "cross-fixture-artifact-diversity",
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
