#!/usr/bin/env python3
"""Expand the declared pass support into an exhaustive matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_MATURITY_STRING_FIELDS = (
    ("false_positive_risk", "false_positive_risk_counts"),
    ("decompiler_effectiveness", "decompiler_effectiveness_counts"),
    ("compatibility", "compatibility_counts"),
    ("performance", "performance_counts"),
    ("instructions_affected", "instructions_affected_counts"),
)
_MATURITY_SEQUENCE_FIELDS = (
    ("formats", "maturity_format_counts"),
    ("architectures", "maturity_architecture_counts"),
    ("unit_tests", "unit_test_evidence_counts"),
    ("e2e_tests", "e2e_test_evidence_counts"),
)
_MATURITY_GAP_VALUES = {
    "performance": {"Not measured per pass."},
    "false_positive_risk": {"Not independently measured."},
    "decompiler_effectiveness": {"Not independently measured."},
    "compatibility": {"Composition with other passes is not contractually supported."},
    "instructions_affected": {"Not exhaustively catalogued."},
}
_MATURITY_GAP_EVIDENCE = {
    "performance": {
        "status": "per-pass-performance-incomplete",
        "evidence_quality": "partial-corpus-metrics",
        "evidence": ["docs/protection-maturity-corpus.json", "docs/pass-maturity.md"],
    },
    "false_positive_risk": {
        "status": "independent-false-positive-rate-incomplete",
        "evidence_quality": "declared-gap-scope",
        "evidence": ["docs/pass-maturity.md", "docs/release-blockers.md"],
    },
    "decompiler_effectiveness": {
        "status": "cross-tool-decompiler-evidence-incomplete",
        "evidence_quality": "partial-adversarial-corpus",
        "evidence": [
            "docs/protection-adversarial-tier1-2026-09-13-400c2a48-summary.json",
            "docs/pass-maturity.md",
        ],
    },
    "compatibility": {
        "status": "arbitrary-pass-composition-unsupported",
        "evidence_quality": "scheduled-corpus-gate",
        "evidence": ["docs/compatibility-corpus.md", "docs/pass-maturity.md"],
    },
    "instructions_affected": {
        "status": "affected-instruction-catalog-incomplete",
        "evidence_quality": "declared-gap-scope",
        "evidence": ["docs/pass-maturity.md", "docs/support-matrix.json"],
    },
    "native_evidence": {
        "status": "native-evidence-incomplete",
        "evidence_quality": "partial-native-regression",
        "evidence": ["docs/pass-maturity.md", "docs/protection-maturity.md"],
    },
}
_DIFFERENTIAL_PLATFORM_SCOPE = {"os": "linux", "format": "ELF", "architecture": "x86-64"}
_DIFFERENTIAL_PLATFORM_GAP_SCOPE = {
    "formats": ["Mach-O", "PE"],
    "architectures": ["AArch64", "ARM", "x86"],
}
_DIFFERENTIAL_PREVIEW_SMOKE_SCOPE = {
    "formats": ["Mach-O", "PE"],
    "architectures": ["AArch64"],
    "evidence": [
        ".github/workflows/differential-corpus.yml",
        "tests/integration/test_mutation_nop_insertion_arm64.py",
        "tests/integration/test_platform_deeper.py",
        "tests/integration/test_elf_arm64_native.py",
    ],
    "status": "preview-smoke-only",
}
_DIFFERENTIAL_CORPUS_GAP_SCOPE = {
    "corpus_families": [],
    "input_sources": [],
}
_ADVERSARIAL_EXPECTED_TOOLS = (
    "radare2",
    "objdump",
    "angr",
    "binary-ninja",
    "unicorn",
    "triton",
    "ida-pro",
    "ghidra",
    "custom",
)
_ADVERSARIAL_INCOMPLETE_TOOLS: tuple[str, ...] = ()
_DEFAULT_VM_SEMANTIC_GAP_SCOPE = (
    "memory",
    "direct-calls",
    "indirect-calls",
    "abi-varargs",
    "unwinding-exceptions",
    "tls-signals",
    "threads",
    "fp-simd",
    "ssa-liveness",
)
_VM_RESISTANCE_GAP_SCOPE = (
    "human-adversarial-validation",
    "isa-opcode-diversity",
    "handler-diversity",
    "dispatcher-diversity",
    "anti-tamper",
    "progressive-bytecode-protection",
)
_VM_RESISTANCE_GAP_EVIDENCE = {
    "human-adversarial-validation": {
        "status": "pending-human-adversarial-review",
        "evidence_quality": "seed-diversity-only",
        "evidence": [
            "docs/independent-review.json",
            "docs/protection-bytecode-grammar.json",
            "docs/protection-handler-clustering.json",
            ".github/workflows/adversarial-benchmark.yml",
            "scripts/vm_resistance_adversarial.py",
            "tests/integration/test_code_virtualization_real.py",
            "tests/integration/test_code_virtualization_diversification_real.py",
            "tests/integration/test_vm_resistance_adversarial.py",
        ],
    },
    "isa-opcode-diversity": {
        "status": "seed-diversity-only-incomplete",
        "evidence_quality": "seed-diversity-only",
        "evidence": [
            "docs/protection-bytecode-grammar.json",
            "scripts/vm_resistance_adversarial.py",
            "tests/integration/test_vm_resistance_adversarial.py",
        ],
    },
    "handler-diversity": {
        "status": "seed-diversity-only-incomplete",
        "evidence_quality": "seed-diversity-only",
        "evidence": ["docs/protection-handler-clustering.json", "scripts/vm_resistance_adversarial.py"],
    },
    "dispatcher-diversity": {
        "status": "seed-diversity-only-incomplete",
        "evidence_quality": "seed-diversity-only",
        "evidence": ["docs/protection-handler-clustering.json", "scripts/vm_resistance_adversarial.py"],
    },
    "anti-tamper": {
        "status": "seed-diversity-only-incomplete",
        "evidence_quality": "seed-diversity-only",
        "evidence": [
            "docs/protection-maturity.md",
            ".github/workflows/adversarial-benchmark.yml",
            "tests/integration/test_code_virtualization_real.py",
            "scripts/vm_resistance_adversarial.py",
            "tests/integration/test_vm_resistance_adversarial.py",
        ],
    },
    "progressive-bytecode-protection": {
        "status": "seed-diversity-only-incomplete",
        "evidence_quality": "seed-diversity-only",
        "evidence": [
            "docs/protection-bytecode-grammar.json",
            ".github/workflows/adversarial-benchmark.yml",
            "tests/integration/test_code_virtualization_real.py",
            "tests/integration/test_code_virtualization_diversification_real.py",
            "scripts/vm_resistance_adversarial.py",
            "tests/integration/test_vm_resistance_adversarial.py",
        ],
    },
}
_NATIVE_EVIDENCE_PROFILES = {"tier-1-native", "code-virtualization", "experimental-corpus-selected"}
FULL_EVIDENCE_PERCENT = 100.0


def _add_count(counts: dict[str, int], value: str) -> None:
    counts[value] = counts.get(value, 0) + 1


def _merge_profile_counts(profile_fields: dict[str, Any], summaries: dict[str, dict[str, int]]) -> None:
    for field, summary_name in _MATURITY_STRING_FIELDS:
        value = profile_fields.get(field)
        if isinstance(value, str):
            _add_count(summaries[summary_name], value)
    for field, summary_name in _MATURITY_SEQUENCE_FIELDS:
        values = profile_fields.get(field)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str):
                    _add_count(summaries[summary_name], value)


def _maturity_summary_counts(maturity: object) -> dict[str, dict[str, int]]:
    summaries = {
        "maturity_profile_counts": {},
        "false_positive_risk_counts": {},
        "decompiler_effectiveness_counts": {},
        "compatibility_counts": {},
        "performance_counts": {},
        "instructions_affected_counts": {},
        "maturity_format_counts": {},
        "maturity_architecture_counts": {},
        "unit_test_evidence_counts": {},
        "e2e_test_evidence_counts": {},
    }
    if not isinstance(maturity, dict):
        return summaries
    pass_profiles = maturity.get("pass_profiles")
    profiles = maturity.get("profiles")
    if not isinstance(pass_profiles, dict) or not isinstance(profiles, dict):
        return summaries
    for profile in pass_profiles.values():
        if not isinstance(profile, str):
            continue
        _add_count(summaries["maturity_profile_counts"], profile)
        profile_fields = profiles.get(profile)
        if isinstance(profile_fields, dict):
            _merge_profile_counts(profile_fields, summaries)
    return summaries


def _maturity_gap_passes(maturity: object) -> dict[str, list[str]]:
    gaps = {field: [] for field in _MATURITY_GAP_VALUES}
    if not isinstance(maturity, dict):
        return gaps
    pass_profiles = maturity.get("pass_profiles")
    profiles = maturity.get("profiles")
    if not isinstance(pass_profiles, dict) or not isinstance(profiles, dict):
        return gaps
    for pass_name, profile_name in pass_profiles.items():
        if not isinstance(pass_name, str) or not isinstance(profile_name, str):
            continue
        profile_fields = profiles.get(profile_name)
        if not isinstance(profile_fields, dict):
            continue
        for field, gap_values in _MATURITY_GAP_VALUES.items():
            if profile_fields.get(field) in gap_values:
                gaps[field].append(pass_name)
    return {field: sorted(pass_names) for field, pass_names in gaps.items() if pass_names}


def _maturity_gaps_by_pass(maturity: object) -> dict[str, list[str]]:
    gaps: dict[str, list[str]] = {}
    if not isinstance(maturity, dict):
        return gaps
    pass_profiles = maturity.get("pass_profiles")
    profiles = maturity.get("profiles")
    if not isinstance(pass_profiles, dict) or not isinstance(profiles, dict):
        return gaps
    for pass_name, profile_name in pass_profiles.items():
        if not isinstance(pass_name, str) or not isinstance(profile_name, str):
            continue
        profile_fields = profiles.get(profile_name)
        if not isinstance(profile_fields, dict):
            continue
        fields = [
            field for field, gap_values in _MATURITY_GAP_VALUES.items() if profile_fields.get(field) in gap_values
        ]
        if fields:
            gaps[pass_name] = sorted(fields)
    return dict(sorted(gaps.items()))


def _native_evidence_gap_passes(maturity: object) -> list[str]:
    if not isinstance(maturity, dict):
        return []
    pass_profiles = maturity.get("pass_profiles")
    if not isinstance(pass_profiles, dict):
        return []
    return sorted(
        pass_name
        for pass_name, profile_name in pass_profiles.items()
        if isinstance(pass_name, str) and profile_name not in _NATIVE_EVIDENCE_PROFILES
    )


def _maturity_evidence_blockers(
    maturity_gap_passes: dict[str, list[str]],
    maturity_gaps_by_pass: dict[str, list[str]],
    native_evidence_gap_passes: list[str],
) -> dict[str, object]:
    blockers: dict[str, object] = {}
    if native_evidence_gap_passes:
        blockers["native_evidence_gap_passes"] = native_evidence_gap_passes
    missing_fields = {field: pass_names for field, pass_names in maturity_gap_passes.items() if pass_names}
    if missing_fields:
        blockers["missing_fields_by_field"] = missing_fields
    if maturity_gaps_by_pass:
        blockers["missing_fields_by_pass"] = maturity_gaps_by_pass
    return blockers


def _maturity_gap_evidence(
    maturity_gap_passes: dict[str, list[str]],
    native_evidence_gap_passes: list[str],
) -> dict[str, object]:
    evidence = {
        field: {**_MATURITY_GAP_EVIDENCE[field], "passes": pass_names}
        for field, pass_names in maturity_gap_passes.items()
        if pass_names
    }
    if native_evidence_gap_passes:
        evidence["native_evidence"] = {
            **_MATURITY_GAP_EVIDENCE["native_evidence"],
            "passes": native_evidence_gap_passes,
        }
    return evidence


def _maturity_blocker_totals(
    maturity_gap_passes: dict[str, list[str]],
    maturity_gaps_by_pass: dict[str, list[str]],
    native_evidence_gap_passes: list[str],
) -> dict[str, int]:
    gap_counts = {f"{field}_gap_passes": len(pass_names) for field, pass_names in maturity_gap_passes.items()}
    total_field_gaps = sum(gap_counts.values())
    native_gap_count = len(native_evidence_gap_passes)
    return {
        "maturity_gap_categories": len([field for field, pass_names in maturity_gap_passes.items() if pass_names]),
        "native_evidence_gap_passes": native_gap_count,
        "passes_with_maturity_field_gaps": len(maturity_gaps_by_pass),
        "total_maturity_blockers": native_gap_count + total_field_gaps,
        "total_maturity_field_gaps": total_field_gaps,
        **gap_counts,
    }


def _vm_semantic_gap_scope(document: dict[str, Any]) -> list[str]:
    vm_semantics = document.get("vm_semantics")
    if not isinstance(vm_semantics, dict):
        return list(_DEFAULT_VM_SEMANTIC_GAP_SCOPE)
    gap_scope = vm_semantics.get("gap_scope")
    if not isinstance(gap_scope, list) or not all(isinstance(item, str) for item in gap_scope):
        return list(_DEFAULT_VM_SEMANTIC_GAP_SCOPE)
    return gap_scope


def _vm_semantic_fixture_coverage(document: dict[str, Any]) -> dict[str, object]:
    vm_semantics = document.get("vm_semantics")
    if not isinstance(vm_semantics, dict):
        return {}
    coverage = vm_semantics.get("fixture_coverage")
    return coverage if isinstance(coverage, dict) else {}


def _vm_semantic_gap_evidence(document: dict[str, Any]) -> dict[str, object]:
    vm_semantics = document.get("vm_semantics")
    if not isinstance(vm_semantics, dict):
        return {}
    evidence = vm_semantics.get("gap_evidence")
    return evidence if isinstance(evidence, dict) else {}


def _vm_semantic_evidence_blockers(gap_scope: list[str]) -> dict[str, object]:
    return {"vm_semantic_gap_scope": gap_scope}


def _vm_semantic_blocker_totals(gap_scope: list[str]) -> dict[str, int]:
    return {
        "total_vm_semantic_blockers": len(gap_scope),
        "vm_semantic_gap_scope": len(gap_scope),
    }


def _vm_resistance_evidence_blockers() -> dict[str, object]:
    return {"vm_resistance_gap_scope": list(_VM_RESISTANCE_GAP_SCOPE)}


def _vm_resistance_gap_evidence() -> dict[str, object]:
    return {gap: _VM_RESISTANCE_GAP_EVIDENCE[gap] for gap in _VM_RESISTANCE_GAP_SCOPE}


def _vm_resistance_blocker_totals() -> dict[str, int]:
    return {
        "total_vm_resistance_blockers": len(_VM_RESISTANCE_GAP_SCOPE),
        "vm_resistance_gap_scope": len(_VM_RESISTANCE_GAP_SCOPE),
    }


def _differential_evidence_scope() -> dict[str, object]:
    return {
        "platform_scope": dict(_DIFFERENTIAL_PLATFORM_SCOPE),
        "preview_smoke_scope": dict(_DIFFERENTIAL_PREVIEW_SMOKE_SCOPE),
        "platform_gap_scope": dict(_DIFFERENTIAL_PLATFORM_GAP_SCOPE),
        "corpus_gap_scope": dict(_DIFFERENTIAL_CORPUS_GAP_SCOPE),
    }


def _differential_gap_evidence() -> dict[str, object]:
    workflow = ".github/workflows/differential-corpus.yml"
    contract = "docs/compatibility-corpus.md"
    return {
        "platform_scope": {
            "status": "scheduled-official-target-only",
            "evidence_quality": "scheduled-corpus-gate",
            "evidence": [workflow, contract, "docs/protection-maturity-corpus.json"],
        },
        "preview_smoke_scope": {
            "status": "preview-smoke-only",
            "evidence_quality": "cross-platform-differential-smoke",
            "evidence": list(_DIFFERENTIAL_PREVIEW_SMOKE_SCOPE["evidence"]),
        },
        "platform_gap_scope": {
            "status": "platform-parity-incomplete",
            "evidence_quality": "declared-gap-scope",
            "evidence": [workflow, contract, "docs/support-matrix.json"],
        },
        "corpus_gap_scope": {
            "status": "corpus-breadth-incomplete",
            "evidence_quality": "declared-gap-scope",
            "evidence": [workflow, contract],
        },
    }


def _differential_evidence_blockers() -> dict[str, object]:
    return {
        "platform_gap_scope": dict(_DIFFERENTIAL_PLATFORM_GAP_SCOPE),
        "corpus_gap_scope": dict(_DIFFERENTIAL_CORPUS_GAP_SCOPE),
    }


def _differential_blocker_totals() -> dict[str, int]:
    platform_gaps = sum(len(values) for values in _DIFFERENTIAL_PLATFORM_GAP_SCOPE.values())
    corpus_gaps = sum(len(values) for values in _DIFFERENTIAL_CORPUS_GAP_SCOPE.values())
    return {
        "platform_gap_scope": platform_gaps,
        "corpus_gap_scope": corpus_gaps,
        "total_differential_blockers": platform_gaps + corpus_gaps,
    }


def _adversarial_benchmark_evidence() -> dict[str, object]:
    return {
        "expected_tools": list(_ADVERSARIAL_EXPECTED_TOOLS),
        "measured_available_tools": {
            "angr": {
                "status": "completed",
                "evidence": [
                    "docs/protection-adversarial-angr-local-2026-09-13-13214f9.json",
                    "docs/protection-adversarial-tier1-2026-09-13-400c2a48-summary.json",
                ],
            },
            "unicorn": {
                "status": "completed",
                "evidence": ["docs/protection-adversarial-benchmark.json"],
            },
            "ghidra": {
                "status": "completed",
                "evidence": ["docs/protection-ghidra-corpus.json"],
            },
            "ida-pro": {
                "status": "completed",
                "evidence": [
                    "docs/protection-ida-mcp-corpus-2026-09-06-646e0942-summary.json",
                    "docs/protection-ida-mcp-corpus-2026-09-06-646e0942.json",
                ],
            },
            "triton": {
                "status": "completed",
                "evidence": ["docs/protection-adversarial-corpus-2026-09-06-a727f304.json"],
            },
        },
        "unavailable_reference_tools": {
            "binary-ninja": {
                "status": "unavailable",
                "evidence": [
                    "docs/protection-adversarial-angr-local-2026-09-13-13214f9.json",
                    ".github/workflows/adversarial-benchmark.yml",
                ],
            }
        },
        "campaign_evidence": [
            ".github/workflows/adversarial-benchmark.yml",
            "scripts/adversarial_benchmark.py",
            "docs/protection-adversarial-tier1-2026-09-13-400c2a48-summary.json",
        ],
    }


def _adversarial_evidence_blockers() -> dict[str, object]:
    return {
        "incomplete_tool_coverage": list(_ADVERSARIAL_INCOMPLETE_TOOLS),
        "binary_ninja_unavailable": ["binary-ninja"],
        "comparable_campaign_scope": ["full-pass-full-tool-completion"],
    }


def _adversarial_blocker_totals() -> dict[str, int]:
    return {
        "incomplete_tool_coverage": len(_ADVERSARIAL_INCOMPLETE_TOOLS),
        "binary_ninja_unavailable": 1,
        "comparable_campaign_scope": 1,
        "total_adversarial_blockers": len(_ADVERSARIAL_INCOMPLETE_TOOLS) + 2,
    }


def _coverage_percent(evidenced: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(evidenced / total * 100.0, 2)


def _non_official_gap_targets(
    cells: list[dict[str, Any]],
    official_format: object,
    official_architecture: object,
) -> list[dict[str, object]]:
    targets: dict[tuple[str, str], dict[str, object]] = {}
    for cell in cells:
        binary_format = cell["format"]
        architecture = cell["architecture"]
        if binary_format == official_format and architecture == official_architecture:
            continue
        key = (binary_format, architecture)
        target = targets.setdefault(
            key,
            {
                "format": binary_format,
                "architecture": architecture,
                "evidenced_cells": 0,
                "not_supported_cells": 0,
            },
        )
        field = "evidenced_cells" if cell["status"] == "evidenced" else "not_supported_cells"
        target[field] = int(target[field]) + 1
    rows = []
    for target in targets.values():
        total = int(target["evidenced_cells"]) + int(target["not_supported_cells"])
        target["evidence_percent"] = _coverage_percent(int(target["evidenced_cells"]), total)
        rows.append(target)
    return sorted(rows, key=lambda target: (str(target["format"]), str(target["architecture"])))


def _parity_gap_scope(
    formats: tuple[str, ...],
    architectures: tuple[str, ...],
    official_format: object,
    official_architecture: object,
) -> dict[str, list[str]]:
    return {
        "formats": sorted(binary_format for binary_format in formats if binary_format != official_format),
        "architectures": sorted(
            architecture for architecture in architectures if architecture != official_architecture
        ),
    }


def _parity_evidence_blockers(
    gap_targets: list[dict[str, object]],
    gap_scope: dict[str, list[str]],
) -> dict[str, object]:
    blockers: dict[str, object] = {}
    incomplete_targets = [
        target
        for target in gap_targets
        if isinstance(target.get("evidence_percent"), int | float)
        and target["evidence_percent"] < FULL_EVIDENCE_PERCENT
    ]
    if incomplete_targets:
        blockers["non_official_gap_targets"] = incomplete_targets
    if gap_scope["formats"] or gap_scope["architectures"]:
        blockers["parity_gap_scope"] = gap_scope
    return blockers


def _parity_gap_evidence(gap_targets: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    zero_evidence = []
    preview_evidence = []
    for target in gap_targets:
        evidenced_cells = int(target["evidenced_cells"])
        row = {
            "format": target["format"],
            "architecture": target["architecture"],
            "evidenced_cells": evidenced_cells,
            "not_supported_cells": int(target["not_supported_cells"]),
            "evidence_percent": target["evidence_percent"],
        }
        if evidenced_cells == 0:
            zero_evidence.append(row)
        else:
            preview_evidence.append(row)
    return {
        "preview_evidence_targets": preview_evidence,
        "zero_evidence_targets": zero_evidence,
    }


def _parity_blocker_totals(
    gap_targets: list[dict[str, object]],
    gap_scope: dict[str, list[str]],
) -> dict[str, int]:
    incomplete_gap_targets = [
        target
        for target in gap_targets
        if isinstance(target.get("evidence_percent"), int | float)
        and target["evidence_percent"] < FULL_EVIDENCE_PERCENT
    ]
    missing_evidence_cells = sum(int(target["not_supported_cells"]) for target in incomplete_gap_targets)
    return {
        "non_official_missing_evidence_cells": missing_evidence_cells,
        "non_official_gap_targets": len(incomplete_gap_targets),
        "parity_gap_architectures": len(gap_scope["architectures"]),
        "parity_gap_formats": len(gap_scope["formats"]),
        "total_parity_blockers": len(incomplete_gap_targets)
        + len(gap_scope["architectures"])
        + len(gap_scope["formats"]),
    }


def build_matrix(document: dict[str, Any]) -> dict[str, Any]:
    """Build one explicit cell for every pass, format, and architecture."""
    formats = tuple(document.get("formats", {}))
    architectures = tuple(document.get("architectures", {}))
    official = document.get("official_target", {})
    official_format = official.get("format")
    official_architecture = official.get("architecture")
    cells: list[dict[str, Any]] = []
    stability_counts: dict[str, int] = {}
    for mutation_pass in document.get("passes", []):
        name = mutation_pass["name"]
        stability = mutation_pass.get("stability")
        if isinstance(stability, str):
            stability_counts[stability] = stability_counts.get(stability, 0) + 1
        supported_formats = set(mutation_pass.get("formats", []))
        supported_architectures = set(mutation_pass.get("architectures", []))
        evidence_cells = {(cell["format"], cell["architecture"]) for cell in mutation_pass.get("evidence_cells", [])}
        for binary_format in formats:
            for architecture in architectures:
                covered = (binary_format in supported_formats and architecture in supported_architectures) or (
                    binary_format,
                    architecture,
                ) in evidence_cells
                cells.append(
                    {
                        "pass": name,
                        "format": binary_format,
                        "architecture": architecture,
                        "status": "evidenced" if covered else "not-supported",
                        "evidence": mutation_pass.get("evidence", []) if covered else [],
                    }
                )
    evidenced = sum(1 for cell in cells if cell["status"] == "evidenced")
    official_evidenced = sum(
        1
        for cell in cells
        if cell["status"] == "evidenced"
        and cell["format"] == official_format
        and cell["architecture"] == official_architecture
    )
    official_not_supported = sum(
        1
        for cell in cells
        if cell["status"] == "not-supported"
        and cell["format"] == official_format
        and cell["architecture"] == official_architecture
    )
    non_official_evidenced = sum(
        1
        for cell in cells
        if cell["status"] == "evidenced"
        and (cell["format"] != official_format or cell["architecture"] != official_architecture)
    )
    non_official_not_supported = sum(
        1
        for cell in cells
        if cell["status"] == "not-supported"
        and (cell["format"] != official_format or cell["architecture"] != official_architecture)
    )
    official_cell_count = official_evidenced + official_not_supported
    non_official_cell_count = non_official_evidenced + non_official_not_supported
    maturity_summaries = _maturity_summary_counts(document.get("maturity"))
    maturity_gap_passes = _maturity_gap_passes(document.get("maturity"))
    maturity_gaps_by_pass = _maturity_gaps_by_pass(document.get("maturity"))
    native_evidence_gap_passes = _native_evidence_gap_passes(document.get("maturity"))
    non_official_gap_targets = _non_official_gap_targets(cells, official_format, official_architecture)
    parity_gap_scope = _parity_gap_scope(formats, architectures, official_format, official_architecture)
    vm_semantic_gap_scope = _vm_semantic_gap_scope(document)
    vm_semantic_fixture_coverage = _vm_semantic_fixture_coverage(document)
    vm_semantic_gap_evidence = _vm_semantic_gap_evidence(document)
    return {
        "dimensions": {
            "passes": [mutation_pass["name"] for mutation_pass in document.get("passes", [])],
            "formats": list(formats),
            "architectures": list(architectures),
        },
        "cell_count": len(cells),
        "summary": {
            "evidenced_cells": evidenced,
            "not_supported_cells": len(cells) - evidenced,
            "official_evidenced_cells": official_evidenced,
            "official_not_supported_cells": official_not_supported,
            "official_evidence_percent": _coverage_percent(official_evidenced, official_cell_count),
            "non_official_evidenced_cells": non_official_evidenced,
            "non_official_not_supported_cells": non_official_not_supported,
            "non_official_evidence_percent": _coverage_percent(non_official_evidenced, non_official_cell_count),
            "non_official_gap_targets": non_official_gap_targets,
            "parity_gap_scope": parity_gap_scope,
            "parity_gap_evidence": _parity_gap_evidence(non_official_gap_targets),
            "parity_evidence_blockers": _parity_evidence_blockers(
                non_official_gap_targets,
                parity_gap_scope,
            ),
            "parity_blocker_totals": _parity_blocker_totals(
                non_official_gap_targets,
                parity_gap_scope,
            ),
            "stability_counts": dict(sorted(stability_counts.items())),
            **{name: dict(sorted(counts.items())) for name, counts in maturity_summaries.items()},
            "maturity_gap_passes": maturity_gap_passes,
            "maturity_gaps_by_pass": maturity_gaps_by_pass,
            "native_evidence_gap_passes": native_evidence_gap_passes,
            "maturity_evidence_blockers": _maturity_evidence_blockers(
                maturity_gap_passes,
                maturity_gaps_by_pass,
                native_evidence_gap_passes,
            ),
            "maturity_gap_evidence": _maturity_gap_evidence(
                maturity_gap_passes,
                native_evidence_gap_passes,
            ),
            "maturity_blocker_totals": _maturity_blocker_totals(
                maturity_gap_passes,
                maturity_gaps_by_pass,
                native_evidence_gap_passes,
            ),
            "differential_evidence_scope": _differential_evidence_scope(),
            "differential_gap_evidence": _differential_gap_evidence(),
            "differential_evidence_blockers": _differential_evidence_blockers(),
            "differential_blocker_totals": _differential_blocker_totals(),
            "adversarial_benchmark_evidence": _adversarial_benchmark_evidence(),
            "adversarial_evidence_blockers": _adversarial_evidence_blockers(),
            "adversarial_blocker_totals": _adversarial_blocker_totals(),
            "vm_semantic_gap_scope": vm_semantic_gap_scope,
            "vm_semantic_fixture_coverage": vm_semantic_fixture_coverage,
            "vm_semantic_gap_evidence": vm_semantic_gap_evidence,
            "vm_semantic_evidence_blockers": _vm_semantic_evidence_blockers(vm_semantic_gap_scope),
            "vm_semantic_blocker_totals": _vm_semantic_blocker_totals(vm_semantic_gap_scope),
            "vm_resistance_gap_scope": list(_VM_RESISTANCE_GAP_SCOPE),
            "vm_resistance_gap_evidence": _vm_resistance_gap_evidence(),
            "vm_resistance_evidence_blockers": _vm_resistance_evidence_blockers(),
            "vm_resistance_blocker_totals": _vm_resistance_blocker_totals(),
        },
        "cells": cells,
    }


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("support matrix must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix", type=Path, default=Path("docs/support-matrix.json"), nargs="?")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write and args.check:
        parser.error("--write and --check are mutually exclusive")
    document = _load(args.matrix)
    expected = build_matrix(document)
    if args.check:
        if document.get("matrix") != expected:
            raise SystemExit("support matrix is missing an up-to-date exhaustive matrix")
    elif args.write:
        document["matrix"] = expected
        args.matrix.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    else:
        print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
