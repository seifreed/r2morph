"""Shared constants and version lookup for release-contract checks."""

from __future__ import annotations

import importlib
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_CI_JOBS = (
    "lint",
    "typecheck",
    "property-validation",
    "unit-tests",
    "integration-tests",
    "product-smoke-tests",
    "cross-platform-tests",
    "package-smoke",
)

MINIMUM_COVERAGE_PERCENT = 75

FULL_EVIDENCE_PERCENT = 100.0

TIER_1_MATURITY_PROFILE = "tier-1-native"

PUBLIC_CLI_ALIASES = {"block", "expand", "nop", "register", "substitute"}

VM_RESISTANCE_SEED_COUNT = 10

VM_HANDLER_COUNT = 255

MINIMUM_VM_VARIANT_COUNT = 3

MAXIMUM_VM_HANDLER_SIMILARITY_ABOVE_THRESHOLD_PERCENT = 20.0

REQUIRED_VM_TARGET_STRIDE_VALUES = [3, 4, 5]

REQUIRED_VM_TARGET_OPERATION = {"is_immediate": False, "mnemonic": "mov", "width": 64}

VM_ADVERSARIAL_VALIDATION = {
    "status": "pending-human-adversarial-review",
    "evidence_quality": "seed-diversity-only",
    "pending_scope": [
        "human-adversarial-validation",
        "isa-opcode-diversity",
        "handler-diversity",
        "dispatcher-diversity",
        "anti-tamper",
        "progressive-bytecode-protection",
    ],
}

VM_RESISTANCE_EVIDENCE_QUALITY = {
    "anti-tamper": "automated-native-tamper-smoke",
    "human-adversarial-validation": "automated-adversarial-smoke",
}

ADVERSARIAL_TOOL_SLOTS = {
    "angr",
    "binary-ninja",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "triton",
    "unicorn",
}

INDEPENDENT_REVIEW_CHECKS = {
    "adversarial_benchmark_evidence",
    "adversarial_continuous_evidence_gate",
    "adversarial_corpus_evidence",
    "adversarial_signoff_blockers",
    "angr_binary_ninja_availability",
    "binary_ninja_benchmark_contract",
    "differential_continuous_evidence_gate",
    "differential_corpus_gap_scope",
    "differential_platform_gap_scope",
    "fppackedidxnb_regression_evidence",
    "ghidra_corpus_evidence",
    "host_adversarial_shard_evidence",
    "ida_corpus_evidence",
    "ida_current_summary_evidence",
    "independent_fuzz_recheck",
    "official_target_scope",
    "parser_rewriter_fuzz_campaign",
    "pass_maturity_gap_scope",
    "release_blocker_ledger_scope",
    "support_matrix_consistency",
    "triton_corpus_evidence",
    "virtualization_fixture_coverage",
    "virtualization_fixture_headers",
    "vm_fail_closed_diagnostics_contract",
    "vm_resistance_adversarial_scope",
    "vm_semantic_gap_scope",
}

_MARKDOWN_LINK_PATTERN = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")

_DOCUMENTATION_LINK_FILES = (
    ROOT / "docs" / "independent-review-packet.md",
    ROOT / "docs" / "compatibility-corpus.md",
    ROOT / "docs" / "release-blockers.md",
)

_RELEASE_HONESTY_FILES = (
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "docs" / "independent-review-packet.md",
    ROOT / "docs" / "pass-maturity.md",
    ROOT / "docs" / "release-blockers.md",
)

_FORBIDDEN_RELEASE_CLAIMS = (
    "production-ready",
    "production ready",
    "ready to ship",
    "full parity",
    "universal protector",
    "vm milestone complete",
    "vm milestone approved",
    "anti-tamper approved",
    "progressive bytecode protection approved",
    "external human review passed",
)

_BANNED_BINARY_NINJA_OMISSION_PHRASES = (
    "Binary Ninja is explicitly omitted",
    "Binary Ninja is intentionally omitted",
    "Binary Ninja remains intentionally omitted",
    "Binary Ninja remains omitted by project decision",
    "Binary Ninja remains excluded by project decision",
)

_RELEASE_BLOCKER_FRAGMENTS = (
    "Per-pass maturity remains incomplete",
    "maturity_evidence_blockers",
    "maturity_blocker_totals",
    "Differential corpus coverage remains incomplete",
    "continuous_evidence_blockers",
    "continuous_evidence_blocker_totals",
    "extended_maturity_evidence_blockers",
    "extended_maturity_evidence_blocker_totals",
    "VM semantic coverage is complete for the declared ELF x86-64 scope",
    "vm_semantic_gap_scope",
    "vm_semantic_blocker_totals",
    "PE, Mach-O, ARM, and AArch64 remain preview or experimental",
    "parity_evidence_blockers",
    "parity_blocker_totals",
    "Binary Ninja is deliberately on hold for",
    "adversarial_evidence_blockers",
    "adversarial_evidence_blocker_totals",
    "adversarial_validation",
    "vm_resistance_blocker_totals",
    "anti-tamper and progressive bytecode protection",
    "Independent human review records signoff",
    "human_signoff",
    "release_decision",
)

_RELEASE_BLOCKER_IDS = tuple(f"RB-{index:03d}" for index in range(1, 8))

_RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT = 2

_RELEASE_BLOCKER_INDEX_AREAS = {
    "RB-001": "per-pass maturity",
    "RB-002": "differential evidence",
    "RB-003": "VM semantics",
    "RB-004": "cross-platform parity",
    "RB-005": "adversarial benchmark",
    "RB-006": "VM resistance",
    "RB-007": "human VM signoff",
}

_RELEASE_BLOCKER_ID_PATTERN = re.compile(r"\bRB-\d{3}\b")


def _check_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = project["project"]["version"]
    init_path = ROOT / "r2morph" / "__init__.py"
    if init_path.exists():
        public_version_matches = f'__version__ = "{package_version}"' in init_path.read_text(encoding="utf-8")
    else:
        public_version_matches = importlib.import_module("r2morph").__version__ == package_version
    if not public_version_matches:
        raise ValueError("package and public version must match")
    return package_version
