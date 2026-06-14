"""Static catalogs for SARIF reporting."""

from __future__ import annotations

from typing import Any

MUTATION_RULES: list[dict[str, Any]] = [
    {
        "id": "RM001",
        "name": "nop-insertion",
        "short_description": "NOP instruction insertion",
        "full_description": "Inserts benign NOP instructions at safe locations",
        "default_level": "note",
    },
    {
        "id": "RM002",
        "name": "instruction-substitution",
        "short_description": "Instruction substitution",
        "full_description": "Replaces instructions with semantically equivalent alternatives",
        "default_level": "note",
    },
    {
        "id": "RM003",
        "name": "register-substitution",
        "short_description": "Register substitution",
        "full_description": "Substitutes registers while preserving program semantics",
        "default_level": "note",
    },
    {
        "id": "RM004",
        "name": "block-reordering",
        "short_description": "Basic block reordering",
        "full_description": "Reorders basic blocks to change code layout",
        "default_level": "warning",
    },
    {
        "id": "RM005",
        "name": "dead-code-injection",
        "short_description": "Dead code injection",
        "full_description": "Injects dead code sequences that execute but have no effect",
        "default_level": "warning",
    },
    {
        "id": "RM006",
        "name": "opaque-predicates",
        "short_description": "Opaque predicate insertion",
        "full_description": "Inserts conditional branches with known outcomes",
        "default_level": "warning",
    },
    {
        "id": "RM007",
        "name": "instruction-expansion",
        "short_description": "Instruction expansion",
        "full_description": "Expands instructions into longer equivalent sequences",
        "default_level": "note",
    },
    {
        "id": "RM008",
        "name": "control-flow-flattening",
        "short_description": "Control flow flattening",
        "full_description": "Flattens control flow to obscure program structure",
        "default_level": "warning",
    },
]

VALIDATION_RULES: list[dict[str, Any]] = [
    {
        "id": "RV001",
        "name": "structural-validation",
        "short_description": "Structural validation failure",
        "full_description": "Binary structure validation detected an issue",
        "default_level": "error",
    },
    {
        "id": "RV002",
        "name": "runtime-validation",
        "short_description": "Runtime validation failure",
        "full_description": "Runtime behavior validation detected a mismatch",
        "default_level": "error",
    },
    {
        "id": "RV003",
        "name": "semantic-validation",
        "short_description": "Semantic validation failure",
        "full_description": "Semantic equivalence validation failed",
        "default_level": "error",
    },
    {
        "id": "RV004",
        "name": "cfg-integrity",
        "short_description": "CFG integrity violation",
        "full_description": "Control flow graph integrity check failed",
        "default_level": "error",
    },
]

MITRE_ATTACK: dict[str, dict[str, str]] = {
    "nop": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "nop-insertion": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "substitute": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "instruction-substitution": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "register": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "register-substitution": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "block": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "block-reordering": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "dead-code": {"id": "T1027.001", "name": "Binary Padding"},
    "dead-code-injection": {"id": "T1027.001", "name": "Binary Padding"},
    "opaque": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "opaque-predicates": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "expand": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "instruction-expansion": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "cff": {"id": "T1027.002", "name": "Software Packing"},
    "control-flow-flattening": {"id": "T1027.002", "name": "Software Packing"},
}
