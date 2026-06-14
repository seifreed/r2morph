"""Rule-id helpers for SARIF reporting."""

from __future__ import annotations

MUTATION_RULE_IDS = {
    "nop": "RM001",
    "nop-insertion": "RM001",
    "substitute": "RM002",
    "instruction-substitution": "RM002",
    "register": "RM003",
    "register-substitution": "RM003",
    "block": "RM004",
    "block-reordering": "RM004",
    "dead-code": "RM005",
    "dead-code-injection": "RM005",
    "opaque": "RM006",
    "opaque-predicates": "RM006",
    "expand": "RM007",
    "instruction-expansion": "RM007",
    "cff": "RM008",
    "control-flow-flattening": "RM008",
}

VALIDATION_RULE_IDS = {
    "structural": "RV001",
    "runtime": "RV002",
    "semantic": "RV003",
    "cfg": "RV004",
    "cfg-integrity": "RV004",
}


def get_mutation_rule_id(pass_name: str) -> str:
    """Map a mutation pass name to a SARIF rule id."""
    return MUTATION_RULE_IDS.get(pass_name, "RM001")


def get_validation_rule_id(validation_type: str) -> str:
    """Map a validation type to a SARIF rule id."""
    return VALIDATION_RULE_IDS.get(validation_type, "RV001")


__all__ = ["get_mutation_rule_id", "get_validation_rule_id"]
