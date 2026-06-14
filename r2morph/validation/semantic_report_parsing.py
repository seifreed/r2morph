"""Semantic-validation report parsing helpers."""

from __future__ import annotations

from typing import Any

from r2morph.validation.semantic_invariant_models import (
    InvariantCategory,
    InvariantSeverity,
    InvariantViolation,
)
from r2morph.validation.semantic_models import (
    MutationRegion,
    ObservableComparison,
    SemanticCheck,
    ValidationMode,
    ValidationResultStatus,
)


def build_observable_comparison(data: dict[str, Any]) -> ObservableComparison:
    """Parse a serialized observable comparison."""
    return ObservableComparison(
        register_matches=dict(data.get("register_matches", {})),
        register_values={
            name: (value["original"], value["mutated"])
            for name, value in data.get("register_values", {}).items()
        },
        flag_matches=dict(data.get("flag_matches", {})),
        memory_matches={int(addr, 16): bool(match) for addr, match in data.get("memory_matches", {}).items()},
        stack_delta_match=bool(data.get("stack_delta_match", True)),
        successor_match=bool(data.get("successor_match", True)),
        successor_addresses=(
            [int(addr, 16) for addr in data.get("successor_addresses", {}).get("original", [])],
            [int(addr, 16) for addr in data.get("successor_addresses", {}).get("mutated", [])],
        ),
    )


def build_semantic_validation_result(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a serialized semantic-validation result into constructor kwargs."""
    region = MutationRegion(
        start_address=data["region"]["start_address"],
        end_address=data["region"]["end_address"],
        original_bytes=bytes.fromhex(data["region"]["original_bytes"]),
        mutated_bytes=bytes.fromhex(data["region"]["mutated_bytes"]),
        pass_name=data["region"]["pass_name"],
        function_address=data["region"].get("function_address"),
        original_disasm=data["region"].get("original_disasm"),
        mutated_disasm=data["region"].get("mutated_disasm"),
        metadata=data["region"].get("metadata", {}),
    )
    checks = [
        SemanticCheck(
            check_name=c["check_name"],
            category=InvariantCategory(c["category"]),
            passed=c["passed"],
            message=c["message"],
            details=c.get("details", {}),
        )
        for c in data.get("checks", [])
    ]
    violations = [
        InvariantViolation(
            invariant_name=v["invariant_name"],
            category=InvariantCategory(v["category"]),
            severity=InvariantSeverity(v["severity"]),
            address_range=tuple(v["address_range"]),
            message=v["message"],
            expected=v.get("expected"),
            actual=v.get("actual"),
            repair_hint=v.get("repair_hint"),
            metadata=v.get("metadata", {}),
        )
        for v in data.get("violations", [])
    ]

    return {
        "region": region,
        "status": ValidationResultStatus(data["status"]),
        "checks": checks,
        "violations": violations,
        "observables": None if data.get("observables") is None else build_observable_comparison(data["observables"]),
        "symbolic_status": data.get("symbolic_status", "not_requested"),
        "symbolic_details": data.get("symbolic_details", {}),
        "execution_time_seconds": data.get("execution_time_seconds", 0.0),
        "error_message": data.get("error_message"),
    }


def build_semantic_validation_report(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a serialized semantic-validation report into constructor kwargs."""
    results = [build_semantic_validation_result(result) for result in data.get("results", [])]
    return {
        "binary_path": data["binary_path"],
        "timestamp": data["timestamp"],
        "mode": ValidationMode(data["mode"]),
        "results": results,
        "summary": data.get("summary", {}),
        "metadata": data.get("metadata", {}),
    }
