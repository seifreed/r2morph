"""Result assembly helpers for real-binary region comparison."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RegionReportInput:
    """Resolved addresses and bounded-step observations for one region."""

    mutation: dict[str, object]
    resolved_original: object
    resolved_mutated: object
    step_budget: int
    region_exit_budget: int
    original_steps: int
    mutated_steps: int
    original_trace_addresses: list[object]
    mutated_trace_addresses: list[object]
    compared_registers: list[str]


def build_region_report(result: RegionReportInput) -> dict[str, object]:
    """Build the region-report skeleton before finalization."""
    return {
        "start_address": result.mutation["start_address"],
        "end_address": result.mutation["end_address"],
        "original_loaded_address": result.resolved_original,
        "mutated_loaded_address": result.resolved_mutated,
        "step_budget": result.step_budget,
        "region_exit_budget": result.region_exit_budget,
        "step_strategy": "region-exit",
        "original_region_exit_steps": result.original_steps,
        "mutated_region_exit_steps": result.mutated_steps,
        "original_trace_addresses": result.original_trace_addresses,
        "mutated_trace_addresses": result.mutated_trace_addresses,
        "registers_checked": [*result.compared_registers, "eflags", "stack_delta"],
        "mismatches": [],
    }


def build_binary_comparison_result(
    compared_regions: list[dict[str, object]],
    mismatches: list[dict[str, object]],
    previous_binary_path: Path,
    current_binary_path: Path,
) -> dict[str, object]:
    """Assemble the real-binary symbolic comparison result payload."""
    return {
        "symbolic_binary_check_performed": bool(compared_regions),
        "symbolic_binary_equivalent": not mismatches if compared_regions else False,
        "symbolic_binary_reason": (
            "bounded real-binary symbolic effects matched"
            if compared_regions and not mismatches
            else (
                "bounded real-binary symbolic effects diverged"
                if compared_regions
                else "no eligible regions for real-binary symbolic comparison"
            )
        ),
        "symbolic_binary_regions": compared_regions,
        "symbolic_binary_mismatches": mismatches,
        "symbolic_binary_paths": {
            "original": str(previous_binary_path),
            "mutated": str(current_binary_path),
        },
    }
