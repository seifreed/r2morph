"""Observable comparison helpers for real-binary region comparison."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from r2morph.validation.binary_region_memory import collect_memory_write_signatures


def compare_register_states(
    original_final: Any,
    mutated_final: Any,
    compared_registers: list[str],
    record: Callable[[str], None],
) -> None:
    """Record register and eflags divergences between the two final states."""
    for reg_name in compared_registers:
        if not hasattr(original_final.regs, reg_name) or not hasattr(mutated_final.regs, reg_name):
            continue
        left = getattr(original_final.regs, reg_name)
        right = getattr(mutated_final.regs, reg_name)
        if original_final.solver.satisfiable(extra_constraints=[left != right]):
            record(reg_name)

    if (
        hasattr(original_final.regs, "eflags")
        and hasattr(mutated_final.regs, "eflags")
        and original_final.solver.satisfiable(
            extra_constraints=[original_final.regs.eflags != mutated_final.regs.eflags]
        )
    ):
        record("eflags")


def compare_stack_and_memory(
    original_final: Any,
    mutated_final: Any,
    stack_reg: str,
    region_report: dict[str, Any],
    record: Callable[[str], None],
) -> None:
    """Record stack-pointer and memory-write divergences; expose write signatures."""
    original_stack = getattr(original_final.regs, stack_reg)
    mutated_stack = getattr(mutated_final.regs, stack_reg)
    if original_final.solver.satisfiable(extra_constraints=[original_stack != mutated_stack]):
        record("stack_delta")

    original_writes = collect_memory_write_signatures(original_final)
    mutated_writes = collect_memory_write_signatures(mutated_final)
    region_report["original_memory_writes"] = original_writes
    region_report["mutated_memory_writes"] = mutated_writes
    region_report["original_memory_write_count"] = len(original_writes)
    region_report["mutated_memory_write_count"] = len(mutated_writes)
    if original_writes != mutated_writes:
        record("memory_writes")


@dataclass(frozen=True)
class ObservableComparison:
    """Final symbolic states and report sinks for one mutation region."""

    region_report: dict[str, Any]
    mismatches: list[dict[str, Any]]
    mutation: dict[str, Any]
    original_final: Any
    mutated_final: Any
    compared_registers: list[str]
    stack_reg: str


def check_observables(comparison: ObservableComparison) -> None:
    """Compare observables between original and mutated final states."""
    start = comparison.mutation["start_address"]
    end = comparison.mutation["end_address"]

    def _record(observable: str) -> None:
        comparison.region_report["mismatches"].append(observable)
        comparison.mismatches.append({"start_address": start, "end_address": end, "observable": observable})

    if getattr(comparison.original_final, "addr", None) != getattr(comparison.mutated_final, "addr", None):
        _record("successor_address")

    compare_register_states(
        comparison.original_final,
        comparison.mutated_final,
        comparison.compared_registers,
        _record,
    )
    compare_stack_and_memory(
        comparison.original_final,
        comparison.mutated_final,
        comparison.stack_reg,
        comparison.region_report,
        _record,
    )
