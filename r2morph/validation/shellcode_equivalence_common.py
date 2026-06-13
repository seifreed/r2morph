"""Shared shellcode-equivalence helpers."""

from __future__ import annotations

from typing import Any


def record_mismatch(
    region_report: dict[str, Any],
    mismatches: list[dict[str, Any]],
    mutation: dict[str, Any],
    observable: str,
) -> None:
    """Append an observable mismatch to both the region report and the run list."""
    region_report["mismatches"].append(observable)
    mismatches.append(
        {
            "start_address": mutation["start_address"],
            "end_address": mutation["end_address"],
            "observable": observable,
        }
    )


def load_shellcode_state_pair(
    angr_module: Any,
    options: Any,
    mutation: dict[str, Any],
    shellcode_arch: str,
) -> tuple[Any, Any, Any, Any]:
    """Load original/mutated shellcode and create a blank state for each."""
    original_project = angr_module.load_shellcode(bytes.fromhex(mutation["original_bytes"]), arch=shellcode_arch)
    mutated_project = angr_module.load_shellcode(bytes.fromhex(mutation["mutated_bytes"]), arch=shellcode_arch)
    add_options = {
        options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    }
    original_state = original_project.factory.blank_state(
        addr=original_project.entry,
        add_options=add_options,
    )
    mutated_state = mutated_project.factory.blank_state(
        addr=mutated_project.entry,
        add_options=add_options,
    )
    return original_project, original_state, mutated_project, mutated_state
