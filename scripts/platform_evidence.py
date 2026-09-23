#!/usr/bin/env python3
"""Summarize cross-platform JUnit evidence without hiding incomplete targets."""

from __future__ import annotations

import argparse
import importlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

_DEFUSED_ELEMENT_TREE = cast(Any, importlib.import_module("defusedxml.ElementTree"))

_REQUIRED_CASES = {
    "macos-arm64": (
        "test_macho_handler_repair_and_codesign",
        "test_nop_insertion_arm64_preserves_native_output",
        "test_instruction_substitution_arm64_preserves_native_output",
        "test_nop_then_instruction_substitution_arm64_preserves_native_output",
        "test_register_substitution_arm64_preserves_generated_native_execution",
        "test_constant_unfolding_arm64_preserves_native_output",
        "test_x86_mutation_sequence_preserves_native_exit_code",
        "test_instruction_substitution_pe_x86_64_preserves_real_integrity",
        "test_code_virtualization_pe_x86_64_target_is_rejected_before_mutation",
        "test_code_virtualization_macho_arm64_target_is_rejected_before_mutation",
    ),
    "windows-pe": (
        "test_pe_handler_checksum",
        "test_pe_handler_checksum_and_imports",
        "test_pe_handler_extended",
        "test_pe_handler_real_binary",
        "test_nop_insertion_pe_x86_64_preserves_repaired_integrity",
        "test_instruction_substitution_pe_fixture_preserves_windows_exit_code",
        "test_register_substitution_pe_x86_64_preserves_native_execution",
        "test_constant_unfolding_pe_x86_64_preserves_native_execution",
        "test_tier1_pass_composition_pe_x86_64_preserves_native_execution",
        "test_multiple_mutation_passes_on_x86_binary",
    ),
    "elf-arm64": (
        "test_elf_arm64_nop_insertion_preserves_native_exit_code",
        "test_elf_arm64_instruction_substitution_preserves_native_exit_code",
        "test_elf_arm64_register_substitution_preserves_native_exit_code",
        "test_elf_arm64_complex_pass_sequence_preserves_native_exit_code",
        "test_elf_arm64_constant_unfolding_zero_preserves_native_exit_code",
        "test_elf_arm64_instruction_expansion_preserves_native_exit_code",
    ),
    "elf-x86-32": (
        "test_elf_x86_32_instruction_substitution_preserves_native_exit_code",
        "test_elf_x86_32_nop_insertion_preserves_native_exit_code",
        "test_elf_x86_32_register_substitution_preserves_native_exit_code",
        "test_elf_x86_32_complex_pass_sequence_preserves_native_exit_code",
        "test_elf_x86_32_constant_unfolding_zero_preserves_native_exit_code",
        "test_elf_x86_32_instruction_expansion_preserves_native_exit_code",
    ),
    "elf-arm-32": (
        "test_elf_arm32_instruction_substitution_preserves_emulated_exit_code",
        "test_elf_arm32_nop_insertion_preserves_emulated_exit_code",
        "test_elf_arm32_register_substitution_preserves_emulated_exit_code",
        "test_elf_arm32_complex_pass_sequence_preserves_emulated_exit_code",
        "test_elf_arm32_constant_unfolding_zero_preserves_emulated_exit_code",
        "test_elf_arm32_instruction_expansion_preserves_emulated_exit_code",
    ),
}
_PASS_CASES = {
    "macos-arm64": {
        "NopInsertion": "test_nop_insertion_arm64_preserves_native_output",
        "InstructionSubstitution": "test_instruction_substitution_arm64_preserves_native_output",
        "Composition": "test_nop_then_instruction_substitution_arm64_preserves_native_output",
        "RegisterSubstitution": "test_register_substitution_arm64_preserves_generated_native_execution",
        "ConstantUnfolding": "test_constant_unfolding_arm64_preserves_native_output",
    },
    "windows-pe": {
        "NopInsertion": "test_nop_insertion_pe_x86_64_preserves_repaired_integrity",
        "InstructionSubstitution": "test_instruction_substitution_pe_fixture_preserves_windows_exit_code",
        "RegisterSubstitution": "test_register_substitution_pe_x86_64_preserves_native_execution",
        "ConstantUnfolding": "test_constant_unfolding_pe_x86_64_preserves_native_execution",
        "Composition": "test_tier1_pass_composition_pe_x86_64_preserves_native_execution",
    },
    "elf-arm64": {
        "NopInsertion": "test_elf_arm64_nop_insertion_preserves_native_exit_code",
        "InstructionSubstitution": "test_elf_arm64_instruction_substitution_preserves_native_exit_code",
        "RegisterSubstitution": "test_elf_arm64_register_substitution_preserves_native_exit_code",
        "ConstantUnfolding": "test_elf_arm64_constant_unfolding_zero_preserves_native_exit_code",
        "InstructionExpansion": "test_elf_arm64_instruction_expansion_preserves_native_exit_code",
        "Composition": "test_elf_arm64_complex_pass_sequence_preserves_native_exit_code",
    },
    "elf-x86-32": {
        "NopInsertion": "test_elf_x86_32_nop_insertion_preserves_native_exit_code",
        "InstructionSubstitution": "test_elf_x86_32_instruction_substitution_preserves_native_exit_code",
        "RegisterSubstitution": "test_elf_x86_32_register_substitution_preserves_native_exit_code",
        "ConstantUnfolding": "test_elf_x86_32_constant_unfolding_zero_preserves_native_exit_code",
        "InstructionExpansion": "test_elf_x86_32_instruction_expansion_preserves_native_exit_code",
        "Composition": "test_elf_x86_32_complex_pass_sequence_preserves_native_exit_code",
    },
    "elf-arm-32": {
        "NopInsertion": "test_elf_arm32_nop_insertion_preserves_emulated_exit_code",
        "InstructionSubstitution": "test_elf_arm32_instruction_substitution_preserves_emulated_exit_code",
        "RegisterSubstitution": "test_elf_arm32_register_substitution_preserves_emulated_exit_code",
        "ConstantUnfolding": "test_elf_arm32_constant_unfolding_zero_preserves_emulated_exit_code",
        "InstructionExpansion": "test_elf_arm32_instruction_expansion_preserves_emulated_exit_code",
        "Composition": "test_elf_arm32_complex_pass_sequence_preserves_emulated_exit_code",
    },
}


def _pass_evidence(names: Sequence[str], required_cases: dict[str, str]) -> dict[str, dict[str, Any]]:
    return {
        pass_name: {
            "required_case": case_name,
            "present": any(name.startswith(case_name) for name in names),
            "status": "complete" if any(name.startswith(case_name) for name in names) else "incomplete",
        }
        for pass_name, case_name in sorted(required_cases.items())
    }


def _report_summary(
    path: Path,
    required_cases: Sequence[str],
    pass_cases: dict[str, str],
) -> dict[str, Any]:
    root = _DEFUSED_ELEMENT_TREE.parse(path).getroot()
    cases = root.findall(".//testcase")
    names = [case.attrib.get("name", "") for case in cases]
    failures = len(root.findall(".//failure"))
    errors = len(root.findall(".//error"))
    skipped = len(root.findall(".//skipped"))
    missing_required_cases = [
        required for required in required_cases if not any(name.startswith(required) for name in names)
    ]
    pass_evidence = _pass_evidence(names, pass_cases)
    complete = (
        not failures
        and not errors
        and not skipped
        and not missing_required_cases
        and all(row["status"] == "complete" for row in pass_evidence.values())
        and bool(cases)
    )
    return {
        "report": path.name,
        "case_count": len(cases),
        "failure_count": failures,
        "error_count": errors,
        "skipped_count": skipped,
        "required_case": required_cases[0],
        "required_cases": list(required_cases),
        "required_case_present": not missing_required_cases,
        "missing_required_cases": missing_required_cases,
        "pass_evidence": pass_evidence,
        "status": "complete" if complete else "incomplete",
    }


def summarize_platform_reports(root: Path) -> dict[str, Any]:
    """Build a bounded summary for the declared cross-platform smoke targets."""
    platforms: dict[str, dict[str, Any]] = {}
    for platform_name, required_cases in _REQUIRED_CASES.items():
        reports = sorted((root / platform_name).glob("*.xml"))
        if len(reports) != 1:
            platforms[platform_name] = {
                "report": None,
                "case_count": 0,
                "failure_count": 0,
                "error_count": 0,
                "skipped_count": 0,
                "required_case": required_cases[0],
                "required_cases": list(required_cases),
                "required_case_present": False,
                "missing_required_cases": list(required_cases),
                "pass_evidence": {
                    pass_name: {
                        "required_case": case_name,
                        "present": False,
                        "status": "incomplete",
                    }
                    for pass_name, case_name in sorted(_PASS_CASES[platform_name].items())
                },
                "status": "incomplete",
                "missing_report_count": len(reports),
            }
            continue
        platforms[platform_name] = _report_summary(reports[0], required_cases, _PASS_CASES[platform_name])
    incomplete = sorted(name for name, report in platforms.items() if report["status"] != "complete")
    return {
        "schema_version": 1,
        "measurement": "cross-platform-differential-smoke",
        "platforms": platforms,
        "summary": {
            "platform_count": len(platforms),
            "complete_platforms": len(platforms) - len(incomplete),
            "incomplete_platforms": incomplete,
            "status": "complete" if not incomplete else "incomplete",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = summarize_platform_reports(args.root)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
