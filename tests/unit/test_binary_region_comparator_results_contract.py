from pathlib import Path

from r2morph.validation.binary_region_comparator_results import (
    build_binary_comparison_result,
    build_region_report,
)


def test_build_region_report_includes_expected_fields() -> None:
    report = build_region_report(
        {"start_address": 0x1000, "end_address": 0x1003},
        0x2000,
        0x3000,
        7,
        14,
        2,
        3,
        [0x4000],
        [0x5000],
        ["rax", "rbx"],
    )

    assert report == {
        "start_address": 0x1000,
        "end_address": 0x1003,
        "original_loaded_address": 0x2000,
        "mutated_loaded_address": 0x3000,
        "step_budget": 7,
        "region_exit_budget": 14,
        "step_strategy": "region-exit",
        "original_region_exit_steps": 2,
        "mutated_region_exit_steps": 3,
        "original_trace_addresses": [0x4000],
        "mutated_trace_addresses": [0x5000],
        "registers_checked": ["rax", "rbx", "eflags", "stack_delta"],
        "mismatches": [],
    }


def test_build_binary_comparison_result_handles_empty_regions() -> None:
    result = build_binary_comparison_result([], [], Path("/prev.bin"), Path("/curr.bin"))

    assert result == {
        "symbolic_binary_check_performed": False,
        "symbolic_binary_equivalent": False,
        "symbolic_binary_reason": "no eligible regions for real-binary symbolic comparison",
        "symbolic_binary_regions": [],
        "symbolic_binary_mismatches": [],
        "symbolic_binary_paths": {
            "original": "/prev.bin",
            "mutated": "/curr.bin",
        },
    }


def test_build_binary_comparison_result_handles_matching_regions() -> None:
    regions = [{"start_address": 0x1000, "end_address": 0x1003}]
    result = build_binary_comparison_result(regions, [], Path("/prev.bin"), Path("/curr.bin"))

    assert result == {
        "symbolic_binary_check_performed": True,
        "symbolic_binary_equivalent": True,
        "symbolic_binary_reason": "bounded real-binary symbolic effects matched",
        "symbolic_binary_regions": regions,
        "symbolic_binary_mismatches": [],
        "symbolic_binary_paths": {
            "original": "/prev.bin",
            "mutated": "/curr.bin",
        },
    }

