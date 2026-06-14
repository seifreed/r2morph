"""Contracts for pass evidence row builders."""

from __future__ import annotations

from r2morph.reporting.summary_aggregator_evidence_rows import (
    _build_pass_evidence_summary,
    _summarize_pass_evidence_rows,
)


def test_build_pass_evidence_summary_compacts_symbolic_rows() -> None:
    pass_result = {
        "diff_summary": {
            "changed_regions": [{"start": 1}],
            "changed_bytes": 12,
            "structural_issue_count": 1,
            "structural_regions": [{"start": 1}],
        },
        "mutations": [
            {
                "start_address": 0x1000,
                "end_address": 0x1010,
                "metadata": {
                    "symbolic_binary_check_performed": True,
                    "symbolic_binary_equivalent": False,
                    "symbolic_binary_mismatches": ["a"],
                    "symbolic_binary_control_flow_observables": ["branch"],
                    "symbolic_binary_original_trace_addresses": [1, 2],
                    "symbolic_binary_mutated_trace_addresses": [3],
                    "symbolic_binary_original_memory_write_count": 2,
                    "symbolic_binary_mutated_memory_write_count": 1,
                    "symbolic_binary_step_strategy": "direct",
                    "symbolic_binary_original_region_exit_address": 0x2000,
                    "symbolic_binary_mutated_region_exit_address": 0x2000,
                    "symbolic_binary_original_region_exit_steps": 3,
                    "symbolic_binary_mutated_region_exit_steps": 4,
                },
            }
        ],
        "rolled_back": True,
        "status": "ok",
    }

    summary = _build_pass_evidence_summary("example-pass", pass_result)

    assert summary == {
        "pass_name": "example-pass",
        "changed_region_count": 1,
        "changed_bytes": 12,
        "structural_issue_count": 1,
        "structural_region_count": 1,
        "symbolic_binary_regions_checked": 1,
        "symbolic_binary_matched_regions": 0,
        "symbolic_binary_mismatched_regions": 1,
        "control_flow_observables": ["branch"],
        "max_original_trace_length": 2,
        "max_mutated_trace_length": 1,
        "memory_write_activity": 3,
        "region_exit_match_count": 1,
        "symbolic_regions": [
            {
                "start_address": 0x1000,
                "end_address": 0x1010,
                "equivalent": False,
                "mismatches": ["a"],
                "mismatch_count": 1,
                "step_strategy": "direct",
                "original_region_exit_address": 0x2000,
                "mutated_region_exit_address": 0x2000,
                "original_trace_length": 2,
                "mutated_trace_length": 1,
                "original_region_exit_steps": 3,
                "mutated_region_exit_steps": 4,
            }
        ],
        "rolled_back": True,
        "status": "ok",
    }


def test_summarize_pass_evidence_rows_orders_mismatches_first() -> None:
    rows = _summarize_pass_evidence_rows(
        {
            "clean-pass": {"evidence_summary": {"changed_region_count": 0, "structural_issue_count": 0}},
            "mismatch-pass": {
                "evidence_summary": {
                    "changed_region_count": 1,
                    "structural_issue_count": 0,
                    "symbolic_binary_regions_checked": 1,
                    "symbolic_binary_mismatched_regions": 2,
                    "rolled_back": True,
                    "status": "ok",
                }
            },
        }
    )

    assert rows == [
        {
            "pass_name": "mismatch-pass",
            "changed_region_count": 1,
            "structural_issue_count": 0,
            "symbolic_binary_regions_checked": 1,
            "symbolic_binary_mismatched_regions": 2,
            "rolled_back": True,
            "status": "ok",
        },
        {
            "pass_name": "clean-pass",
            "changed_region_count": 0,
            "structural_issue_count": 0,
            "symbolic_binary_regions_checked": 0,
            "symbolic_binary_mismatched_regions": 0,
            "rolled_back": False,
            "status": "unknown",
        },
    ]
