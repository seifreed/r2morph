from r2morph.core.report_helpers_evidence_summary import (
    _build_pass_region_evidence_map,
    _summarize_pass_evidence,
)


def test_summarize_pass_evidence_orders_by_mismatch_then_issues() -> None:
    rows = _summarize_pass_evidence(
        {
            "nop": {
                "evidence_summary": {
                    "changed_region_count": 1,
                    "structural_issue_count": 0,
                    "symbolic_binary_regions_checked": 2,
                    "symbolic_binary_mismatched_regions": 1,
                    "rolled_back": False,
                    "status": "ok",
                }
            },
            "expand": {
                "evidence_summary": {
                    "changed_region_count": 2,
                    "structural_issue_count": 3,
                    "symbolic_binary_regions_checked": 4,
                    "symbolic_binary_mismatched_regions": 1,
                    "rolled_back": True,
                    "status": "warn",
                }
            },
            "register": {
                "evidence_summary": {
                    "changed_region_count": 3,
                    "structural_issue_count": 1,
                    "symbolic_binary_regions_checked": 0,
                    "symbolic_binary_mismatched_regions": 0,
                    "rolled_back": False,
                    "status": "ok",
                }
            },
        }
    )

    assert rows == [
        {
            "pass_name": "expand",
            "changed_region_count": 2,
            "structural_issue_count": 3,
            "symbolic_binary_regions_checked": 4,
            "symbolic_binary_mismatched_regions": 1,
            "rolled_back": True,
            "status": "warn",
        },
        {
            "pass_name": "nop",
            "changed_region_count": 1,
            "structural_issue_count": 0,
            "symbolic_binary_regions_checked": 2,
            "symbolic_binary_mismatched_regions": 1,
            "rolled_back": False,
            "status": "ok",
        },
        {
            "pass_name": "register",
            "changed_region_count": 3,
            "structural_issue_count": 1,
            "symbolic_binary_regions_checked": 0,
            "symbolic_binary_mismatched_regions": 0,
            "rolled_back": False,
            "status": "ok",
        },
    ]


def test_build_pass_region_evidence_map_compacts_symbolic_rows() -> None:
    region_map = _build_pass_region_evidence_map(
        {
            "nop": {
                "evidence_summary": {
                    "symbolic_regions": [
                        {
                            "start_address": 0x1000,
                            "end_address": 0x1004,
                            "equivalent": False,
                            "mismatch_count": 2,
                            "mismatches": ["rax", "stack_delta"],
                            "step_strategy": "bounded",
                            "original_region_exit_address": 0x2000,
                            "mutated_region_exit_address": 0x3000,
                            "original_trace_length": 3,
                            "mutated_trace_length": 4,
                            "original_region_exit_steps": 5,
                            "mutated_region_exit_steps": 6,
                        }
                    ]
                }
            }
        }
    )

    assert region_map == {
        "nop": [
            {
                "start_address": 0x1000,
                "end_address": 0x1004,
                "equivalent": False,
                "mismatch_count": 2,
                "mismatches": ["rax", "stack_delta"],
                "step_strategy": "bounded",
                "region_exit_equivalent": False,
                "original_region_exit_address": 0x2000,
                "mutated_region_exit_address": 0x3000,
                "original_trace_length": 3,
                "mutated_trace_length": 4,
                "original_region_exit_steps": 5,
                "mutated_region_exit_steps": 6,
            }
        ]
    }

