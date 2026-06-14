from r2morph.reporting.report_rendering_pass_section_helpers import (
    build_pass_capability_fragments,
    build_pass_region_label,
    build_pass_validation_context_fragments,
    group_issues_by_severity,
)


def test_build_pass_capability_fragments_formats_flags_in_order() -> None:
    fragments = build_pass_capability_fragments(
        {
            "runtime": {"recommended": True},
            "symbolic": {"confidence": "high", "recommended": False},
        }
    )

    assert fragments == [
        "runtime recommended=yes",
        "symbolic confidence=high",
        "symbolic recommended=no",
    ]


def test_build_pass_validation_context_fragments_handles_degraded_role() -> None:
    fragments = build_pass_validation_context_fragments(
        {
            "requested_validation_mode": "symbolic",
            "effective_validation_mode": "runtime",
            "degraded_execution": True,
            "degradation_triggered_by_pass": False,
            "role": "ignored",
        }
    )

    assert fragments == [
        "requested=symbolic",
        "effective=runtime",
        "degraded=yes",
        "role=executed-under-degraded-mode",
    ]


def test_build_pass_region_label_formats_ranges() -> None:
    assert build_pass_region_label(None, 0x2000) == "unknown"
    assert build_pass_region_label(0x1000, 0x1000) == "0x1000"
    assert build_pass_region_label(0x1000, 0x2000) == "0x1000-0x2000"


def test_group_issues_by_severity_accumulates_counts() -> None:
    grouped = group_issues_by_severity(
        [
            {"severity": "high", "observable_mismatch": 2, "without_coverage": 1, "bounded_only": 0},
            {"severity": "high", "observable_mismatch": 1, "without_coverage": 0, "bounded_only": 3},
            {"severity": "low", "observable_mismatch": 0, "without_coverage": 4, "bounded_only": 1},
        ]
    )

    assert grouped == {
        "high": {"mismatch": 3, "without_coverage": 1, "bounded_only": 3},
        "low": {"mismatch": 0, "without_coverage": 4, "bounded_only": 1},
    }
