from r2morph.reporting.report_rendering_text_section_helpers import (
    build_mismatch_summary_rows,
)


def test_build_mismatch_summary_rows_sorts_by_count_and_truncates_observables() -> None:
    rows = build_mismatch_summary_rows(
        {
            "alpha": 5,
            "beta": 2,
        },
        {
            "alpha": ["rax", "rbx", "rcx", "rdx"],
            "beta": ["rsp"],
        },
    )

    assert rows == [
        {"pass_name": "alpha", "count": "5", "observables": "rax, rbx, rcx..."},
        {"pass_name": "beta", "count": "2", "observables": "rsp"},
    ]
