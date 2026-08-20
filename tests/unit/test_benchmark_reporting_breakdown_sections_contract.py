from r2morph.validation.benchmark_reporting_breakdown_sections import (
    build_category_breakdown_lines,
    build_severity_breakdown_lines,
)
from tests.utils.assertions import expect


def test_benchmark_reporting_breakdown_sections_contract() -> None:
    summary = {
        "categories": {"detection": {"total": 2, "successful": 1, "success_rate": 0.5, "avg_time": 1.2}},
        "severity_breakdown": {"low": {"total": 2, "successful": 1, "success_rate": 0.5}},
    }

    categories = build_category_breakdown_lines(summary)
    severities = build_severity_breakdown_lines(summary)

    expect(categories[0] == "CATEGORY BREAKDOWN")
    expect(not ("DETECTION:" not in categories))
    expect(severities[0] == "SEVERITY BREAKDOWN")
    expect(not ("LOW:" not in severities))
