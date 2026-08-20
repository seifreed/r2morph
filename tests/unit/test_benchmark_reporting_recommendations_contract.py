from r2morph.validation.benchmark_reporting_recommendations import build_recommendation_lines
from tests.utils.assertions import expect


def test_benchmark_reporting_recommendations_contract() -> None:
    report = build_recommendation_lines(
        {
            "success_rate": 0.75,
            "avg_execution_time": 31.2,
            "avg_accuracy": 0.75,
        }
    )

    expect(report[0] == "RECOMMENDATIONS")
    expect(not ("⚠️  Success rate below 80% - review failed tests" not in report))
    expect(not ("⚠️  Average execution time > 30s - consider optimization" not in report))
    expect(not ("⚠️  Average accuracy below 80% - review detection algorithms" not in report))
