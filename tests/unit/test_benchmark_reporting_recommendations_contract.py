from r2morph.validation.benchmark_reporting_recommendations import build_recommendation_lines


def test_benchmark_reporting_recommendations_contract() -> None:
    report = build_recommendation_lines(
        {
            "success_rate": 0.75,
            "avg_execution_time": 31.2,
            "avg_accuracy": 0.75,
        }
    )

    assert report[0] == "RECOMMENDATIONS"
    assert "⚠️  Success rate below 80% - review failed tests" in report
    assert "⚠️  Average execution time > 30s - consider optimization" in report
    assert "⚠️  Average accuracy below 80% - review detection algorithms" in report
