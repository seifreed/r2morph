from r2morph.validation import regression_comparison
from r2morph.validation.regression import RegressionTestFramework, RegressionTestType


def test_regression_comparison_helpers_work() -> None:
    expected = {"score": 0.5, "techniques": ["a", "b"], "flag": True}
    actual = {"score": 0.55, "techniques": ["b", "a"], "flag": False, "extra": 1}

    issues = regression_comparison.compare_outputs(expected, actual)
    assert any("Missing output keys" in issue for issue in issues) is False
    assert any("Extra output keys" in issue for issue in issues) is True
    assert any("Value mismatch" in issue for issue in issues) is True

    assert regression_comparison.values_differ(0.5, 0.55, "score") is False
    assert regression_comparison.values_differ(0.5, 0.502, "other") is True
    assert regression_comparison.values_differ(["a", "b"], ["b", "a"], "techniques") is False

    perf_issues = regression_comparison.compare_performance({"runtime_max": 1.0}, {"runtime": 1.5})
    assert perf_issues


def test_regression_framework_delegates_comparison_helpers() -> None:
    framework = RegressionTestFramework()
    expected = {"score": 0.5}
    actual = {"score": 0.6}

    issues = framework._compare_outputs(expected, actual, RegressionTestType.DETECTION_ACCURACY)
    assert issues == regression_comparison.compare_outputs(expected, actual)
