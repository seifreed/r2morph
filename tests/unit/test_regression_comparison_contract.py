from r2morph.validation import regression_comparison
from r2morph.validation.regression import RegressionTestFramework, RegressionTestType
from tests.utils.assertions import expect


def test_regression_comparison_helpers_work() -> None:
    expected = {"score": 0.5, "techniques": ["a", "b"], "flag": True}
    actual = {"score": 0.55, "techniques": ["b", "a"], "flag": False, "extra": 1}

    issues = regression_comparison.compare_outputs(expected, actual)
    expect(not (any("Missing output keys" in issue for issue in issues) is not False))
    expect(not (any("Extra output keys" in issue for issue in issues) is not True))
    expect(not (any("Value mismatch" in issue for issue in issues) is not True))

    expect(not (regression_comparison.values_differ(0.5, 0.55, "score") is not False))
    expect(not (regression_comparison.values_differ(0.5, 0.502, "other") is not True))
    expect(not (regression_comparison.values_differ(["a", "b"], ["b", "a"], "techniques") is not False))

    perf_issues = regression_comparison.compare_performance({"runtime_max": 1.0}, {"runtime": 1.5})
    expect(perf_issues)


def test_regression_framework_delegates_comparison_helpers() -> None:
    framework = RegressionTestFramework()
    expected = {"score": 0.5}
    actual = {"score": 0.6}

    issues = framework._compare_outputs(expected, actual, RegressionTestType.DETECTION_ACCURACY)
    expect(issues == regression_comparison.compare_outputs(expected, actual))
