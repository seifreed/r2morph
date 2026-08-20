from __future__ import annotations

from r2morph.validation import regression_storage
from r2morph.validation.regression_models import BaselineResult, RegressionTestType
from tests.utils.assertions import expect


def test_regression_storage_round_trip(tmp_path) -> None:
    baseline = BaselineResult(
        test_id="baseline-1",
        test_type=RegressionTestType.API_COMPATIBILITY,
        input_hash="hash",
        expected_output={"ok": True},
        performance_baseline={},
        timestamp="now",
        version="1.0",
    )

    regression_storage.save_baseline(tmp_path, baseline)
    loaded = regression_storage.load_baselines(tmp_path)

    expect(not ("baseline-1" not in loaded))
    expect(not (loaded["baseline-1"].test_type is not RegressionTestType.API_COMPATIBILITY))
