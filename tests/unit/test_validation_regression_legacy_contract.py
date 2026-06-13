from r2morph.mutations import NopInsertionPass
from r2morph.validation import RegressionTester as ExportedRegressionTester
from r2morph.validation.regression_legacy import RegressionTester


def test_validation_regression_legacy_export_matches_package_root() -> None:
    assert ExportedRegressionTester is RegressionTester


def test_validation_regression_legacy_mutation_mapping_returns_real_pass() -> None:
    tester = RegressionTester()
    assert isinstance(tester._get_mutation_pass("nop"), NopInsertionPass)
