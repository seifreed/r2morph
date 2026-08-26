"""Regression tests for runtime data shipped in the distribution."""

from importlib.resources import files

from tests.utils.assertions import expect


def test_arm64_equivalence_rules_are_packaged() -> None:
    expect(files("r2morph.mutations.equivalences").joinpath("arm64_rules.yaml").is_file())


def test_report_schema_is_packaged() -> None:
    expect(files("r2morph.reporting").joinpath("report_schema.json").is_file())
