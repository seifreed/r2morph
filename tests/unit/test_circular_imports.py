"""Verify no circular imports in reporting/ and core/ packages."""
import importlib
import pytest

REPORTING_MODULES = [
    "r2morph.reporting",
    "r2morph.reporting.gate_evaluator",
    "r2morph.reporting.report_helpers",
    "r2morph.reporting.report_rendering",
    "r2morph.reporting.report_resolver",
    "r2morph.reporting.report_orchestrator",
    "r2morph.reporting.filtered_summary_builder",
    "r2morph.reporting.report_view_builder",
    "r2morph.reporting.report_context",
    "r2morph.reporting.summary_aggregator",
]


@pytest.mark.parametrize("module_name", REPORTING_MODULES)
def test_reporting_module_imports_cleanly(module_name):
    mod = importlib.import_module(module_name)
    assert mod is not None
