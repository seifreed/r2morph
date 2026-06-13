"""Verify no circular imports in reporting/ and core/ packages."""

import importlib
import sys

import pytest

REPORTING_MODULES = [
    "r2morph.reporting",
    "r2morph.reporting.gate_evaluator",
    "r2morph.reporting.report_helpers",
    "r2morph.reporting.report_rendering",
    "r2morph.reporting.report_rendering_sections",
    "r2morph.reporting.report_resolver",
    "r2morph.reporting.report_orchestrator",
    "r2morph.reporting.filtered_summary_builder",
    "r2morph.reporting.filtered_summary_sections",
    "r2morph.reporting.filtered_summary_symbolic",
    "r2morph.reporting.report_view_builder",
    "r2morph.reporting.report_context",
    "r2morph.reporting.summary_aggregator",
]


@pytest.mark.parametrize("module_name", REPORTING_MODULES)
def test_reporting_module_imports_cleanly(module_name):
    mod = importlib.import_module(module_name)
    assert mod is not None


def test_package_root_defers_heavy_exports():
    module = importlib.import_module("r2morph")

    module.__dict__.pop("Binary", None)
    module.__dict__.pop("MorphEngine", None)
    module.__dict__.pop("Pipeline", None)
    sys.modules.pop("r2morph.core.binary", None)
    sys.modules.pop("r2morph.core.engine", None)
    sys.modules.pop("r2morph.pipeline.pipeline", None)

    assert "r2morph.core.binary" not in sys.modules
    assert "r2morph.core.engine" not in sys.modules
    assert "r2morph.pipeline.pipeline" not in sys.modules

    assert module.Binary.__name__ == "Binary"
    assert module.MorphEngine.__name__ == "MorphEngine"
    assert module.Pipeline.__name__ == "Pipeline"

    assert "r2morph.core.binary" in sys.modules
    assert "r2morph.core.engine" in sys.modules
    assert "r2morph.pipeline.pipeline" in sys.modules


def test_reporting_package_defers_heavy_exports():
    module = importlib.import_module("r2morph.reporting")

    module.__dict__.pop("ReportBuilder", None)
    module.__dict__.pop("SARIFFormatter", None)
    sys.modules.pop("r2morph.reporting.report_builder", None)
    sys.modules.pop("r2morph.reporting.sarif_formatter", None)

    assert "r2morph.reporting.report_builder" not in sys.modules
    assert "r2morph.reporting.sarif_formatter" not in sys.modules

    assert module.ReportBuilder.__name__ == "ReportBuilder"
    assert module.SARIFFormatter.__name__ == "SARIFFormatter"

    assert "r2morph.reporting.report_builder" in sys.modules
    assert "r2morph.reporting.sarif_formatter" in sys.modules


def test_report_builder_only_keeps_payload_construction_helpers():
    from r2morph.reporting.report_builder import ReportBuilder

    assert not hasattr(ReportBuilder, "resolve_report_context")
    assert not hasattr(ReportBuilder, "resolve_min_severity")
    assert not hasattr(ReportBuilder, "resolve_report_pass_filter")
