from r2morph.reporting.sarif_formatter_builders import ReportData, build_artifacts, build_driver, build_invocations
from r2morph.reporting.sarif_formatter_run import build_report, build_run
from r2morph.reporting.sarif_result_builder import SARIFResultBuilder


def test_sarif_formatter_run_helpers_build_report_and_run() -> None:
    report_data = ReportData(binary_path="input.exe", output_path=None, exit_code=0)
    mutation_rules = []
    validation_rules = []
    tool = build_driver("1.2.3", "https://example.invalid", [])
    result_builder = SARIFResultBuilder(mutation_rules, validation_rules)

    run = build_run(
        tool,
        result_builder.build_results(report_data),
        build_artifacts(report_data),
        build_invocations(report_data),
        [],
        "/workspace",
    )
    report = build_report(
        tool,
        result_builder.build_results(report_data),
        build_artifacts(report_data),
        build_invocations(report_data),
        [],
        "/workspace",
    )

    assert run.tool.driver.version == "1.2.3"
    assert run.artifacts and [artifact.location.uri for artifact in run.artifacts] == ["input.exe"]
    assert run.original_uri_base_ids == {"SRCROOT": "/workspace"}
    assert report.runs[0].tool.driver.information_uri == "https://example.invalid"
