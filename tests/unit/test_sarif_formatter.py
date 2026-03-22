"""
Unit tests for SARIF 2.1.0 schema and formatter.
"""

import json
import tempfile
from pathlib import Path

import pytest

from r2morph.reporting.sarif_schema import (
    SARIFArtifact,
    SARIFArtifactLocation,
    SARIFFix,
    SARIFInvocation,
    SARIFLevel,
    SARIFLocation,
    SARIFLogicalLocation,
    SARIFMessage,
    SARIFPhysicalLocation,
    SARIFRegion,
    SARIFReport,
    SARIFResult,
    SARIFRule,
    SARIFRun,
    SARIFSnippet,
    SARIFTool,
    SARIFToolComponent,
)
from r2morph.reporting.sarif_formatter import (
    MutationResult,
    ReportData,
    ValidationResult,
    SARIFFormatter,
    format_as_sarif,
)


class TestSARIFSchema:
    """Tests for SARIF schema dataclasses."""

    def test_sarif_message_to_dict(self):
        msg = SARIFMessage(text="Test message", markdown="**Test** message")
        d = msg.to_dict()
        assert d["text"] == "Test message"
        assert d["markdown"] == "**Test** message"

    def test_sarif_message_minimal(self):
        msg = SARIFMessage(text="Simple")
        d = msg.to_dict()
        assert d["text"] == "Simple"
        assert "markdown" not in d

    def test_sarif_artifact_location(self):
        loc = SARIFArtifactLocation(uri="file:///path/to/binary", uri_base_id="SRCROOT")
        d = loc.to_dict()
        assert d["uri"] == "file:///path/to/binary"
        assert d["uriBaseId"] == "SRCROOT"

    def test_sarif_region_full(self):
        region = SARIFRegion(
            start_line=10,
            start_column=5,
            end_line=15,
            end_column=20,
            byte_offset=100,
            byte_length=50,
        )
        d = region.to_dict()
        assert d["startLine"] == 10
        assert d["startColumn"] == 5
        assert d["endLine"] == 15
        assert d["endColumn"] == 20
        assert d["byteOffset"] == 100
        assert d["byteLength"] == 50

    def test_sarif_region_minimal(self):
        region = SARIFRegion(byte_offset=100)
        d = region.to_dict()
        assert d["byteOffset"] == 100
        assert "startLine" not in d

    def test_sarif_snippet(self):
        snippet = SARIFSnippet(text="original bytes")
        d = snippet.to_dict()
        assert d["text"] == "original bytes"

    def test_sarif_physical_location(self):
        artifact_loc = SARIFArtifactLocation(uri="binary.exe")
        region = SARIFRegion(byte_offset=100, byte_length=10)
        phys_loc = SARIFPhysicalLocation(artifact_location=artifact_loc, region=region)
        d = phys_loc.to_dict()
        assert "artifactLocation" in d
        assert "region" in d

    def test_sarif_location_with_logical(self):
        artifact_loc = SARIFArtifactLocation(uri="binary.exe")
        phys_loc = SARIFPhysicalLocation(artifact_location=artifact_loc)
        logical_locs = [SARIFLogicalLocation(name="main", kind="function")]
        loc = SARIFLocation(
            physical_location=phys_loc,
            logical_locations=logical_locs,
        )
        d = loc.to_dict()
        assert "physicalLocation" in d
        assert "logicalLocations" in d
        assert d["logicalLocations"][0]["name"] == "main"

    def test_sarif_rule(self):
        rule = SARIFRule(
            id="RM001",
            name="nop-insertion",
            short_description=SARIFMessage(text="NOP insertion"),
            default_level=SARIFLevel.NOTE,
        )
        d = rule.to_dict()
        assert d["id"] == "RM001"
        assert d["name"] == "nop-insertion"
        assert d["defaultConfiguration"]["level"] == "note"

    def test_sarif_tool_component(self):
        rules = [SARIFRule(id="RM001", name="test", default_level=SARIFLevel.WARNING)]
        component = SARIFToolComponent(
            name="r2morph",
            version="0.2.0",
            information_uri="https://github.com/r2morph",
            rules=rules,
        )
        d = component.to_dict()
        assert d["name"] == "r2morph"
        assert d["version"] == "0.2.0"
        assert len(d["rules"]) == 1

    def test_sarif_tool(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)
        d = tool.to_dict()
        assert "driver" in d
        assert d["driver"]["name"] == "r2morph"

    def test_sarif_result(self):
        artifact_loc = SARIFArtifactLocation(uri="binary.exe")
        phys_loc = SARIFPhysicalLocation(artifact_location=artifact_loc)
        loc = SARIFLocation(physical_location=phys_loc)

        result = SARIFResult(
            rule_id="RM001",
            level=SARIFLevel.NOTE,
            message=SARIFMessage(text="Mutation applied"),
            locations=[loc],
        )
        d = result.to_dict()
        assert d["ruleId"] == "RM001"
        assert d["level"] == "note"
        assert "locations" in d

    def test_sarif_result_with_fixes(self):
        artifact_loc = SARIFArtifactLocation(uri="binary.exe")
        phys_loc = SARIFPhysicalLocation(artifact_location=artifact_loc)
        loc = SARIFLocation(physical_location=phys_loc)

        fix = SARIFFix(
            description=SARIFMessage(text="Applied fix"),
            file_changes=[],
        )
        result = SARIFResult(
            rule_id="RM001",
            level=SARIFLevel.NOTE,
            message=SARIFMessage(text="Mutation applied"),
            locations=[loc],
            fixes=[fix],
        )
        d = result.to_dict()
        assert "fixes" in d
        assert d["fixes"][0]["description"]["text"] == "Applied fix"

    def test_sarif_run(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)

        run = SARIFRun(tool=tool, results=[])
        d = run.to_dict()
        assert "tool" in d
        assert "results" in d

    def test_sarif_report(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)
        run = SARIFRun(tool=tool, results=[])

        report = SARIFReport(runs=[run])
        d = report.to_dict()
        assert "$schema" in d
        assert d["version"] == "2.1.0"
        assert len(d["runs"]) == 1

    def test_sarif_report_to_json(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)
        run = SARIFRun(tool=tool, results=[])
        report = SARIFReport(runs=[run])

        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_sarif_artifact(self):
        loc = SARIFArtifactLocation(uri="binary.exe")
        artifact = SARIFArtifact(
            location=loc,
            mime_type="application/octet-stream",
        )
        d = artifact.to_dict()
        assert d["location"]["uri"] == "binary.exe"
        assert d["mimeType"] == "application/octet-stream"

    def test_sarif_invocation(self):
        invocation = SARIFInvocation(
            execution_successful=True,
            exit_code=0,
        )
        d = invocation.to_dict()
        assert d["executionSuccessful"] is True
        assert d["exitCode"] == 0


class TestSARIFFormatter:
    """Tests for SARIF formatter."""

    @pytest.fixture
    def formatter(self):
        return SARIFFormatter(tool_version="0.2.0")

    @pytest.fixture
    def sample_mutation(self):
        return MutationResult(
            address=0x1000,
            original_bytes=b"\x90\x90",
            mutated_bytes=b"\x90\x90\x90",
            pass_name="nop-insertion",
            function="main",
            section=".text",
        )

    @pytest.fixture
    def sample_validation_failure(self):
        return ValidationResult(
            passed=False,
            address=0x1000,
            message="CFG integrity check failed",
            validation_type="cfg",
            severity="error",
        )

    @pytest.fixture
    def sample_validation_success(self):
        return ValidationResult(
            passed=True,
            validation_type="structural",
        )

    def test_formatter_initialization(self, formatter):
        assert formatter.tool_version == "0.2.0"
        assert len(formatter._mutation_rules) > 0
        assert len(formatter._validation_rules) > 0

    def test_format_empty_report(self, formatter):
        report_data = ReportData(binary_path="test.exe")
        report = formatter.format(report_data)

        assert report.version == "2.1.0"
        assert len(report.runs) == 1
        assert len(report.runs[0].results) == 0

    def test_format_with_mutation(self, formatter, sample_mutation):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
        )
        report = formatter.format(report_data)

        assert len(report.runs[0].results) == 1
        result = report.runs[0].results[0]
        assert result.rule_id == "RM001"
        assert result.level == SARIFLevel.NOTE
        assert len(result.locations) == 1

    def test_format_with_validation_failure(self, formatter, sample_validation_failure):
        report_data = ReportData(
            binary_path="test.exe",
            validations=[sample_validation_failure],
        )
        report = formatter.format(report_data)

        assert len(report.runs[0].results) == 1
        result = report.runs[0].results[0]
        assert result.rule_id == "RV004"
        assert result.level == SARIFLevel.ERROR

    def test_format_with_validation_success_ignored(self, formatter, sample_validation_success):
        report_data = ReportData(
            binary_path="test.exe",
            validations=[sample_validation_success],
        )
        report = formatter.format(report_data)

        assert len(report.runs[0].results) == 0

    def test_format_combined(self, formatter, sample_mutation, sample_validation_failure):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
            validations=[sample_validation_failure],
        )
        report = formatter.format(report_data)

        assert len(report.runs[0].results) == 2

    def test_mutation_rule_mapping(self, formatter):
        assert formatter._get_mutation_rule_id("nop") == "RM001"
        assert formatter._get_mutation_rule_id("nop-insertion") == "RM001"
        assert formatter._get_mutation_rule_id("substitute") == "RM002"
        assert formatter._get_mutation_rule_id("instruction-substitution") == "RM002"
        assert formatter._get_mutation_rule_id("register") == "RM003"
        assert formatter._get_mutation_rule_id("block") == "RM004"
        assert formatter._get_mutation_rule_id("dead-code") == "RM005"
        assert formatter._get_mutation_rule_id("opaque") == "RM006"
        assert formatter._get_mutation_rule_id("expand") == "RM007"
        assert formatter._get_mutation_rule_id("cff") == "RM008"
        assert formatter._get_mutation_rule_id("unknown") == "RM001"

    def test_validation_rule_mapping(self, formatter):
        assert formatter._get_validation_rule_id("structural") == "RV001"
        assert formatter._get_validation_rule_id("runtime") == "RV002"
        assert formatter._get_validation_rule_id("semantic") == "RV003"
        assert formatter._get_validation_rule_id("cfg") == "RV004"
        assert formatter._get_validation_rule_id("unknown") == "RV001"

    def test_to_json(self, formatter, sample_mutation):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
        )
        json_str = formatter.to_json(report_data)

        parsed = json.loads(json_str)
        assert "$schema" in parsed
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_to_file(self, formatter, sample_mutation):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            output_path = Path(f.name)

        try:
            report_data = ReportData(
                binary_path="test.exe",
                mutations=[sample_mutation],
            )
            formatter.to_file(report_data, output_path)

            assert output_path.exists()

            content = output_path.read_text()
            parsed = json.loads(content)
            assert parsed["version"] == "2.1.0"
        finally:
            output_path.unlink(missing_ok=True)

    def test_artifacts_in_report(self, formatter):
        report_data = ReportData(
            binary_path="input.exe",
            output_path="output.exe",
        )
        report = formatter.format(report_data)

        artifacts = report.runs[0].artifacts
        assert artifacts is not None
        assert len(artifacts) == 2

    def test_properties_in_result(self, formatter, sample_mutation):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
        )
        report = formatter.format(report_data)

        result = report.runs[0].results[0]
        assert result.properties is not None
        assert result.properties["pass_name"] == "nop-insertion"
        assert result.properties["original_size"] == 2
        assert result.properties["mutated_size"] == 3


class TestFormatAsSarifConvenience:
    """Tests for convenience function."""

    def test_format_as_sarif_basic(self):
        mutations = [
            {
                "address": 0x1000,
                "original_bytes": b"\x90\x90",
                "mutated_bytes": b"\x90\x90\x90",
                "pass_name": "nop",
            }
        ]
        validations = []

        report = format_as_sarif(
            mutations=mutations,
            validations=validations,
            binary_path="test.exe",
        )

        assert report.version == "2.1.0"
        assert len(report.runs[0].results) == 1

    def test_format_as_sarif_with_validation(self):
        mutations = [
            {
                "address": 0x1000,
                "original_bytes": b"\x90\x90",
                "mutated_bytes": b"\x90\x90\x90",
                "pass_name": "nop",
            }
        ]
        validations = [
            {
                "passed": False,
                "address": 0x1000,
                "message": "Validation failed",
                "validation_type": "structural",
                "severity": "error",
            }
        ]

        report = format_as_sarif(
            mutations=mutations,
            validations=validations,
            binary_path="test.exe",
        )

        assert len(report.runs[0].results) == 2

    def test_format_as_sarif_custom_version(self):
        report = format_as_sarif(
            mutations=[],
            validations=[],
            binary_path="test.exe",
            tool_version="0.3.0",
        )

        assert report.runs[0].tool.driver.version == "0.3.0"
