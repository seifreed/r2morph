"""
Unit tests for SARIF 2.1.0 schema and formatter.
"""

import json
import tempfile
from pathlib import Path

import pytest

from r2morph.reporting.sarif_formatter import (
    MutationResult,
    ReportData,
    SARIFFormatter,
    ValidationResult,
    format_as_sarif,
)
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
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_D_BYTELENGTH_50 = 50
_EXPECTED_D_BYTEOFFSET_100 = 100
_EXPECTED_D_BYTEOFFSET_100_2 = 100
_EXPECTED_D_ENDCOLUMN_20 = 20
_EXPECTED_D_ENDLINE_15 = 15
_EXPECTED_D_STARTCOLUMN_5 = 5
_EXPECTED_D_STARTLINE_10 = 10
_EXPECTED_LEN_ARTIFACTS_2 = 2
_EXPECTED_LEN_REPORT_RUNS_0_RESULTS_2 = 2
_EXPECTED_LEN_REPORT_RUNS_0_RESULTS_2_2 = 2
_EXPECTED_RESULT_PROPERTIES_MUTATED_SIZE_3 = 3
_EXPECTED_RESULT_PROPERTIES_ORIGINAL_SIZE_2 = 2


class TestSARIFSchema:
    """Tests for SARIF schema dataclasses."""

    def test_sarif_message_to_dict(self):
        msg = SARIFMessage(text="Test message", markdown="**Test** message")
        d = msg.to_dict()
        expect(d["text"] == "Test message")
        expect(d["markdown"] == "**Test** message")

    def test_sarif_message_minimal(self):
        msg = SARIFMessage(text="Simple")
        d = msg.to_dict()
        expect(d["text"] == "Simple")
        expect("markdown" not in d)

    def test_sarif_artifact_location(self):
        loc = SARIFArtifactLocation(uri="file:///path/to/binary", uri_base_id="SRCROOT")
        d = loc.to_dict()
        expect(d["uri"] == "file:///path/to/binary")
        expect(d["uriBaseId"] == "SRCROOT")

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
        expect(d["startLine"] == _EXPECTED_D_STARTLINE_10)
        expect(d["startColumn"] == _EXPECTED_D_STARTCOLUMN_5)
        expect(d["endLine"] == _EXPECTED_D_ENDLINE_15)
        expect(d["endColumn"] == _EXPECTED_D_ENDCOLUMN_20)
        expect(d["byteOffset"] == _EXPECTED_D_BYTEOFFSET_100)
        expect(d["byteLength"] == _EXPECTED_D_BYTELENGTH_50)

    def test_sarif_region_minimal(self):
        region = SARIFRegion(byte_offset=100)
        d = region.to_dict()
        expect(d["byteOffset"] == _EXPECTED_D_BYTEOFFSET_100_2)
        expect("startLine" not in d)

    def test_sarif_snippet(self):
        snippet = SARIFSnippet(text="original bytes")
        d = snippet.to_dict()
        expect(d["text"] == "original bytes")

    def test_sarif_physical_location(self):
        artifact_loc = SARIFArtifactLocation(uri="binary.exe")
        region = SARIFRegion(byte_offset=100, byte_length=10)
        phys_loc = SARIFPhysicalLocation(artifact_location=artifact_loc, region=region)
        d = phys_loc.to_dict()
        expect(not ("artifactLocation" not in d))
        expect(not ("region" not in d))

    def test_sarif_location_with_logical(self):
        artifact_loc = SARIFArtifactLocation(uri="binary.exe")
        phys_loc = SARIFPhysicalLocation(artifact_location=artifact_loc)
        logical_locs = [SARIFLogicalLocation(name="main", kind="function")]
        loc = SARIFLocation(
            physical_location=phys_loc,
            logical_locations=logical_locs,
        )
        d = loc.to_dict()
        expect(not ("physicalLocation" not in d))
        expect(not ("logicalLocations" not in d))
        expect(d["logicalLocations"][0]["name"] == "main")

    def test_sarif_rule(self):
        rule = SARIFRule(
            id="RM001",
            name="nop-insertion",
            short_description=SARIFMessage(text="NOP insertion"),
            default_level=SARIFLevel.NOTE,
        )
        d = rule.to_dict()
        expect(d["id"] == "RM001")
        expect(d["name"] == "nop-insertion")
        expect(d["defaultConfiguration"]["level"] == "note")

    def test_sarif_tool_component(self):
        rules = [SARIFRule(id="RM001", name="test", default_level=SARIFLevel.WARNING)]
        component = SARIFToolComponent(
            name="r2morph",
            version="0.2.0",
            information_uri="https://github.com/r2morph",
            rules=rules,
        )
        d = component.to_dict()
        expect(d["name"] == "r2morph")
        expect(d["version"] == "0.2.0")
        expect(len(d["rules"]) == 1)

    def test_sarif_tool(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)
        d = tool.to_dict()
        expect(not ("driver" not in d))
        expect(d["driver"]["name"] == "r2morph")

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
        expect(d["ruleId"] == "RM001")
        expect(d["level"] == "note")
        expect(not ("locations" not in d))

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
        expect(not ("fixes" not in d))
        expect(d["fixes"][0]["description"]["text"] == "Applied fix")

    def test_sarif_run(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)

        run = SARIFRun(tool=tool, results=[])
        d = run.to_dict()
        expect(not ("tool" not in d))
        expect(not ("results" not in d))

    def test_sarif_report(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)
        run = SARIFRun(tool=tool, results=[])

        report = SARIFReport(runs=[run])
        d = report.to_dict()
        expect(not ("$schema" not in d))
        expect(d["version"] == "2.1.0")
        expect(len(d["runs"]) == 1)

    def test_sarif_report_to_json(self):
        driver = SARIFToolComponent(name="r2morph")
        tool = SARIFTool(driver=driver)
        run = SARIFRun(tool=tool, results=[])
        report = SARIFReport(runs=[run])

        json_str = report.to_json()
        parsed = json.loads(json_str)
        expect(parsed["version"] == "2.1.0")

    def test_sarif_artifact(self):
        loc = SARIFArtifactLocation(uri="binary.exe")
        artifact = SARIFArtifact(
            location=loc,
            mime_type="application/octet-stream",
        )
        d = artifact.to_dict()
        expect(d["location"]["uri"] == "binary.exe")
        expect(d["mimeType"] == "application/octet-stream")

    def test_sarif_invocation(self):
        invocation = SARIFInvocation(
            execution_successful=True,
            exit_code=0,
        )
        d = invocation.to_dict()
        expect(not (d["executionSuccessful"] is not True))
        expect(d["exitCode"] == 0)


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
            **{MUTATION_NAME_KEY: "nop-insertion"},
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
        expect(formatter.tool_version == "0.2.0")
        expect(not (len(formatter._mutation_rules) <= 0))
        expect(not (len(formatter._validation_rules) <= 0))

    def test_format_empty_report(self, formatter):
        report_data = ReportData(binary_path="test.exe")
        report = formatter.format(report_data)

        expect(report.version == "2.1.0")
        expect(len(report.runs) == 1)
        expect(len(report.runs[0].results) == 0)

    def test_format_with_mutation(self, formatter, sample_mutation):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
        )
        report = formatter.format(report_data)

        expect(len(report.runs[0].results) == 1)
        result = report.runs[0].results[0]
        expect(result.rule_id == "RM001")
        expect(result.level == SARIFLevel.NOTE)
        expect(len(result.locations) == 1)

    def test_format_with_validation_failure(self, formatter, sample_validation_failure):
        report_data = ReportData(
            binary_path="test.exe",
            validations=[sample_validation_failure],
        )
        report = formatter.format(report_data)

        expect(len(report.runs[0].results) == 1)
        result = report.runs[0].results[0]
        expect(result.rule_id == "RV004")
        expect(result.level == SARIFLevel.ERROR)

    def test_format_with_validation_success_ignored(self, formatter, sample_validation_success):
        report_data = ReportData(
            binary_path="test.exe",
            validations=[sample_validation_success],
        )
        report = formatter.format(report_data)

        expect(len(report.runs[0].results) == 0)

    def test_format_combined(self, formatter, sample_mutation, sample_validation_failure):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
            validations=[sample_validation_failure],
        )
        report = formatter.format(report_data)

        expect(len(report.runs[0].results) == _EXPECTED_LEN_REPORT_RUNS_0_RESULTS_2)

    def test_mutation_rule_mapping(self, formatter):
        expect(formatter._get_mutation_rule_id("nop") == "RM001")
        expect(formatter._get_mutation_rule_id("nop-insertion") == "RM001")
        expect(formatter._get_mutation_rule_id("substitute") == "RM002")
        expect(formatter._get_mutation_rule_id("instruction-substitution") == "RM002")
        expect(formatter._get_mutation_rule_id("register") == "RM003")
        expect(formatter._get_mutation_rule_id("block") == "RM004")
        expect(formatter._get_mutation_rule_id("dead-code") == "RM005")
        expect(formatter._get_mutation_rule_id("opaque") == "RM006")
        expect(formatter._get_mutation_rule_id("expand") == "RM007")
        expect(formatter._get_mutation_rule_id("cff") == "RM008")
        expect(formatter._get_mutation_rule_id("unknown") == "RM001")

    def test_validation_rule_mapping(self, formatter):
        expect(formatter._get_validation_rule_id("structural") == "RV001")
        expect(formatter._get_validation_rule_id("runtime") == "RV002")
        expect(formatter._get_validation_rule_id("semantic") == "RV003")
        expect(formatter._get_validation_rule_id("cfg") == "RV004")
        expect(formatter._get_validation_rule_id("unknown") == "RV001")

    def test_to_json(self, formatter, sample_mutation):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
        )
        json_str = formatter.to_json(report_data)

        parsed = json.loads(json_str)
        expect(not ("$schema" not in parsed))
        expect(parsed["version"] == "2.1.0")
        expect(len(parsed["runs"]) == 1)

    def test_to_file(self, formatter, sample_mutation):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            output_path = Path(f.name)

        try:
            report_data = ReportData(
                binary_path="test.exe",
                mutations=[sample_mutation],
            )
            formatter.to_file(report_data, output_path)

            expect(output_path.exists())

            content = output_path.read_text()
            parsed = json.loads(content)
            expect(parsed["version"] == "2.1.0")
        finally:
            output_path.unlink(missing_ok=True)

    def test_artifacts_in_report(self, formatter):
        report_data = ReportData(
            binary_path="input.exe",
            output_path="output.exe",
        )
        report = formatter.format(report_data)

        artifacts = report.runs[0].artifacts
        expect(artifacts is not None)
        expect(len(artifacts) == _EXPECTED_LEN_ARTIFACTS_2)

    def test_properties_in_result(self, formatter, sample_mutation):
        report_data = ReportData(
            binary_path="test.exe",
            mutations=[sample_mutation],
        )
        report = formatter.format(report_data)

        result = report.runs[0].results[0]
        expect(result.properties is not None)
        expect(result.properties[MUTATION_NAME_KEY] == "nop-insertion")
        expect(result.properties["original_size"] == _EXPECTED_RESULT_PROPERTIES_ORIGINAL_SIZE_2)
        expect(result.properties["mutated_size"] == _EXPECTED_RESULT_PROPERTIES_MUTATED_SIZE_3)


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

        expect(report.version == "2.1.0")
        expect(len(report.runs[0].results) == 1)

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

        expect(len(report.runs[0].results) == _EXPECTED_LEN_REPORT_RUNS_0_RESULTS_2_2)

    def test_format_as_sarif_custom_version(self):
        report = format_as_sarif(
            mutations=[],
            validations=[],
            binary_path="test.exe",
            tool_version="0.3.0",
        )

        expect(report.runs[0].tool.driver.version == "0.3.0")
