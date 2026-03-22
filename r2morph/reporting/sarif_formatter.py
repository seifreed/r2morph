"""
SARIF 2.1.0 formatter for r2morph mutation reports.

Converts mutation and validation results to SARIF format for CI/CD integration
with tools like GitHub Security, Azure DevOps, and SonarQube.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from r2morph.reporting.sarif_schema import (
    SARIFArtifact,
    SARIFArtifactLocation,
    SARIFFix,
    SARIFFileChange,
    SARIFInvocation,
    SARIFLevel,
    SARIFLocation,
    SARIFLogicalLocation,
    SARIFMessage,
    SARIFPhysicalLocation,
    SARIFRegion,
    SARIFReplacement,
    SARIFReport,
    SARIFResult,
    SARIFRule,
    SARIFRun,
    SARIFSnippet,
    SARIFTool,
    SARIFToolComponent,
)


@dataclass
class MutationResult:
    address: int
    original_bytes: bytes
    mutated_bytes: bytes
    pass_name: str
    description: str | None = None
    function: str | None = None
    section: str | None = None


@dataclass
class ValidationResult:
    passed: bool
    address: int | None = None
    message: str | None = None
    validation_type: str = "structural"
    severity: str = "warning"
    details: dict[str, Any] | None = None


@dataclass
class ReportData:
    binary_path: str
    output_path: str | None = None
    mutations: list[MutationResult] | None = None
    validations: list[ValidationResult] | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    exit_code: int = 0


MUTATION_RULES: list[dict[str, Any]] = [
    {
        "id": "RM001",
        "name": "nop-insertion",
        "short_description": "NOP instruction insertion",
        "full_description": "Inserts benign NOP instructions at safe locations",
        "default_level": "note",
    },
    {
        "id": "RM002",
        "name": "instruction-substitution",
        "short_description": "Instruction substitution",
        "full_description": "Replaces instructions with semantically equivalent alternatives",
        "default_level": "note",
    },
    {
        "id": "RM003",
        "name": "register-substitution",
        "short_description": "Register substitution",
        "full_description": "Substitutes registers while preserving program semantics",
        "default_level": "note",
    },
    {
        "id": "RM004",
        "name": "block-reordering",
        "short_description": "Basic block reordering",
        "full_description": "Reorders basic blocks to change code layout",
        "default_level": "warning",
    },
    {
        "id": "RM005",
        "name": "dead-code-injection",
        "short_description": "Dead code injection",
        "full_description": "Injects dead code sequences that execute but have no effect",
        "default_level": "warning",
    },
    {
        "id": "RM006",
        "name": "opaque-predicates",
        "short_description": "Opaque predicate insertion",
        "full_description": "Inserts conditional branches with known outcomes",
        "default_level": "warning",
    },
    {
        "id": "RM007",
        "name": "instruction-expansion",
        "short_description": "Instruction expansion",
        "full_description": "Expands instructions into longer equivalent sequences",
        "default_level": "note",
    },
    {
        "id": "RM008",
        "name": "control-flow-flattening",
        "short_description": "Control flow flattening",
        "full_description": "Flattens control flow to obscure program structure",
        "default_level": "warning",
    },
]

VALIDATION_RULES: list[dict[str, Any]] = [
    {
        "id": "RV001",
        "name": "structural-validation",
        "short_description": "Structural validation failure",
        "full_description": "Binary structure validation detected an issue",
        "default_level": "error",
    },
    {
        "id": "RV002",
        "name": "runtime-validation",
        "short_description": "Runtime validation failure",
        "full_description": "Runtime behavior validation detected a mismatch",
        "default_level": "error",
    },
    {
        "id": "RV003",
        "name": "semantic-validation",
        "short_description": "Semantic validation failure",
        "full_description": "Semantic equivalence validation failed",
        "default_level": "error",
    },
    {
        "id": "RV004",
        "name": "cfg-integrity",
        "short_description": "CFG integrity violation",
        "full_description": "Control flow graph integrity check failed",
        "default_level": "error",
    },
]


class SARIFFormatter:
    def __init__(
        self,
        tool_version: str = "0.2.0",
        information_uri: str = "https://github.com/anomalyco/r2morph",
    ):
        self.tool_version = tool_version
        self.information_uri = information_uri
        self._mutation_rules = self._build_rules(MUTATION_RULES)
        self._validation_rules = self._build_rules(VALIDATION_RULES)

    def _build_rules(self, rule_defs: list[dict[str, Any]]) -> list[SARIFRule]:
        rules = []
        for rd in rule_defs:
            rule = SARIFRule(
                id=rd["id"],
                name=rd["name"],
                short_description=SARIFMessage(text=rd["short_description"]),
                full_description=SARIFMessage(text=rd["full_description"]),
                default_level=SARIFLevel(rd.get("default_level", "warning")),
            )
            rules.append(rule)
        return rules

    def format(self, report_data: ReportData) -> SARIFReport:
        driver = SARIFToolComponent(
            name="r2morph",
            version=self.tool_version,
            information_uri=self.information_uri,
            rules=self._mutation_rules + self._validation_rules,
        )

        tool = SARIFTool(driver=driver)

        results = self._build_results(report_data)

        artifacts = self._build_artifacts(report_data)

        invocations = self._build_invocations(report_data)

        run = SARIFRun(
            tool=tool,
            results=results,
            artifacts=artifacts if artifacts else None,
            invocations=invocations if invocations else None,
            original_uri_base_ids={"SRCROOT": str(Path.cwd())},
        )

        return SARIFReport(runs=[run])

    def _build_results(self, report_data: ReportData) -> list[SARIFResult]:
        results = []

        if report_data.mutations:
            for mutation in report_data.mutations:
                result = self._mutation_to_result(mutation, report_data.binary_path)
                results.append(result)

        if report_data.validations:
            for validation in report_data.validations:
                if not validation.passed:
                    result = self._validation_to_result(validation, report_data.binary_path)
                    results.append(result)

        return results

    def _mutation_to_result(self, mutation: MutationResult, binary_path: str) -> SARIFResult:
        rule_id = self._get_mutation_rule_id(mutation.pass_name)

        logical_locations = []
        if mutation.function:
            logical_locations.append(
                SARIFLogicalLocation(
                    name=mutation.function,
                    kind="function",
                )
            )

        artifact_loc = SARIFArtifactLocation(uri=binary_path)
        region = SARIFRegion(
            byte_offset=mutation.address,
            byte_length=len(mutation.original_bytes),
            snippet=SARIFSnippet(text=mutation.original_bytes.hex()),
        )
        physical_loc = SARIFPhysicalLocation(
            artifact_location=artifact_loc,
            region=region,
        )

        location = SARIFLocation(
            physical_location=physical_loc,
            logical_locations=logical_locations if logical_locations else None,
            message=SARIFMessage(
                text=f"Mutation applied at address 0x{mutation.address:x}",
                markdown=f"**{mutation.pass_name}** mutation applied at `0x{mutation.address:x}`",
            ),
        )

        fix = self._build_fix(mutation, binary_path)

        return SARIFResult(
            rule_id=rule_id,
            level=SARIFLevel.NOTE,
            message=SARIFMessage(
                text=mutation.description or f"Applied {mutation.pass_name} mutation",
                markdown=mutation.description or f"Applied **{mutation.pass_name}** mutation",
            ),
            locations=[location],
            fixes=[fix],
            properties={
                "pass_name": mutation.pass_name,
                "original_size": len(mutation.original_bytes),
                "mutated_size": len(mutation.mutated_bytes),
                "section": mutation.section or "unknown",
            },
        )

    def _build_fix(self, mutation: MutationResult, binary_path: str) -> SARIFFix:
        artifact_loc = SARIFArtifactLocation(uri=binary_path)

        replacement = SARIFReplacement(
            deleted_region=SARIFRegion(
                byte_offset=mutation.address,
                byte_length=len(mutation.original_bytes),
            ),
            inserted_content=mutation.mutated_bytes.hex(),
        )
        file_change = SARIFFileChange(
            artifact_location=artifact_loc,
            replacements=[replacement],
        )

        return SARIFFix(
            description=SARIFMessage(
                text=f"Applied {mutation.pass_name} mutation",
                markdown=f"Applied **{mutation.pass_name}** mutation",
            ),
            file_changes=[file_change],
        )

    def _validation_to_result(self, validation: ValidationResult, binary_path: str) -> SARIFResult:
        rule_id = self._get_validation_rule_id(validation.validation_type)

        artifact_loc = SARIFArtifactLocation(uri=binary_path)

        region = None
        if validation.address is not None:
            region = SARIFRegion(
                byte_offset=validation.address,
                snippet=SARIFSnippet(text=f"address: 0x{validation.address:x}"),
            )

        physical_loc = SARIFPhysicalLocation(
            artifact_location=artifact_loc,
            region=region,
        )

        location = SARIFLocation(physical_location=physical_loc)

        level = SARIFLevel.ERROR if validation.severity == "error" else SARIFLevel.WARNING

        properties: dict[str, Any] = {"validation_type": validation.validation_type}
        if validation.details:
            properties.update(validation.details)

        return SARIFResult(
            rule_id=rule_id,
            level=level,
            message=SARIFMessage(
                text=validation.message or "Validation failed",
                markdown=validation.message or "Validation failed",
            ),
            locations=[location],
            properties=properties,
        )

    def _build_artifacts(self, report_data: ReportData) -> list[SARIFArtifact]:
        artifacts = []

        loc = SARIFArtifactLocation(uri=report_data.binary_path)
        artifact = SARIFArtifact(location=loc, mime_type="application/octet-stream")
        artifacts.append(artifact)

        if report_data.output_path:
            loc = SARIFArtifactLocation(uri=report_data.output_path)
            artifact = SARIFArtifact(location=loc, mime_type="application/octet-stream")
            artifacts.append(artifact)

        return artifacts

    def _build_invocations(self, report_data: ReportData) -> list[SARIFInvocation]:
        invocation = SARIFInvocation(
            execution_successful=report_data.exit_code == 0,
            exit_code=report_data.exit_code,
        )

        if report_data.start_time:
            invocation.start_time_utc = report_data.start_time.isoformat()
        if report_data.end_time:
            invocation.end_time_utc = report_data.end_time.isoformat()

        return [invocation]

    def _get_mutation_rule_id(self, pass_name: str) -> str:
        name_map = {
            "nop": "RM001",
            "nop-insertion": "RM001",
            "substitute": "RM002",
            "instruction-substitution": "RM002",
            "register": "RM003",
            "register-substitution": "RM003",
            "block": "RM004",
            "block-reordering": "RM004",
            "dead-code": "RM005",
            "dead-code-injection": "RM005",
            "opaque": "RM006",
            "opaque-predicates": "RM006",
            "expand": "RM007",
            "instruction-expansion": "RM007",
            "cff": "RM008",
            "control-flow-flattening": "RM008",
        }
        return name_map.get(pass_name, "RM001")

    def _get_validation_rule_id(self, validation_type: str) -> str:
        type_map = {
            "structural": "RV001",
            "runtime": "RV002",
            "semantic": "RV003",
            "cfg": "RV004",
            "cfg-integrity": "RV004",
        }
        return type_map.get(validation_type, "RV001")

    def to_json(self, report_data: ReportData) -> str:
        report = self.format(report_data)
        return report.to_json()

    def to_file(self, report_data: ReportData, output_path: str | Path) -> None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        json_content = self.to_json(report_data)
        output_path.write_text(json_content)


def format_as_sarif(
    mutations: list[dict[str, Any]],
    validations: list[dict[str, Any]],
    binary_path: str,
    output_path: str | None = None,
    tool_version: str = "0.2.0",
) -> SARIFReport:
    formatter = SARIFFormatter(tool_version=tool_version)

    mutation_results = []
    for m in mutations:
        mr = MutationResult(
            address=m.get("address", 0),
            original_bytes=m.get("original_bytes", b""),
            mutated_bytes=m.get("mutated_bytes", b""),
            pass_name=m.get("pass_name", "unknown"),
            description=m.get("description"),
            function=m.get("function"),
            section=m.get("section"),
        )
        mutation_results.append(mr)

    validation_results = []
    for v in validations:
        vr = ValidationResult(
            passed=v.get("passed", True),
            address=v.get("address"),
            message=v.get("message"),
            validation_type=v.get("validation_type", "structural"),
            severity=v.get("severity", "warning"),
            details=v.get("details"),
        )
        validation_results.append(vr)

    report_data = ReportData(
        binary_path=binary_path,
        output_path=output_path,
        mutations=mutation_results,
        validations=validation_results,
    )

    return formatter.format(report_data)
