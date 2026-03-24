"""
SARIF 2.1.0 formatter for r2morph mutation reports.

Converts mutation and validation results to SARIF format for CI/CD integration
with tools like GitHub Security, Azure DevOps, and SonarQube.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from r2morph.reporting.sarif_schema import (
    SARIFArtifact,
    SARIFArtifactLocation,
    SARIFCodeFlow,
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
    SARIFTaxon,
    SARIFTaxonomy,
    SARIFTaxonReference,
    SARIFThreadFlow,
    SARIFThreadFlowLocation,
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
    disassembly: str | None = None


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

MITRE_ATTACK: dict[str, dict[str, str]] = {
    "nop": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "nop-insertion": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "substitute": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "instruction-substitution": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "register": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "register-substitution": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "block": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "block-reordering": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "dead-code": {"id": "T1027.001", "name": "Binary Padding"},
    "dead-code-injection": {"id": "T1027.001", "name": "Binary Padding"},
    "opaque": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "opaque-predicates": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "expand": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "instruction-expansion": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "cff": {"id": "T1027.002", "name": "Software Packing"},
    "control-flow-flattening": {"id": "T1027.002", "name": "Software Packing"},
}


class SARIFFormatter:
    def __init__(
        self,
        tool_version: str = "0.2.0",
        information_uri: str = "https://github.com/anomalyco/r2morph",
    ) -> None:
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

    def _build_mitre_taxonomy(self) -> SARIFTaxonomy:
        seen: dict[str, SARIFTaxon] = {}
        for entry in MITRE_ATTACK.values():
            tid = entry["id"]
            if tid not in seen:
                seen[tid] = SARIFTaxon(
                    id=tid,
                    name=entry["name"],
                    short_description=SARIFMessage(text=entry["name"]),
                )
        return SARIFTaxonomy(
            name="MITRE ATT&CK",
            version="14.0",
            information_uri="https://attack.mitre.org",
            taxa=list(seen.values()),
        )

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
        taxonomy = self._build_mitre_taxonomy()

        run = SARIFRun(
            tool=tool,
            results=results,
            artifacts=artifacts if artifacts else None,
            invocations=invocations if invocations else None,
            taxonomies=[taxonomy],
            original_uri_base_ids={"SRCROOT": str(Path.cwd())},
        )

        return SARIFReport(runs=[run])

    def _build_results(self, report_data: ReportData) -> list[SARIFResult]:
        results: list[SARIFResult] = []

        validation_by_addr: dict[int, list[ValidationResult]] = defaultdict(list)
        if report_data.validations:
            for v in report_data.validations:
                if v.address is not None and not v.passed:
                    validation_by_addr[v.address].append(v)

        mutation_results: list[SARIFResult] = []
        if report_data.mutations:
            for mutation in report_data.mutations:
                related = validation_by_addr.get(mutation.address, [])
                result = self._mutation_to_result(mutation, report_data.binary_path, related)
                mutation_results.append(result)

        code_flows = self._build_code_flows(report_data.mutations or [], report_data.binary_path)
        if code_flows and mutation_results:
            mutation_results[0].code_flows = code_flows

        results.extend(mutation_results)

        if report_data.validations:
            for validation in report_data.validations:
                if not validation.passed:
                    result = self._validation_to_result(validation, report_data.binary_path)
                    results.append(result)

        return results

    def _mutation_to_result(
        self,
        mutation: MutationResult,
        binary_path: str,
        related_validations: list[ValidationResult],
    ) -> SARIFResult:
        rule_id = self._get_mutation_rule_id(mutation.pass_name)

        logical_locations = []
        if mutation.function:
            logical_locations.append(SARIFLogicalLocation(name=mutation.function, kind="function"))

        snippet_text = mutation.original_bytes.hex()
        snippet_rendered = None
        if mutation.disassembly:
            snippet_rendered = SARIFMessage(text=mutation.disassembly)

        artifact_loc = SARIFArtifactLocation(uri=binary_path)
        region = SARIFRegion(
            byte_offset=mutation.address,
            byte_length=len(mutation.original_bytes),
            snippet=SARIFSnippet(text=snippet_text, rendered=snippet_rendered),
        )
        physical_loc = SARIFPhysicalLocation(artifact_location=artifact_loc, region=region)

        location = SARIFLocation(
            physical_location=physical_loc,
            logical_locations=logical_locations if logical_locations else None,
            message=SARIFMessage(
                text=f"Mutation applied at address 0x{mutation.address:x}",
                markdown=f"**{mutation.pass_name}** mutation at `0x{mutation.address:x}`",
            ),
        )

        fix = self._build_fix(mutation, binary_path)

        related_locs = self._build_related_locations(related_validations, binary_path)

        fingerprint = hashlib.sha256(
            f"{mutation.pass_name}:{mutation.address}:{mutation.original_bytes.hex()}".encode()
        ).hexdigest()[:16]

        mitre = MITRE_ATTACK.get(mutation.pass_name)
        taxa_refs = None
        if mitre:
            taxa_refs = [SARIFTaxonReference(id=mitre["id"], tool_component={"name": "MITRE ATT&CK"})]

        return SARIFResult(
            rule_id=rule_id,
            level=SARIFLevel.NOTE,
            message=SARIFMessage(
                text=mutation.description or f"Applied {mutation.pass_name} mutation",
                markdown=mutation.description or f"Applied **{mutation.pass_name}** mutation",
            ),
            locations=[location],
            related_locations=related_locs,
            fixes=[fix],
            partial_fingerprints={"primaryLocationLineHash/v1": fingerprint},
            taxa=taxa_refs,
            properties={
                "pass_name": mutation.pass_name,
                "original_size": len(mutation.original_bytes),
                "mutated_size": len(mutation.mutated_bytes),
                "section": mutation.section or "unknown",
            },
        )

    def _build_related_locations(self, validations: list[ValidationResult], binary_path: str) -> list[SARIFLocation]:
        related: list[SARIFLocation] = []
        for v in validations:
            region = None
            if v.address is not None:
                region = SARIFRegion(byte_offset=v.address)
            loc = SARIFLocation(
                physical_location=SARIFPhysicalLocation(
                    artifact_location=SARIFArtifactLocation(uri=binary_path),
                    region=region,
                ),
                message=SARIFMessage(text=v.message or f"Validation {v.validation_type} failed"),
            )
            related.append(loc)
        return related

    def _build_code_flows(self, mutations: list[MutationResult], binary_path: str) -> list[SARIFCodeFlow]:
        by_function: dict[str, list[MutationResult]] = defaultdict(list)
        for m in mutations:
            key = m.function or "__global__"
            by_function[key].append(m)

        flows: list[SARIFCodeFlow] = []
        for func_name, func_mutations in by_function.items():
            if len(func_mutations) < 2:
                continue
            sorted_mutations = sorted(func_mutations, key=lambda m: m.address)
            thread_locs: list[SARIFThreadFlowLocation] = []
            for i, m in enumerate(sorted_mutations):
                loc = SARIFLocation(
                    physical_location=SARIFPhysicalLocation(
                        artifact_location=SARIFArtifactLocation(uri=binary_path),
                        region=SARIFRegion(byte_offset=m.address),
                    ),
                    message=SARIFMessage(text=f"{m.pass_name} at 0x{m.address:x}"),
                )
                thread_locs.append(SARIFThreadFlowLocation(location=loc, index=i))

            flow = SARIFCodeFlow(
                message=SARIFMessage(text=f"Mutation chain in {func_name}"),
                thread_flows=[SARIFThreadFlow(locations=thread_locs)],
            )
            flows.append(flow)
        return flows

    def _build_fix(self, mutation: MutationResult, binary_path: str) -> SARIFFix:
        artifact_loc = SARIFArtifactLocation(uri=binary_path)
        replacement = SARIFReplacement(
            deleted_region=SARIFRegion(
                byte_offset=mutation.address,
                byte_length=len(mutation.original_bytes),
            ),
            inserted_content=mutation.mutated_bytes.hex(),
        )
        file_change = SARIFFileChange(artifact_location=artifact_loc, replacements=[replacement])
        return SARIFFix(
            description=SARIFMessage(text=f"Applied {mutation.pass_name} mutation"),
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

        physical_loc = SARIFPhysicalLocation(artifact_location=artifact_loc, region=region)
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
        artifacts.append(SARIFArtifact(location=loc, mime_type="application/octet-stream"))
        if report_data.output_path:
            loc = SARIFArtifactLocation(uri=report_data.output_path)
            artifacts.append(SARIFArtifact(location=loc, mime_type="application/octet-stream"))
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
        output_path.write_text(self.to_json(report_data))


def format_as_sarif(
    mutations: list[dict[str, Any]],
    validations: list[dict[str, Any]],
    binary_path: str,
    output_path: str | None = None,
    tool_version: str = "0.2.0",
) -> SARIFReport:
    formatter = SARIFFormatter(tool_version=tool_version)

    mutation_results = [
        MutationResult(
            address=m.get("address", 0),
            original_bytes=m.get("original_bytes", b""),
            mutated_bytes=m.get("mutated_bytes", b""),
            pass_name=m.get("pass_name", "unknown"),
            description=m.get("description"),
            function=m.get("function"),
            section=m.get("section"),
            disassembly=m.get("disassembly") or m.get("original_disasm"),
        )
        for m in mutations
    ]

    validation_results = [
        ValidationResult(
            passed=v.get("passed", True),
            address=v.get("address"),
            message=v.get("message"),
            validation_type=v.get("validation_type", "structural"),
            severity=v.get("severity", "warning"),
            details=v.get("details"),
        )
        for v in validations
    ]

    report_data = ReportData(
        binary_path=binary_path,
        output_path=output_path,
        mutations=mutation_results,
        validations=validation_results,
    )
    return formatter.format(report_data)
