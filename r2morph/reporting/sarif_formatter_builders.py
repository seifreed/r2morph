"""Helper builders for SARIF formatter assembly."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from r2morph.reporting.sarif_schema import (
    SARIFArtifact,
    SARIFArtifactLocation,
    SARIFInvocation,
    SARIFLevel,
    SARIFMessage,
    SARIFRule,
    SARIFTaxon,
    SARIFTaxonomy,
    SARIFTool,
    SARIFToolComponent,
)

__all__ = [
    "MutationResult",
    "ReportData",
    "ValidationResult",
    "build_artifacts",
    "build_driver",
    "build_invocations",
    "build_mitre_taxonomy",
    "build_rules",
]


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


def build_rules(rule_defs: list[dict[str, Any]]) -> list[SARIFRule]:
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


def build_mitre_taxonomy(mitre_attack: dict[str, dict[str, str]]) -> SARIFTaxonomy:
    seen: dict[str, SARIFTaxon] = {}
    for entry in mitre_attack.values():
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


def build_driver(tool_version: str, information_uri: str, rules: list[SARIFRule]) -> SARIFTool:
    driver = SARIFToolComponent(
        name="r2morph",
        version=tool_version,
        information_uri=information_uri,
        rules=rules,
    )
    return SARIFTool(driver=driver)


def build_artifacts(report_data: ReportData) -> list[SARIFArtifact]:
    artifacts = []
    loc = SARIFArtifactLocation(uri=report_data.binary_path)
    artifacts.append(SARIFArtifact(location=loc, mime_type="application/octet-stream"))
    if report_data.output_path:
        loc = SARIFArtifactLocation(uri=report_data.output_path)
        artifacts.append(SARIFArtifact(location=loc, mime_type="application/octet-stream"))
    return artifacts


def build_invocations(report_data: ReportData) -> list[SARIFInvocation]:
    invocation = SARIFInvocation(
        execution_successful=report_data.exit_code == 0,
        exit_code=report_data.exit_code,
    )
    if report_data.start_time:
        invocation.start_time_utc = report_data.start_time.isoformat()
    if report_data.end_time:
        invocation.end_time_utc = report_data.end_time.isoformat()
    return [invocation]
