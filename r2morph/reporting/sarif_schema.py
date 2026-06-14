"""
SARIF 2.1.0 schema definitions for r2morph mutation reports.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for serializing static analysis results. This module provides typed
dataclasses for SARIF 2.1.0 compliance.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd02/sarif-v2.1.0-csprd02.html
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from r2morph.reporting import sarif_schema_core as _core

SARIFArtifactLocation = _core.SARIFArtifactLocation
SARIFCodeFlow = _core.SARIFCodeFlow
SARIFFileChange = _core.SARIFFileChange
SARIFFix = _core.SARIFFix
SARIFLevel = _core.SARIFLevel
SARIFLocation = _core.SARIFLocation
SARIFLogicalLocation = _core.SARIFLogicalLocation
SARIFMessage = _core.SARIFMessage
SARIFPhysicalLocation = _core.SARIFPhysicalLocation
SARIFRegion = _core.SARIFRegion
SARIFReplacement = _core.SARIFReplacement
SARIFSnippet = _core.SARIFSnippet
SARIFTaxon = _core.SARIFTaxon
SARIFTaxonReference = _core.SARIFTaxonReference
SARIFTaxonomy = _core.SARIFTaxonomy
SARIFThreadFlow = _core.SARIFThreadFlow
SARIFThreadFlowLocation = _core.SARIFThreadFlowLocation


@dataclass
class SARIFResult:
    rule_id: str
    level: SARIFLevel = SARIFLevel.WARNING
    message: SARIFMessage | None = None
    locations: list[SARIFLocation] = field(default_factory=list)
    related_locations: list[SARIFLocation] = field(default_factory=list)
    fixes: list[SARIFFix] | None = None
    code_flows: list[SARIFCodeFlow] | None = None
    rule_index: int | None = None
    partial_fingerprints: dict[str, str] | None = None
    taxa: list[SARIFTaxonReference] | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.level.value,
        }
        if self.message:
            d["message"] = self.message.to_dict()
        if self.locations:
            d["locations"] = [loc.to_dict() for loc in self.locations]
        if self.related_locations:
            d["relatedLocations"] = [loc.to_dict() for loc in self.related_locations]
        if self.fixes:
            d["fixes"] = [fix.to_dict() for fix in self.fixes]
        if self.code_flows:
            d["codeFlows"] = [cf.to_dict() for cf in self.code_flows]
        if self.rule_index is not None:
            d["ruleIndex"] = self.rule_index
        if self.partial_fingerprints:
            d["partialFingerprints"] = self.partial_fingerprints
        if self.taxa:
            d["taxa"] = [t.to_dict() for t in self.taxa]
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class SARIFRule:
    id: str
    name: str
    short_description: SARIFMessage | None = None
    full_description: SARIFMessage | None = None
    help_uri: str | None = None
    default_level: SARIFLevel = SARIFLevel.WARNING
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "defaultConfiguration": {"level": self.default_level.value},
        }
        if self.short_description:
            d["shortDescription"] = self.short_description.to_dict()
        if self.full_description:
            d["fullDescription"] = self.full_description.to_dict()
        if self.help_uri:
            d["helpUri"] = self.help_uri
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class SARIFToolComponent:
    name: str
    version: str | None = None
    information_uri: str | None = None
    rules: list[SARIFRule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name}
        if self.version:
            d["version"] = self.version
        if self.information_uri:
            d["informationUri"] = self.information_uri
        if self.rules:
            d["rules"] = [rule.to_dict() for rule in self.rules]
        return d


@dataclass
class SARIFTool:
    driver: SARIFToolComponent
    extensions: list[SARIFToolComponent] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"driver": self.driver.to_dict()}
        if self.extensions:
            d["extensions"] = [ext.to_dict() for ext in self.extensions]
        return d


@dataclass
class SARIFArtifact:
    location: SARIFArtifactLocation
    mime_type: str | None = None
    contents: str | None = None
    encoding: str = "utf-8"
    source_language: str | None = None
    description: SARIFMessage | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"location": self.location.to_dict()}
        if self.mime_type:
            d["mimeType"] = self.mime_type
        if self.contents is not None:
            d["contents"] = {"text": self.contents}
        if self.encoding != "utf-8":
            d["encoding"] = self.encoding
        if self.source_language:
            d["sourceLanguage"] = self.source_language
        if self.description:
            d["description"] = self.description.to_dict()
        return d


@dataclass
class SARIFInvocation:
    execution_successful: bool = True
    start_time_utc: str | None = None
    end_time_utc: str | None = None
    exit_code: int | None = None
    tool_execution_notifications: list[SARIFNotification] | None = None
    arguments: list[str] | None = None
    working_directory: SARIFArtifactLocation | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"executionSuccessful": self.execution_successful}
        if self.start_time_utc:
            d["startTimeUtc"] = self.start_time_utc
        if self.end_time_utc:
            d["endTimeUtc"] = self.end_time_utc
        if self.exit_code is not None:
            d["exitCode"] = self.exit_code
        if self.tool_execution_notifications:
            d["toolExecutionNotifications"] = [n.to_dict() for n in self.tool_execution_notifications]
        if self.arguments:
            d["arguments"] = self.arguments
        if self.working_directory:
            d["workingDirectory"] = self.working_directory.to_dict()
        return d


@dataclass
class SARIFNotification:
    level: SARIFLevel
    message: SARIFMessage
    descriptor: SARIFRule | None = None
    locations: list[SARIFLocation] | None = None
    related_locations: list[SARIFLocation] | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"level": self.level.value, "message": self.message.to_dict()}
        if self.descriptor:
            d["descriptor"] = self.descriptor.to_dict()
        if self.locations:
            d["locations"] = [loc.to_dict() for loc in self.locations]
        if self.related_locations:
            d["relatedLocations"] = [loc.to_dict() for loc in self.related_locations]
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class SARIFRun:
    tool: SARIFTool
    results: list[SARIFResult] = field(default_factory=list)
    artifacts: list[SARIFArtifact] | None = None
    invocations: list[SARIFInvocation] | None = None
    taxonomies: list[SARIFTaxonomy] | None = None
    original_uri_base_ids: dict[str, str] | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }
        if self.artifacts:
            d["artifacts"] = [a.to_dict() for a in self.artifacts]
        if self.invocations:
            d["invocations"] = [i.to_dict() for i in self.invocations]
        if self.taxonomies:
            d["taxonomies"] = [t.to_dict() for t in self.taxonomies]
        if self.original_uri_base_ids:
            d["originalUriBaseIds"] = self.original_uri_base_ids
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class SARIFReport:
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"
    version: str = "2.1.0"
    runs: list[SARIFRun] = field(default_factory=list)
    inline_external_properties: dict[str, Any] | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "$schema": self.schema_uri,
            "version": self.version,
            "runs": [run.to_dict() for run in self.runs],
        }
        if self.inline_external_properties:
            d["inlineExternalProperties"] = self.inline_external_properties
        if self.properties:
            d["properties"] = self.properties
        return d

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), indent=2)
