"""
SARIF 2.1.0 schema definitions for r2morph mutation reports.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for serializing static analysis results. This module provides typed
dataclasses for SARIF 2.1.0 compliance.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd02/sarif-v2.1.0-csprd02.html
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SARIFLevel(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    NONE = "none"


@dataclass
class SARIFMessage:
    text: str
    markdown: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"text": self.text}
        if self.markdown:
            d["markdown"] = self.markdown
        return d


@dataclass
class SARIFArtifactLocation:
    uri: str
    uri_base_id: str | None = None
    index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"uri": self.uri}
        if self.uri_base_id:
            d["uriBaseId"] = self.uri_base_id
        if self.index is not None:
            d["index"] = self.index
        return d


@dataclass
class SARIFRegion:
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    byte_offset: int | None = None
    byte_length: int | None = None
    snippet: SARIFSnippet | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.start_line is not None:
            d["startLine"] = self.start_line
        if self.start_column is not None:
            d["startColumn"] = self.start_column
        if self.end_line is not None:
            d["endLine"] = self.end_line
        if self.end_column is not None:
            d["endColumn"] = self.end_column
        if self.byte_offset is not None:
            d["byteOffset"] = self.byte_offset
        if self.byte_length is not None:
            d["byteLength"] = self.byte_length
        if self.snippet:
            d["snippet"] = self.snippet.to_dict()
        return d


@dataclass
class SARIFSnippet:
    text: str
    rendered: SARIFMessage | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"text": self.text}
        if self.rendered:
            d["rendered"] = self.rendered.to_dict()
        return d


@dataclass
class SARIFPhysicalLocation:
    artifact_location: SARIFArtifactLocation
    region: SARIFRegion | None = None
    context_region: SARIFRegion | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"artifactLocation": self.artifact_location.to_dict()}
        if self.region:
            d["region"] = self.region.to_dict()
        if self.context_region:
            d["contextRegion"] = self.context_region.to_dict()
        return d


@dataclass
class SARIFLocation:
    physical_location: SARIFPhysicalLocation
    logical_locations: list[SARIFLogicalLocation] | None = None
    message: SARIFMessage | None = None
    annotations: list[SARIFLocation] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"physicalLocation": self.physical_location.to_dict()}
        if self.logical_locations:
            d["logicalLocations"] = [ll.to_dict() for ll in self.logical_locations]
        if self.message:
            d["message"] = self.message.to_dict()
        if self.annotations:
            d["annotations"] = [a.to_dict() for a in self.annotations]
        return d


@dataclass
class SARIFLogicalLocation:
    name: str
    fully_qualified_name: str | None = None
    kind: str | None = None
    parent_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name}
        if self.fully_qualified_name:
            d["fullyQualifiedName"] = self.fully_qualified_name
        if self.kind:
            d["kind"] = self.kind
        if self.parent_key:
            d["parentKey"] = self.parent_key
        return d


@dataclass
class SARIFReplacement:
    deleted_region: SARIFRegion
    inserted_content: str
    deleted_length: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "deletedRegion": self.deleted_region.to_dict(),
            "insertedContent": {"text": self.inserted_content},
        }
        if self.deleted_length is not None:
            d["deletedLength"] = self.deleted_length
        return d


@dataclass
class SARIFFileChange:
    artifact_location: SARIFArtifactLocation
    replacements: list[SARIFReplacement]

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifactLocation": self.artifact_location.to_dict(),
            "replacements": [r.to_dict() for r in self.replacements],
        }


@dataclass
class SARIFFix:
    description: SARIFMessage
    file_changes: list[SARIFFileChange]

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description.to_dict(),
            "fileChanges": [fc.to_dict() for fc in self.file_changes],
        }


@dataclass
class SARIFResult:
    rule_id: str
    level: SARIFLevel = SARIFLevel.WARNING
    message: SARIFMessage | None = None
    locations: list[SARIFLocation] = field(default_factory=list)
    related_locations: list[SARIFLocation] = field(default_factory=list)
    fixes: list[SARIFFix] | None = None
    rule_index: int | None = None
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
        if self.rule_index is not None:
            d["ruleIndex"] = self.rule_index
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
        if self.original_uri_base_ids:
            d["originalUriBaseIds"] = self.original_uri_base_ids
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class SARIFReport:
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
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
