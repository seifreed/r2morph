"""Shared SARIF schema types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SARIFLevel(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    NONE = "none"


@dataclass(frozen=True)
class SARIFMessage:
    text: str
    markdown: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"text": self.text}
        if self.markdown:
            d["markdown"] = self.markdown
        return d


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class SARIFSnippet:
    text: str
    rendered: SARIFMessage | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"text": self.text}
        if self.rendered:
            d["rendered"] = self.rendered.to_dict()
        return d


@dataclass(frozen=True)
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
class SARIFThreadFlowLocation:
    location: SARIFLocation
    index: int | None = None
    state: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"location": self.location.to_dict()}
        if self.index is not None:
            d["index"] = self.index
        if self.state:
            d["state"] = self.state
        return d


@dataclass
class SARIFThreadFlow:
    locations: list[SARIFThreadFlowLocation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"locations": [loc.to_dict() for loc in self.locations]}


@dataclass
class SARIFCodeFlow:
    message: SARIFMessage | None = None
    thread_flows: list[SARIFThreadFlow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"threadFlows": [tf.to_dict() for tf in self.thread_flows]}
        if self.message:
            d["message"] = self.message.to_dict()
        return d


@dataclass
class SARIFTaxonReference:
    id: str
    tool_component: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id}
        if self.tool_component:
            d["toolComponent"] = self.tool_component
        return d


@dataclass
class SARIFTaxon:
    id: str
    name: str
    short_description: SARIFMessage | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "name": self.name}
        if self.short_description:
            d["shortDescription"] = self.short_description.to_dict()
        return d


@dataclass
class SARIFTaxonomy:
    name: str
    version: str | None = None
    information_uri: str | None = None
    taxa: list[SARIFTaxon] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name}
        if self.version:
            d["version"] = self.version
        if self.information_uri:
            d["informationUri"] = self.information_uri
        if self.taxa:
            d["taxa"] = [t.to_dict() for t in self.taxa]
        return d
