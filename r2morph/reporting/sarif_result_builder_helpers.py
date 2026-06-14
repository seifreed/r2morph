"""Pure SARIF result assembly helpers."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from r2morph.reporting.sarif_catalogs import MITRE_ATTACK
from r2morph.reporting.sarif_rule_ids import get_mutation_rule_id, get_validation_rule_id
from r2morph.reporting.sarif_schema import (
    SARIFArtifactLocation,
    SARIFCodeFlow,
    SARIFFileChange,
    SARIFFix,
    SARIFLevel,
    SARIFLocation,
    SARIFLogicalLocation,
    SARIFMessage,
    SARIFPhysicalLocation,
    SARIFRegion,
    SARIFReplacement,
    SARIFResult,
    SARIFSnippet,
    SARIFTaxonReference,
    SARIFThreadFlow,
    SARIFThreadFlowLocation,
)


def build_related_locations(validations: list[Any], binary_path: str) -> list[SARIFLocation]:
    related: list[SARIFLocation] = []
    for validation in validations:
        region = None
        if validation.address is not None:
            region = SARIFRegion(byte_offset=validation.address)
        loc = SARIFLocation(
            physical_location=SARIFPhysicalLocation(
                artifact_location=SARIFArtifactLocation(uri=binary_path),
                region=region,
            ),
            message=SARIFMessage(text=validation.message or f"Validation {validation.validation_type} failed"),
        )
        related.append(loc)
    return related


def build_code_flows(mutations: list[Any], binary_path: str) -> list[SARIFCodeFlow]:
    by_function: dict[str, list[Any]] = defaultdict(list)
    for mutation in mutations:
        key = mutation.function or "__global__"
        by_function[key].append(mutation)

    flows: list[SARIFCodeFlow] = []
    for func_name, func_mutations in by_function.items():
        if len(func_mutations) < 2:
            continue
        sorted_mutations = sorted(func_mutations, key=lambda mutation: mutation.address)
        thread_locs: list[SARIFThreadFlowLocation] = []
        for index, mutation in enumerate(sorted_mutations):
            loc = SARIFLocation(
                physical_location=SARIFPhysicalLocation(
                    artifact_location=SARIFArtifactLocation(uri=binary_path),
                    region=SARIFRegion(byte_offset=mutation.address),
                ),
                message=SARIFMessage(text=f"{mutation.pass_name} at 0x{mutation.address:x}"),
            )
            thread_locs.append(SARIFThreadFlowLocation(location=loc, index=index))

        flow = SARIFCodeFlow(
            message=SARIFMessage(text=f"Mutation chain in {func_name}"),
            thread_flows=[SARIFThreadFlow(locations=thread_locs)],
        )
        flows.append(flow)
    return flows


def build_fix(mutation: Any, binary_path: str) -> SARIFFix:
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


def build_mutation_result(mutation: Any, binary_path: str, related_validations: list[Any]) -> SARIFResult:
    rule_id = get_mutation_rule_id(mutation.pass_name)

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

    fix = build_fix(mutation, binary_path)
    related_locs = build_related_locations(related_validations, binary_path)
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


def build_validation_result(validation: Any, binary_path: str) -> SARIFResult:
    rule_id = get_validation_rule_id(validation.validation_type)
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
