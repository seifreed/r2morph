"""Result construction helpers for SARIF formatting."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

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


class SARIFResultBuilder:
    """Build SARIF results from mutation and validation records."""

    def __init__(
        self,
        mutation_rules: list[dict[str, Any]],
        validation_rules: list[dict[str, Any]],
    ) -> None:
        self._mutation_rules = mutation_rules
        self._validation_rules = validation_rules

    def build_results(self, report_data: Any) -> list[SARIFResult]:
        results: list[SARIFResult] = []

        validation_by_addr: dict[int, list[Any]] = defaultdict(list)
        if report_data.validations:
            for validation in report_data.validations:
                if validation.address is not None and not validation.passed:
                    validation_by_addr[validation.address].append(validation)

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
        mutation: Any,
        binary_path: str,
        related_validations: list[Any],
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

    def _build_related_locations(self, validations: list[Any], binary_path: str) -> list[SARIFLocation]:
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

    def _build_code_flows(self, mutations: list[Any], binary_path: str) -> list[SARIFCodeFlow]:
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

    def _build_fix(self, mutation: Any, binary_path: str) -> SARIFFix:
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

    def _validation_to_result(self, validation: Any, binary_path: str) -> SARIFResult:
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
