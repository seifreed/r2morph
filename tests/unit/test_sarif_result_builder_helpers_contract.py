from dataclasses import dataclass

from r2morph.reporting.sarif_result_builder_helpers import (
    build_code_flows,
    build_mutation_result,
    build_related_locations,
    build_validation_result,
)


@dataclass
class _Mutation:
    address: int
    original_bytes: bytes
    mutated_bytes: bytes
    pass_name: str
    function: str | None = None
    disassembly: str | None = None
    description: str | None = None
    section: str | None = None


@dataclass
class _Validation:
    address: int | None
    message: str | None
    validation_type: str
    severity: str
    details: dict[str, str] | None = None


def test_sarif_result_builder_helpers_cover_core_assembly_paths() -> None:
    mutation_a = _Mutation(
        address=0x1000,
        original_bytes=b"\x90",
        mutated_bytes=b"\x90\x90",
        pass_name="nop-insertion",
        function="main",
        disassembly="nop",
        description="Inserted NOPs",
        section=".text",
    )
    mutation_b = _Mutation(
        address=0x1004,
        original_bytes=b"\x90",
        mutated_bytes=b"\x90\x90",
        pass_name="nop-insertion",
        function="main",
        disassembly="nop",
        description="Inserted NOPs",
        section=".text",
    )
    validation = _Validation(
        address=0x1000,
        message="validation failed",
        validation_type="cfg",
        severity="error",
        details={"kind": "cfg"},
    )

    related_locations = build_related_locations([validation], "binary.exe")
    code_flows = build_code_flows([mutation_a, mutation_b], "binary.exe")
    mutation_result = build_mutation_result(mutation_a, "binary.exe", [validation])
    validation_result = build_validation_result(validation, "binary.exe")

    assert related_locations[0].message is not None
    assert code_flows[0].thread_flows[0].locations[0].location.message is not None
    assert mutation_result.rule_id == "RM001"
    assert mutation_result.related_locations[0].message is not None
    assert validation_result.level.value == "error"
    assert validation_result.properties["kind"] == "cfg"
