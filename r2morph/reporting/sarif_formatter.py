"""
SARIF 2.1.0 formatter for r2morph mutation reports.

Converts mutation and validation results to SARIF format for CI/CD integration
with tools like GitHub Security, Azure DevOps, and SonarQube.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from r2morph.reporting.sarif_formatter_builders import (
    MutationResult,
    ReportData,
    ValidationResult,
    build_artifacts,
    build_driver,
    build_invocations,
    build_mitre_taxonomy,
    build_rules,
)
from r2morph.reporting.sarif_formatter_run import build_report
from r2morph.reporting.sarif_result_builder import SARIFResultBuilder
from r2morph.reporting.sarif_rule_ids import get_mutation_rule_id, get_validation_rule_id
from r2morph.reporting.sarif_schema import SARIFReport

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
        self._mutation_rules = build_rules(MUTATION_RULES)
        self._validation_rules = build_rules(VALIDATION_RULES)
        self._result_builder = SARIFResultBuilder(self._mutation_rules, self._validation_rules)

    def format(self, report_data: ReportData) -> SARIFReport:
        tool = build_driver(
            self.tool_version,
            self.information_uri,
            self._mutation_rules + self._validation_rules,
        )

        results = self._result_builder.build_results(report_data)
        artifacts = build_artifacts(report_data)
        invocations = build_invocations(report_data)
        taxonomy = build_mitre_taxonomy(MITRE_ATTACK)

        return build_report(
            tool,
            results,
            artifacts,
            invocations,
            [taxonomy],
            str(Path.cwd()),
        )

    def _get_mutation_rule_id(self, pass_name: str) -> str:
        return get_mutation_rule_id(pass_name)

    def _get_validation_rule_id(self, validation_type: str) -> str:
        return get_validation_rule_id(validation_type)

    def to_json(self, report_data: ReportData) -> str:
        report = self.format(report_data)
        return report.to_json()

    def to_file(self, report_data: ReportData, output_path: str | Path) -> None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.to_json(report_data))


def _coerce_bytes(raw: Any) -> bytes:
    """Accept either a hex string or a bytes-like for the wire-format
    bytes fields on a mutation dict.

    ``MutationRecord.to_dict`` (the only producer of report mutations)
    stores ``original_bytes``/``mutated_bytes`` as **hex strings** -- they
    have to be JSON-serializable, and the dataclass field is typed
    ``str``. The CLI's ``report --format sarif`` path then loads the JSON
    and hands the dicts straight to this function. Previously the
    formatter assumed ``bytes``, called ``.hex()`` on whatever came in,
    and crashed with ``AttributeError: 'str' object has no attribute
    'hex'`` for every real mutation report. Accept both shapes so the
    bytes-input fast path keeps working for in-process callers while the
    hex-string path the CLI uses just works.
    """
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            # Mutation passes never produce non-hex strings here, but a
            # malformed report shouldn't crash the SARIF output -- treat
            # an unparseable string the same as a missing field.
            return b""
    return b""


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
            original_bytes=_coerce_bytes(m.get("original_bytes", b"")),
            mutated_bytes=_coerce_bytes(m.get("mutated_bytes", b"")),
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
