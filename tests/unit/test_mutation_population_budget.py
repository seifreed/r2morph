"""Regression coverage for bounded analysis of large function populations."""

from typing import Any

from r2morph.core.constants import MAX_FUNCTION_ANALYSIS_COUNT
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect


class _LargeFunctionPopulationBinary:
    def is_analyzed(self) -> bool:
        return True

    def get_arch_family(self) -> tuple[str, int]:
        return ("x86", 64)

    def get_arch_info(self) -> dict[str, Any]:
        return {"format": "ELF", "arch": "x86", "bits": 64}

    def get_sections(self) -> list[dict[str, Any]]:
        return []

    def get_functions(self) -> list[dict[str, Any]]:
        return [{"addr": 0x400000 + index * 16, "size": 16} for index in range(MAX_FUNCTION_ANALYSIS_COUNT + 1)]


def test_pattern_substitution_rejects_large_function_population() -> None:
    result = PatternSubstitutionPass({"probability": 1.0}).apply(_LargeFunctionPopulationBinary())

    expect(result["mutations_applied"] == 0 and result["analysis_budget"] == MAX_FUNCTION_ANALYSIS_COUNT)


def test_instruction_substitution_rejects_large_function_population() -> None:
    result = InstructionSubstitutionPass({"probability": 1.0}).apply(_LargeFunctionPopulationBinary())

    expect(result["mutations_applied"] == 0 and result["functions_processed"] == 0)


def test_register_substitution_rejects_large_function_population() -> None:
    result = RegisterSubstitutionPass({"probability": 1.0}).apply(_LargeFunctionPopulationBinary())

    expect(result["mutations_applied"] == 0 and result["analysis_budget"] == MAX_FUNCTION_ANALYSIS_COUNT)


def test_code_virtualization_rejects_large_function_population() -> None:
    result = CodeVirtualizationPass({"probability": 1.0}).apply(_LargeFunctionPopulationBinary())

    expect(
        result["functions_virtualized"] == 0 and result["unsupported_function_capabilities"] == {"analysis_budget": 1}
    )
