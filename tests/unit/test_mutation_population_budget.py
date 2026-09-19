"""Regression coverage for bounded analysis of large function populations."""

from typing import Any

from r2morph.core.constants import MAX_FUNCTION_ANALYSIS_COUNT
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_apply import _ordered_functions
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.pattern_substitution import PatternSubstitutionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect


class _LargeFunctionPopulationBinary:
    class _R2:
        @staticmethod
        def cmdj(_command: str) -> list[dict[str, Any]]:
            return []

    r2 = _R2()

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


def test_code_virtualization_accepts_explicitly_bounded_larger_population() -> None:
    result = CodeVirtualizationPass(
        {"probability": 0.0, "max_function_analysis_count": MAX_FUNCTION_ANALYSIS_COUNT + 1}
    ).apply(_LargeFunctionPopulationBinary())

    expect(result["unsupported_function_capabilities"] != {"analysis_budget": 1})


def test_code_virtualization_keeps_sole_runtime_function_candidate() -> None:
    class _SingleFunctionBinary:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [{"addr": 0x401000, "name": "entry0", "size": 53}]

    candidates = _ordered_functions(
        _SingleFunctionBinary(),
        entrypoint_addresses=frozenset({0x401000}),
    )

    expect(candidates == [{"addr": 0x401000, "name": "entry0", "size": 53}])


def test_code_virtualization_filters_runtime_entrypoint_when_user_function_exists() -> None:
    class _BinaryWithLoaderAndUserFunction:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x401000, "name": "entry0", "size": 53},
                {"addr": 0x401100, "name": "main", "size": 80},
            ]

    candidates = _ordered_functions(
        _BinaryWithLoaderAndUserFunction(),
        entrypoint_addresses=frozenset({0x401000}),
    )

    expect(candidates == [{"addr": 0x401100, "name": "main", "size": 80}])


def test_code_virtualization_keeps_dispatch_entrypoint_when_requested() -> None:
    class _BinaryWithDispatchEntrypoint:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x401000, "name": "entry0", "size": 53},
                {"addr": 0x401100, "name": "main", "size": 80},
            ]

    candidates = _ordered_functions(
        _BinaryWithDispatchEntrypoint(),
        entrypoint_addresses=frozenset({0x401000}),
        dispatch_entrypoint_addresses=frozenset({0x401000}),
    )

    expect(
        candidates
        == [
            {"addr": 0x401000, "name": "entry0", "size": 53},
            {"addr": 0x401100, "name": "main", "size": 80},
        ]
    )
