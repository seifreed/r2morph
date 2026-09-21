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


def test_code_virtualization_rejects_large_non_tiny_population_before_ret_scan() -> None:
    class _BinaryWithSmallFunctions:
        class _R2:
            def __init__(self) -> None:
                self.commands = 0

            def cmdj(self, _command: str) -> list[dict[str, Any]]:
                self.commands += 1
                return []

        def __init__(self) -> None:
            self.r2 = self._R2()

        def get_sections(self) -> list[dict[str, Any]]:
            return []

        def get_functions(self) -> list[dict[str, int]]:
            return [{"addr": index * 32, "size": 32} for index in range(257)] + [
                {"addr": 0x10000 + index * 8, "size": 1} for index in range(64)
            ]

    binary = _BinaryWithSmallFunctions()
    candidates = _ordered_functions(binary, analysis_budget=256)

    expect(candidates is None and binary.r2.commands == 0)


def test_code_virtualization_bounds_compact_return_probe_for_large_tiny_population() -> None:
    class _BinaryWithTinyFunctions:
        def __init__(self) -> None:
            self.reads = 0

        def get_sections(self) -> list[dict[str, int | str]]:
            return []

        def get_functions(self) -> list[dict[str, int]]:
            return [{"addr": index * 8, "size": 1} for index in range(129)]

        def read_bytes(self, _address: int, _size: int) -> bytes:
            self.reads += 1
            return b"\xc2\x08\x00"

    binary = _BinaryWithTinyFunctions()

    candidates = _ordered_functions(binary, analysis_budget=256)

    expect(candidates == [] and binary.reads == 0)


def test_code_virtualization_keeps_compact_return_function_under_probe_cap() -> None:
    class _CompactReturnBinary:
        def get_sections(self) -> list[dict[str, int | str]]:
            return []

        def get_functions(self) -> list[dict[str, int]]:
            return [{"addr": 0x1000, "size": 3}]

        def read_bytes(self, _address: int, _size: int) -> bytes:
            return b"\xc2\x08\x00"

    candidates = _ordered_functions(_CompactReturnBinary(), analysis_budget=1)

    expect(candidates == [{"addr": 0x1000, "size": 3}])


def test_code_virtualization_prioritizes_named_application_symbols() -> None:
    class _NamedFunctionBinary:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x1000, "size": 16, "name": "fcn.00001000"},
                {"addr": 0x2000, "size": 16, "name": "sym.user_function"},
            ]

    candidates = _ordered_functions(_NamedFunctionBinary(), analysis_budget=2)

    expect([function["name"] for function in candidates or []] == ["sym.user_function", "fcn.00001000"])


def test_code_virtualization_prioritizes_main_jump_target() -> None:
    class _R2:
        @staticmethod
        def cmdj(command: str) -> dict[str, list[dict[str, int | str]]]:
            if command == "pdfj @ 4096":
                return {"ops": [{"type": "jmp", "jump": 0x3000}]}
            return {"ops": []}

    class _BinaryWithMainJump:
        r2 = _R2()

        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x1000, "name": "main", "size": 5},
                {"addr": 0x2000, "name": "fcn.00002000", "size": 16},
                {"addr": 0x3000, "name": "fcn.00003000", "size": 16},
            ] + [{"addr": 0x4000 + index * 16, "name": f"fcn.{index:08x}", "size": 16} for index in range(1022)]

    candidates = _ordered_functions(_BinaryWithMainJump(), analysis_budget=2048)

    expect([function["addr"] for function in candidates or []] == [0x3000])


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


def test_code_virtualization_filters_linker_plt_stub_before_user_function() -> None:
    class _BinaryWithPltStub:
        def get_sections(self) -> list[dict[str, int | str]]:
            return [{"name": ".plt", "vaddr": 0x401000, "vsize": "0", "size": "64", "perm": "r-x"}]

        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x401020, "name": "sym.imp.puts", "size": 16},
                {"addr": 0x401100, "name": "main", "size": 80},
            ]

    candidates = _ordered_functions(_BinaryWithPltStub())

    expect(candidates == [{"addr": 0x401100, "name": "main", "size": 80}])
