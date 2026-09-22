"""Regression tests for virtualization preflight dataflow coverage."""

from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph
from r2morph.analysis.defuse import DefUseAnalyzer
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_apply import (
    _application_candidate_addresses,
    _application_target_addresses,
    _exceeds_function_size_budget,
    _has_compact_ret_cleanup,
    _has_materialized_instructions,
    _ordered_functions,
    _preflight_rejection_diagnostic,
    _static_dataflow_is_complete,
    _transform_function,
    _UnwindContext,
)
from tests.utils.assertions import expect


def _branching_cfg() -> ControlFlowGraph:
    cfg = ControlFlowGraph(function_address=0x1000, function_name="branch")
    cfg.add_block(
        BasicBlock(
            address=0x1000,
            size=5,
            instructions=[{"offset": 0x1000, "disasm": "mov rax, 1", "type": "mov"}],
        )
    )
    cfg.add_block(
        BasicBlock(
            address=0x1010,
            size=5,
            instructions=[{"offset": 0x1010, "disasm": "add rax, 2", "type": "add"}],
        )
    )
    cfg.add_block(
        BasicBlock(
            address=0x1020,
            size=5,
            instructions=[{"offset": 0x1020, "disasm": "sub rax, 2", "type": "sub"}],
        )
    )
    cfg.add_block(
        BasicBlock(
            address=0x1030,
            size=1,
            instructions=[{"offset": 0x1030, "disasm": "ret", "type": "ret"}],
        )
    )
    cfg.add_edge(0x1000, 0x1010)
    cfg.add_edge(0x1000, 0x1020)
    cfg.add_edge(0x1010, 0x1030)
    cfg.add_edge(0x1020, 0x1030)
    return cfg


def test_static_dataflow_branching_cfg_proves_ssa_and_liveness_coverage() -> None:
    expect(_static_dataflow_is_complete(_branching_cfg()))


def test_static_dataflow_budget_rejects_oversized_function_before_cfg() -> None:
    expect(_exceeds_function_size_budget({"size": 65537}, 65536))


def test_static_dataflow_budget_accepts_function_at_limit() -> None:
    expect(not _exceeds_function_size_budget({"size": 65536}, 65536))


def test_empty_disassembly_is_not_reported_as_incomplete_dataflow() -> None:
    class FunctionSource:
        class _Disassembler:
            @staticmethod
            def cmdj(_command: str) -> dict[str, list[dict[str, object]]]:
                return {"ops": []}

        r2 = _Disassembler()

    expect(_has_materialized_instructions(FunctionSource(), {"addr": 0x1000}) is False)


def test_padding_only_disassembly_is_not_a_materialized_function() -> None:
    class FunctionSource:
        class _Disassembler:
            @staticmethod
            def cmdj(_command: str) -> dict[str, list[dict[str, object]]]:
                return {"ops": [{"type": "nop", "opcode": "nop"}]}

        r2 = _Disassembler()

    expect(_has_materialized_instructions(FunctionSource(), {"addr": 0x1000}) is False)


def test_compact_ret_cleanup_is_decoded_without_disassembler_round_trip() -> None:
    class FunctionSource:
        def read_bytes(self, _address: int, _size: int) -> bytes:
            return b"\xc2\x10\x00"

    expect(_has_compact_ret_cleanup(FunctionSource(), {"addr": 0x1000, "size": 3}))


def test_ordered_functions_prioritize_lowest_image_address() -> None:
    class FunctionSource:
        def get_functions(self) -> list[dict[str, int]]:
            return [{"addr": 0x4000}, {"addr": 0x1000}, {"addr": 0x2000}]

    expect([function["addr"] for function in _ordered_functions(FunctionSource())] == [0x1000, 0x2000, 0x4000])


def test_ordered_functions_excludes_tiny_functions_before_analysis_budget() -> None:
    class FunctionSource:
        def get_functions(self) -> list[dict[str, int]]:
            return [{"addr": index, "size": 1} for index in range(300)] + [{"addr": 0x1000, "size": 16}]

    functions = _ordered_functions(FunctionSource(), analysis_budget=1)

    expect(functions == [{"addr": 0x1000, "size": 16}])


def test_ordered_functions_excludes_runtime_helper_aliases_before_function_budget() -> None:
    class FunctionSource:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x1000, "size": 16, "name": "fcn.00001000"},
                {"addr": 0x2000, "size": 16, "name": "sym.user_function"},
            ]

    functions = _ordered_functions(FunctionSource(), analysis_budget=1, entrypoint_addresses=frozenset({0x1000}))

    expect(functions == [{"addr": 0x2000, "size": 16, "name": "sym.user_function"}])


def test_ordered_functions_recovers_unlisted_application_target_function() -> None:
    class FunctionSource:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [{"addr": 0x1000, "size": 3, "name": "main"}]

        class _R2:
            @staticmethod
            def cmd(_command: str) -> str:
                return ""

            @staticmethod
            def cmdj(command: str) -> object:
                if command.startswith("pdfj"):
                    return {"ops": []}
                if command.startswith("pdj"):
                    return [{"addr": 0x1000, "type": "jmp", "jump": 0x2000}]
                if command.startswith("afij"):
                    return [{"addr": 0x2000, "size": 16, "name": "fcn.00002000"}]
                return []

        r2 = _R2()

    functions = _ordered_functions(FunctionSource())

    expect(functions[0] == {"addr": 0x2000, "size": 16, "name": "fcn.00002000"})


def test_application_target_addresses_collect_direct_entry_targets() -> None:
    class FunctionSource:
        def get_functions(self) -> list[dict[str, int | str]]:
            return [
                {"addr": 0x1000, "size": 16, "name": "main"},
                {"addr": 0x2000, "size": 16, "name": "sym.application"},
            ]

        class _R2:
            @staticmethod
            def cmdj(command: str) -> object:
                if command == "pdfj @ 4096":
                    return {"ops": [{"type": "call", "jump": 0x2000}]}
                return {"ops": []}

        r2 = _R2()

    targets = _application_target_addresses(FunctionSource(), FunctionSource().get_functions())

    expect(targets == frozenset({0x2000}))


def test_application_candidate_addresses_exclude_entry_internal_targets() -> None:
    functions = [
        {"addr": 0x1000, "minaddr": 0x1000, "maxaddr": 0x1010, "size": 16, "name": "main"},
    ]

    candidates = _application_candidate_addresses(functions, frozenset({0x1008, 0x1100, 0x1110}))

    expect(candidates == frozenset({0x1100, 0x1110}))


def test_defuse_analyzer_reports_complete_liveness_for_materialized_instructions() -> None:
    analyzer = DefUseAnalyzer(_branching_cfg())
    analyzer.analyze()

    expect(analyzer.has_complete_liveness_coverage())


def test_incomplete_static_dataflow_reports_ssa_liveness_capability() -> None:
    capability, reason = _preflight_rejection_diagnostic(_UnwindContext(unproven=False, frame=None))

    expect(capability == "ssa_liveness" and "SSA" in reason and "liveness" in reason)


def test_unvirtualizable_call_is_rejected_before_cfg_analysis() -> None:
    class FunctionSource:
        class _R2:
            @staticmethod
            def cmdj(command: str) -> object:
                if command.startswith("afbj") or command.startswith("pdj"):
                    return []
                return {
                    "ops": [
                        {"addr": 0x1000, "type": "call", "opcode": "call 0x2000"},
                    ]
                }

        r2 = _R2()

        def get_basic_blocks(self, _address: int) -> list[dict[str, int]]:
            raise AssertionError("CFG analysis must not run for an unvirtualizable call")

    records: tuple[list[dict[str, object]], list[dict[str, object]]] = ([], [])
    result = _transform_function(
        CodeVirtualizationPass({"probability": 1.0}),
        FunctionSource(),
        {"addr": 0x1000, "size": 5},
        records,
        _UnwindContext(unproven=False, frame=None),
    )

    expect(result["unsupported"] == 1 and bool(records[0]))


def test_unwind_parse_error_preserves_precise_rejection_reason() -> None:
    capability, reason = _preflight_rejection_diagnostic(
        _UnwindContext(unproven=True, frame=None, reason="ELF .eh_frame contains an invalid entry length")
    )

    expect(capability == "exceptions_and_unwinding" and reason == "ELF .eh_frame contains an invalid entry length")
