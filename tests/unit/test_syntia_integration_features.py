import pytest

from r2morph.analysis.symbolic.syntia_integration import InstructionSemantics, SyntiaFramework, VMHandlerSemantics
from tests.utils.assertions import expect

_EXPECTED_FRAMEWORK_EVALUATE_EXPRESSION_X_X_0_4294967295 = 0xFFFFFFFF
_EXPECTED_FRAMEWORK_EVALUATE_EXPRESSION_X_Y_X_4_Y_3_12 = 12
_EXPECTED_FRAMEWORK_EVALUATE_EXPRESSION_X_Y_X_5_Y_3_6 = 6


pytestmark = [pytest.mark.experimental]


def test_syntia_vm_handler_analysis_and_exports(tmp_path):
    framework = SyntiaFramework()

    handler_instructions = [
        (0x1000, b"\x90", "nop"),
        (0x1001, bytes.fromhex("01 d8"), "add eax, ebx"),
        (0x1003, bytes.fromhex("89 d8"), "mov eax, ebx"),
    ]

    handler_result = framework.analyze_vm_handler(handler_instructions, handler_id=1)
    expect(handler_result is not None)

    simplified = framework.simplify_mba_with_syntia("x + x", variables={"x"})
    expect(simplified is None or isinstance(simplified, str))

    stats = framework.get_synthesis_statistics()
    expect(not ("instructions_analyzed" not in stats))

    output_path = tmp_path / "semantics.json"
    expect(not (framework.export_learned_semantics(output_path) is not True))
    expect(output_path.exists())

    framework.clear_cache()

    # Additional classification paths
    sem = InstructionSemantics(
        address=0x2000, instruction_bytes=b"\x90", disassembly="jmp 0x1", learned_semantics="branch", confidence=0.9
    )
    handler_type = framework._classify_handler_type([sem])
    expect(not (handler_type not in {"branch", "unknown"}))

    handler_sem = VMHandlerSemantics(
        handler_id=2,
        entry_address=0x2000,
        handler_type="branch",
        instruction_semantics=[sem],
        overall_semantic_formula="branch",
    )
    native = framework._generate_equivalent_native_code(handler_sem)
    expect(native is not None)


def test_syntia_evaluate_expression_characterization():
    """Pin SyntiaFramework._evaluate_expression: variable substitution, the
    32-bit mask, and the safe-character guard (oracle for routing it through
    the shared safe_eval_arithmetic_node helper)."""
    framework = SyntiaFramework()

    expect(
        framework._evaluate_expression("x ^ y", {"x": 5, "y": 3})
        == _EXPECTED_FRAMEWORK_EVALUATE_EXPRESSION_X_Y_X_5_Y_3_6
    )
    expect(
        framework._evaluate_expression("x * y", {"x": 4, "y": 3})
        == _EXPECTED_FRAMEWORK_EVALUATE_EXPRESSION_X_Y_X_4_Y_3_12
    )
    # ~0 is -1, masked to 32 bits
    expect(framework._evaluate_expression("~x", {"x": 0}) == _EXPECTED_FRAMEWORK_EVALUATE_EXPRESSION_X_X_0_4294967295)
    # disallowed characters short-circuit to None
    expect(not (framework._evaluate_expression("x and y", {"x": 1, "y": 1}) is not None))
