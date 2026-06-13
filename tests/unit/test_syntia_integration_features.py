import pytest

from r2morph.analysis.symbolic.syntia_integration import InstructionSemantics, SyntiaFramework, VMHandlerSemantics

pytestmark = [pytest.mark.experimental]


def test_syntia_vm_handler_analysis_and_exports(tmp_path):
    framework = SyntiaFramework()

    handler_instructions = [
        (0x1000, b"\x90", "nop"),
        (0x1001, bytes.fromhex("01 d8"), "add eax, ebx"),
        (0x1003, bytes.fromhex("89 d8"), "mov eax, ebx"),
    ]

    handler_result = framework.analyze_vm_handler(handler_instructions, handler_id=1)
    assert handler_result is not None

    simplified = framework.simplify_mba_with_syntia("x + x", variables={"x"})
    assert simplified is None or isinstance(simplified, str)

    stats = framework.get_synthesis_statistics()
    assert "instructions_analyzed" in stats

    output_path = tmp_path / "semantics.json"
    assert framework.export_learned_semantics(output_path) is True
    assert output_path.exists()

    framework.clear_cache()

    # Additional classification paths
    sem = InstructionSemantics(
        address=0x2000, instruction_bytes=b"\x90", disassembly="jmp 0x1", learned_semantics="branch", confidence=0.9
    )
    handler_type = framework._classify_handler_type([sem])
    assert handler_type in {"branch", "unknown"}

    handler_sem = VMHandlerSemantics(
        handler_id=2,
        entry_address=0x2000,
        handler_type="branch",
        instruction_semantics=[sem],
        overall_semantic_formula="branch",
    )
    native = framework._generate_equivalent_native_code(handler_sem)
    assert native is not None


def test_syntia_evaluate_expression_characterization():
    """Pin SyntiaFramework._evaluate_expression: variable substitution, the
    32-bit mask, and the safe-character guard (oracle for routing it through
    the shared safe_eval_arithmetic_node helper)."""
    framework = SyntiaFramework()

    assert framework._evaluate_expression("x ^ y", {"x": 5, "y": 3}) == 6
    assert framework._evaluate_expression("x * y", {"x": 4, "y": 3}) == 12
    # ~0 is -1, masked to 32 bits
    assert framework._evaluate_expression("~x", {"x": 0}) == 0xFFFFFFFF
    # disallowed characters short-circuit to None
    assert framework._evaluate_expression("x and y", {"x": 1, "y": 1}) is None
