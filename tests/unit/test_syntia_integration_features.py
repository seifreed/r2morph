from pathlib import Path

from r2morph.analysis.symbolic.syntia_integration import SyntiaFramework, InstructionSemantics, VMHandlerSemantics


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
    sem = InstructionSemantics(address=0x2000, instruction_bytes=b"\x90", disassembly="jmp 0x1", learned_semantics="branch", confidence=0.9)
    handler_type = framework._classify_handler_type([sem])
    assert handler_type in {"branch", "unknown"}

    handler_sem = VMHandlerSemantics(handler_id=2, entry_address=0x2000, handler_type="branch", instruction_semantics=[sem], overall_semantic_formula="branch")
    native = framework._generate_equivalent_native_code(handler_sem)
    assert native is not None
