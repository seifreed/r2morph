from r2morph.analysis.abi_models import ABI_SPECS, ABIType, ABIViolation, ABIViolationType


def test_abi_models_round_trip() -> None:
    spec = ABI_SPECS["x86_64_sysv"]
    violation = ABIViolation(
        violation_type=ABIViolationType.STACK_ALIGNMENT,
        description="stack misaligned",
        location=0x1000,
    )

    assert spec.abi_type == ABIType.X86_64_SYSTEM_V
    assert spec.stack_alignment == 16
    assert spec.return_regs == ["rax", "rdx"]
    assert "rbx" in spec.callee_saved_regs
    assert repr(spec).startswith("<ABISpec x86_64_sysv")
    assert repr(violation).startswith("<ABIViolation stack_alignment")
