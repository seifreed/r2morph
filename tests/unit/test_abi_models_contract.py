from r2morph.analysis.abi_models import ABI_SPECS, ABIType, ABIViolation, ABIViolationType
from tests.utils.assertions import expect

_EXPECTED_SPEC_STACK_ALIGNMENT_16 = 16


def test_abi_models_round_trip() -> None:
    spec = ABI_SPECS["x86_64_sysv"]
    violation = ABIViolation(
        violation_type=ABIViolationType.STACK_ALIGNMENT,
        description="stack misaligned",
        location=0x1000,
    )

    expect(spec.abi_type == ABIType.X86_64_SYSTEM_V)
    expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16)
    expect(spec.return_regs == ["rax", "rdx"])
    expect(not ("rbx" not in spec.callee_saved_regs))
    expect(repr(spec).startswith("<ABISpec x86_64_sysv"))
    expect(repr(violation).startswith("<ABIViolation stack_alignment"))
