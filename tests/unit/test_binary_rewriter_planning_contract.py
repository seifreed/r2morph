from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import (
    calculate_address_shifts,
    is_valid_address,
    plan_rewrite_strategy,
    validate_instructions,
    validate_patches,
)
from tests.utils.assertions import expect

_EXPECTED_ADDRESS_8192 = 0x2000


class _Assembler:
    def asm(self, code: str) -> tuple[list[int], int]:
        return [1, 2, 3], 3


def test_binary_rewriter_planning_helpers_expose_expected_contract() -> None:
    patches = [
        CodePatch(
            address=0x2000,
            operation=RewriteOperation.INSTRUCTION_INSERT,
            original_bytes=b"",
            new_bytes=b"\x90" * 120,
            size_change=120,
        ),
        CodePatch(
            address=0x1000,
            operation=RewriteOperation.INSTRUCTION_REPLACE,
            original_bytes=b"\x90",
            new_bytes=b"\x90\x90",
            size_change=1,
        ),
    ]

    strategy = plan_rewrite_strategy(patches)
    expect(not (strategy["use_code_caves"] is not True))
    expect(not (strategy["requires_relocation_update"] is not True))
    expect([p.address for p in strategy["patch_order"]] == [4096, 8192])

    shifts = calculate_address_shifts(patches)
    expect(shifts[4096] == 0)
    expect(shifts[8192] == 1)

    expect(not (is_valid_address({".text": {"vaddr": 0x1000, "vsize": 0x200}}, 0x1100) is not True))
    expect(not (is_valid_address({".text": {"vaddr": 0x1000, "vsize": 0x200}}, 0x2200) is not False))

    expect(not (validate_instructions(_Assembler(), ["nop", "ret"]) is not True))

    result = validate_patches(
        [
            CodePatch(
                address=0x2000,
                operation=RewriteOperation.INSTRUCTION_INSERT,
                original_bytes=b"",
                new_bytes=b"\x90" * 5,
                size_change=5,
                new_instructions=["invalid"],
            ),
            CodePatch(
                address=0x2000,
                operation=RewriteOperation.INSTRUCTION_DELETE,
                original_bytes=b"\x90" * 2000,
                new_bytes=b"",
                size_change=-2000,
            ),
        ],
        lambda address: address != _EXPECTED_ADDRESS_8192,
        lambda instructions: False,
    )
    expect(not (result["valid"] is not False))
    expect(any("Overlapping" in err for err in result["errors"]))
    expect(any("Invalid address" in warning for warning in result["warnings"]))
    expect(any("Large size change" in warning for warning in result["warnings"]))
