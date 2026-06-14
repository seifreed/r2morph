from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import (
    calculate_address_shifts,
    is_valid_address,
    plan_rewrite_strategy,
    validate_instructions,
    validate_patches,
)


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
    assert strategy["use_code_caves"] is True
    assert strategy["requires_relocation_update"] is True
    assert [p.address for p in strategy["patch_order"]] == [0x1000, 0x2000]

    shifts = calculate_address_shifts(patches)
    assert shifts[0x1000] == 0
    assert shifts[0x2000] == 1

    assert is_valid_address({".text": {"vaddr": 0x1000, "vsize": 0x200}}, 0x1100) is True
    assert is_valid_address({".text": {"vaddr": 0x1000, "vsize": 0x200}}, 0x2200) is False

    assert validate_instructions(_Assembler(), ["nop", "ret"]) is True

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
        lambda address: address != 0x2000,
        lambda instructions: False,
    )
    assert result["valid"] is False
    assert any("Overlapping" in err for err in result["errors"])
    assert any("Invalid address" in warning for warning in result["warnings"])
    assert any("Large size change" in warning for warning in result["warnings"])
