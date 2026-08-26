"""Property coverage for binary rewrite planning."""

from hypothesis import given
from hypothesis import strategies as st

from r2morph.devirtualization.binary_rewriter_models import CodePatch, RewriteOperation
from r2morph.devirtualization.binary_rewriter_planning import calculate_address_shifts, plan_rewrite_strategy
from tests.utils.assertions import expect


@given(
    patches=st.lists(
        st.tuples(
            st.integers(min_value=0x1000, max_value=0xFFFFF),
            st.integers(min_value=-2048, max_value=2048),
        ),
        unique_by=lambda patch: patch[0],
        max_size=24,
    )
)
def test_rewrite_planning_orders_unique_addresses_and_accumulates_shifts(
    patches: list[tuple[int, int]],
) -> None:
    code_patches = [
        CodePatch(
            address=address,
            operation=RewriteOperation.INSTRUCTION_REPLACE,
            original_bytes=b"\x90",
            new_bytes=b"\x90",
            size_change=size_change,
        )
        for address, size_change in patches
    ]

    strategy = plan_rewrite_strategy(code_patches)
    ordered = sorted(patches)
    expected_shifts: dict[int, int] = {}
    current_shift = 0
    for address, size_change in ordered:
        expected_shifts[address] = current_shift
        current_shift += size_change

    expect(
        [patch.address for patch in strategy["patch_order"]] == [address for address, _ in ordered]
        and calculate_address_shifts(code_patches) == expected_shifts
    )
