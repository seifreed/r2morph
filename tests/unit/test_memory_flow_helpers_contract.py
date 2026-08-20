from r2morph.analysis.memory_flow_helpers import (
    record_saved_register,
    record_stack_allocation,
    record_stack_local,
)
from tests.utils.assertions import expect

_EXPECTED_RECORD_SAVED_REGISTER_PUSH_RBP_0X1000_0_STACK_8 = 8
_EXPECTED_RECORD_STACK_ALLOCATION_SUB_SP_32_0X1004_8_ST_40 = 40
_EXPECTED_STACK_FRAME_ALLOCATIONS_0_SIZE_32 = 32


def test_memory_flow_helpers_contract() -> None:
    stack_frame = {"saved_regs": [], "allocations": []}
    expect(
        record_saved_register("push rbp", 4096, 0, stack_frame)
        == _EXPECTED_RECORD_SAVED_REGISTER_PUSH_RBP_0X1000_0_STACK_8
    )
    expect(stack_frame["saved_regs"][0]["register"] == "rbp")

    expect(
        record_stack_allocation("sub sp, #32", 4100, 8, stack_frame)
        == _EXPECTED_RECORD_STACK_ALLOCATION_SUB_SP_32_0X1004_8_ST_40
    )
    expect(stack_frame["allocations"][0]["size"] == _EXPECTED_STACK_FRAME_ALLOCATIONS_0_SIZE_32)

    locals_map: dict[str, dict[str, int | str]] = {}
    record_stack_local("mov [rbp-16], eax", 0x1008, locals_map)
    expect(not ("var_16" not in locals_map))
