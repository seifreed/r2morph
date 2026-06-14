from r2morph.analysis.memory_flow_helpers import (
    record_saved_register,
    record_stack_allocation,
    record_stack_local,
)


def test_memory_flow_helpers_contract() -> None:
    stack_frame = {"saved_regs": [], "allocations": []}
    assert record_saved_register("push rbp", 0x1000, 0, stack_frame) == 8
    assert stack_frame["saved_regs"][0]["register"] == "rbp"

    assert record_stack_allocation("sub sp, #32", 0x1004, 8, stack_frame) == 40
    assert stack_frame["allocations"][0]["size"] == 32

    locals_map: dict[str, dict[str, int | str]] = {}
    record_stack_local("mov [rbp-16], eax", 0x1008, locals_map)
    assert "var_16" in locals_map
