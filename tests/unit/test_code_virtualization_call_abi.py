"""Contracts for native-call register bridges in the region VM."""

from r2morph.mutations.code_virtualization_region_control_handlers import _call_handler_asm
from tests.utils.assertions import expect


def test_call_bridge_loads_all_xmm_arguments_before_native_call() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))

    expect(all(f"movups xmm{index}, xmmword ptr [rsp+{0x100 + index * 16}]" in assembly for index in range(16)))


def test_call_bridge_spills_all_xmm_results_after_native_call() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))

    expect(all(f"movups xmmword ptr [rsp+{0x100 + index * 16}], xmm{index}" in assembly for index in range(16)))
