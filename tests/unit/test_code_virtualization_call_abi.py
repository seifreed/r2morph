"""Contracts for native-call register bridges in the region VM."""

from r2morph.mutations.code_virtualization_region_codegen import _relocate_flags_slot
from r2morph.mutations.code_virtualization_region_control_handlers import (
    _GUARD,
    CallBridgeConfig,
    _call_handler_asm,
)
from tests.utils.assertions import expect


def test_call_bridge_loads_all_xmm_arguments_before_native_call() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))

    expect(all(f"movups xmm{index}, xmmword ptr [rsp+{0x100 + index * 16}]" in assembly for index in range(16)))


def test_call_bridge_loads_and_spills_all_ymm_upper_halves() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)), CallBridgeConfig(preserve_ymm=True))

    expect(
        all(
            f"vinsertf128 ymm{index}, ymm{index}, xmmword ptr [rsp+{0x300 + index * 16}], 1" in assembly
            and f"movups xmmword ptr [r12+{0x300 + index * 16}], xmm0" in assembly
            for index in range(16)
        )
    )


def test_call_bridge_spills_all_xmm_results_after_native_call() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))

    expect(all(f"movups xmmword ptr [r12+{0x100 + index * 16}], xmm{index}" in assembly for index in range(16)))


def test_call_bridge_captures_callee_flags_before_register_spills() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))
    flags_capture = "pushfq\n  pop qword ptr [r12+128]"
    first_spill = "movups xmmword ptr [r12+256], xmm0"

    expect(assembly.index(flags_capture) < assembly.index(first_spill))


def test_call_bridge_restores_mxcsr_after_native_return() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))

    expect("stmxcsr dword ptr [rsp+528]" in assembly and "ldmxcsr dword ptr [r12+528]" in assembly)


def test_call_bridge_restores_all_system_v_callee_saved_registers() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)))

    expect(all(f"mov {register}, r11" in assembly for register in ("rbx", "rbp", "r13", "r14", "r15", "r12")))


def test_call_bridge_reconstructs_frame_after_native_return() -> None:
    assembly = _call_handler_asm(0, "0x12345678", tuple(range(16)), CallBridgeConfig(frame_size=0x340))

    expect(f"call_resume_0:\n  lea r12, [rsp+{_GUARD - 0x340}]" in assembly)


def test_flags_slot_relocation_preserves_call_resume_frame_base() -> None:
    assembly = "call_resume_0:\n" "  lea r12, [rsp+128]\n" "  pushfq\n" "  pop qword ptr [rsp+128]\n"

    relocated = _relocate_flags_slot(assembly, 200)

    expect(relocated == "call_resume_0:\n  lea r12, [rsp+128]\n  pushfq\n  pop qword ptr [rsp + 200]\n")
