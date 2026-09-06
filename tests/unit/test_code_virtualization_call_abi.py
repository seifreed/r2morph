"""Contracts for native-call register bridges in the region VM."""

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import (
    _relocate_flags_slot,
    build_region_blob,
    call_unwind_ranges,
)
from r2morph.mutations.code_virtualization_region_control_handlers import (
    _GUARD,
    CallBridgeConfig,
    _call_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
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

    expect(
        f"call_resume_0:\n  mov r11d, 0x135c0000\n  lea r12, [rsp+{_GUARD - 0x340}]" in assembly
        and "mov r11d, 0x12ac0000" in assembly
    )


def test_flags_slot_relocation_preserves_call_resume_frame_base() -> None:
    assembly = "call_resume_0:\n" "  lea r12, [rsp+128]\n" "  pushfq\n" "  pop qword ptr [rsp+128]\n"

    relocated = _relocate_flags_slot(assembly, 200)

    expect(relocated == "call_resume_0:\n  lea r12, [rsp+128]\n  pushfq\n  pop qword ptr [rsp + 200]\n")


def test_call_blob_exposes_relocated_cfa_ranges_for_each_handler_copy() -> None:
    items = [("call", 0x9000), ("exit", 0x2000)]
    region = Region(
        items,
        0x2000,
        0x1000,
        {key for item in items if (key := _op_key(item)) is not None},
        [(0x1000, 5)],
    )
    scheme = build_region_scheme(region, randomness.Random(7))
    blob = build_region_blob(region, 0x500000, scheme)

    expect(blob is not None)
    ranges = call_unwind_ranges(blob, scheme, region) if blob is not None else None
    expect(ranges is not None and len(ranges) == len(scheme.dup["call"]))
    expect(all(start < end and cfa_offset > _GUARD for start, end, cfa_offset in ranges or ()))
