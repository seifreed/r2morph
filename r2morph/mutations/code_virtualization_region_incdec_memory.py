"""Memory ``inc``/``dec`` handler for the region VM."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_flags import synth_flags_asm
from r2morph.mutations.code_virtualization_region_handlers import (
    _DWORD_WIDTH_BITS,
    _FLAGS_OFFSET,
    _QWORD_WIDTH_BITS,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    MemoryOperationConfig,
    _indexed_address_asm,
    _indexed_address_nobase_asm,
    _mem_address_asm,
)


def _incdec_memory_handler_asm(config: MemoryOperationConfig) -> str:
    """Return a flag-accurate ``inc/dec [memory]`` handler body."""
    kind, mnemonic, width_text = config.handler_key.split("_")
    width = int(width_text)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(
            config.key, config.key_dword, config.field_perm, config.addr_variant
        )
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(config.key, config.key_dword, config.field_perm, config.addr_variant)
    else:
        body, advance = _mem_address_asm(
            kind.endswith("rip"),
            config.key,
            config.key_dword,
            config.field_perm,
            config.addr_variant,
        )
    size_name = {8: "byte", 16: "word", 32: "dword", 64: "qword"}[width]
    if width == _QWORD_WIDTH_BITS:
        body += "  mov rbx, qword ptr [r10]\n"
    elif width == _DWORD_WIDTH_BITS:
        body += "  mov ebx, dword ptr [r10]\n"
    else:
        body += f"  movzx ebx, {size_name} ptr [r10]\n"
    body += "  mov ebp, 1\n"
    body += f"  {mnemonic} {size_name} ptr [r10]\n"
    if width == _QWORD_WIDTH_BITS:
        body += "  mov r10, qword ptr [r10]\n"
    elif width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, dword ptr [r10]\n"
    else:
        body += f"  movzx r10d, {size_name} ptr [r10]\n"
    body += synth_flags_asm(width, "add" if mnemonic == "inc" else "sub", config.flag_variant)
    body += (
        f"  and r11, -2\n  mov rcx, qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        "  and ecx, 1\n  or r11, rcx\n"
        f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"
