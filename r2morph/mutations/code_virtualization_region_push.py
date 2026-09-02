"""Memory-backed stack decoding and emission for region virtualization."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_decoders import _INSTRUCTION_PART_COUNT, _parse_mem_operand
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _explicit_memory_width,
    _parse_indexed_operand,
    _parse_riprel_operand,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    _indexed_address_asm,
    _indexed_address_nobase_asm,
    _mem_address_asm,
)

_QWORD_WIDTH_BITS = 64
_WORD_WIDTH_BITS = 16
_STACK_MEMORY_WIDTHS = frozenset({_WORD_WIDTH_BITS, _QWORD_WIDTH_BITS})


def _push_memory_width(operand: str) -> int:
    width = _explicit_memory_width(operand)
    return _QWORD_WIDTH_BITS if width is None else width


def _decode_push_memory(text: str, insn_addr: int = 0, insn_size: int = 0) -> tuple[object, ...] | None:
    """Decode 16- or 64-bit ``push [memory]`` forms into a region item."""
    parts = text.split(None, 1)
    result: tuple[object, ...] | None = None
    if len(parts) == _INSTRUCTION_PART_COUNT and parts[0].lower() == "push":
        operand = parts[1].strip().lower()
        width = _push_memory_width(operand)
        if width in _STACK_MEMORY_WIDTHS:
            direct = _parse_mem_operand(operand)
            if direct is not None:
                base, displacement, width = direct
                if width in (None, *_STACK_MEMORY_WIDTHS):
                    result = ("pushmem", base, displacement, _push_memory_width(operand))
            if result is None:
                rip_relative = _parse_riprel_operand(operand, insn_addr, insn_size)
                if rip_relative is not None and rip_relative[1] in (None, *_STACK_MEMORY_WIDTHS):
                    result = ("pushmemrip", rip_relative[0], _push_memory_width(operand))
            if result is None:
                indexed = _parse_indexed_operand(operand, base_optional=True)
                if indexed is not None:
                    base, index, shift, displacement = indexed
                    result = (
                        ("pushmemidxnb", index, shift, displacement, _push_memory_width(operand))
                        if base < 0
                        else ("pushmemidx", base, index, shift, displacement, _push_memory_width(operand))
                    )
    return result


def _decode_pop_memory(text: str, insn_addr: int = 0, insn_size: int = 0) -> tuple[object, ...] | None:
    """Decode 16- or 64-bit ``pop [memory]`` forms into a region item."""
    decoded = _decode_push_memory(text.replace("pop", "push", 1), insn_addr, insn_size)
    if decoded is None:
        return None
    return ("pop" + str(decoded[0])[4:], *decoded[1:])


def _push_memory_handler_asm(
    handler_key: str,
    keys: tuple[str, str],
    field_perm: int,
    addr_variant: int,
    rsp_off: int,
) -> str:
    """Load a qword from memory and push it onto the relocated program stack."""
    key, key_dword = keys
    kind, width_text = handler_key.rsplit("_", 1)
    width = int(width_text)
    if width not in _STACK_MEMORY_WIDTHS:
        raise ValueError(f"unsupported push memory width: {width_text}")
    stack_bytes = width // 8
    if kind == "pushmemrip":
        body, advance = _mem_address_asm(True, key, key_dword, field_perm, addr_variant)
    elif kind == "pushmemidxnb":
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind == "pushmemidx":
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    load = "movzx rax, word ptr [r10]" if width == _WORD_WIDTH_BITS else "mov rax, qword ptr [r10]"
    store = "mov word ptr [r9], ax" if width == _WORD_WIDTH_BITS else "mov qword ptr [r9], rax"
    body += (
        f"  {load}\n"
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n"
        f"  sub r9, {stack_bytes}\n"
        f"  mov qword ptr [rsp+{rsp_off}], r9\n"
        f"  {store}\n"
        f"  add rsi, {advance}\n  jmp vm_dispatch\n"
    )
    return body


def _pop_memory_handler_asm(
    handler_key: str,
    keys: tuple[str, str],
    field_perm: int,
    addr_variant: int,
    rsp_off: int,
) -> str:
    """Read a stack value and store its declared width in memory."""
    key, key_dword = keys
    kind, width_text = handler_key.rsplit("_", 1)
    width = int(width_text)
    if width not in _STACK_MEMORY_WIDTHS:
        raise ValueError(f"unsupported pop memory width: {width_text}")
    stack_bytes = width // 8
    if kind == "popmemrip":
        body, advance = _mem_address_asm(True, key, key_dword, field_perm, addr_variant)
    elif kind == "popmemidxnb":
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind == "popmemidx":
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    load = "movzx rax, word ptr [r9]" if width == _WORD_WIDTH_BITS else "mov rax, qword ptr [r9]"
    store = "mov word ptr [r10], ax" if width == _WORD_WIDTH_BITS else "mov qword ptr [r10], rax"
    body += (
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n"
        f"  {load}\n"
        f"  add r9, {stack_bytes}\n"
        f"  mov qword ptr [rsp+{rsp_off}], r9\n"
        f"  {store}\n"
        f"  add rsi, {advance}\n  jmp vm_dispatch\n"
    )
    return body
