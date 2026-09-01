"""VEX packed FMA decoding and handlers for the region VM."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_layout import triple_offsets
from r2morph.mutations.code_virtualization_region_decoders import _parse_mem_operand
from r2morph.mutations.code_virtualization_region_fp_decoders import _parse_xmm_operand, _parse_ymm_operand
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    _YMM_UPPER_SAVE_OFFSET,
    VexMemoryHandlerConfig,
    _store_ymm_to_frame,
)
from r2morph.mutations.code_virtualization_region_handlers import _XMM_SAVE_OFFSET
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _parse_indexed_operand,
    _parse_riprel_operand,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    _indexed_address_asm,
    _indexed_address_nobase_asm,
    _mem_address_asm,
)

_FMA_FORMS = ("132", "213", "231")
_FMA_ROOTS = ("vfmadd", "vfmsub", "vfnmadd", "vfnmsub")
_FMA_SUFFIXES = ("ps", "pd")
_FMA_OPERAND_COUNT = 3
_INSTRUCTION_PART_COUNT = 2
_FP_VEX_FMA_MNEMONICS = frozenset(
    f"{root}{form}{suffix}" for root in _FMA_ROOTS for form in _FMA_FORMS for suffix in _FMA_SUFFIXES
)
FmaMemoryItem = (
    tuple[str, str, int, int, int, int]
    | tuple[str, str, int, int, int]
    | tuple[str, str, int, int, int, int, int, int]
    | tuple[str, str, int, int, int, int, int]
)


def _parse_fma_registers(text: str) -> tuple[int, int, int, bool] | None:
    operands = [operand.strip() for operand in text.split(",")]
    if len(operands) != _FMA_OPERAND_COUNT:
        return None
    is_ymm = operands[0].lower().startswith("ymm")
    parser = _parse_ymm_operand if is_ymm else _parse_xmm_operand
    registers = tuple(parser(operand) for operand in operands)
    destination, first_source, second_source = registers
    if destination is None or first_source is None or second_source is None:
        return None
    return destination, first_source, second_source, is_ymm


def _decode_fp_vex_fma(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode register-only packed VEX FMA while preserving operand order."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() not in _FP_VEX_FMA_MNEMONICS:
        return None
    mnemonic = parts[0].lower()
    parsed = _parse_fma_registers(parts[1])
    if parsed is None:
        return None
    destination, first_source, second_source, is_ymm = parsed
    kind = "fppackedvex256" if is_ymm else "fppackedvex"
    return kind, mnemonic, destination, first_source, second_source


def _decode_fp_vex_fma_memory(text: str, insn_addr: int, insn_size: int, is_ymm: bool) -> FmaMemoryItem | None:
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_VEX_FMA_MNEMONICS:
        return None
    operands = [operand.strip() for operand in parts[1].split(",")]
    if len(operands) != _FMA_OPERAND_COUNT or "[" not in operands[-1]:
        return None
    parser = _parse_ymm_operand if is_ymm else _parse_xmm_operand
    destination = parser(operands[0])
    first_source = parser(operands[1])
    if destination is None or first_source is None:
        return None
    memory = operands[2].lower().replace("ymmword", "").replace("xmmword", "")
    kind_prefix = "fppackedvex256mem" if is_ymm else "fppackedvexmem"
    indexed = _parse_indexed_operand(memory, base_optional=True)
    result: FmaMemoryItem | None = None
    if indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        if base_slot < 0:
            result = (
                f"{kind_prefix}idxnb",
                mnemonic,
                destination,
                first_source,
                index_slot,
                shift,
                displacement,
            )
        else:
            result = (
                f"{kind_prefix}idx",
                mnemonic,
                destination,
                first_source,
                base_slot,
                index_slot,
                shift,
                displacement,
            )
    else:
        rip_relative = _parse_riprel_operand(memory, insn_addr, insn_size)
        if rip_relative is not None:
            result = f"{kind_prefix}rip", mnemonic, destination, first_source, rip_relative[0]
        else:
            parsed_memory = _parse_mem_operand(memory)
            if parsed_memory is not None:
                base_slot, displacement, _width = parsed_memory
                result = f"{kind_prefix}", mnemonic, destination, first_source, base_slot, displacement
    return result


def _decode_fp_vex_fma_mem(text: str, insn_addr: int, insn_size: int) -> FmaMemoryItem | None:
    return _decode_fp_vex_fma_memory(text, insn_addr, insn_size, False)


def _decode_fp_vex_256_fma_mem(text: str, insn_addr: int, insn_size: int) -> FmaMemoryItem | None:
    return _decode_fp_vex_fma_memory(text, insn_addr, insn_size, True)


def _load_fma_ymm_from_frame(offset: str, register: int) -> str:
    """Load a YMM operand without aliasing the physical third operand register."""
    return (
        f"  movups xmm{register}, [rsp + {offset} + {_XMM_SAVE_OFFSET}]\n"
        f"  movups xmm15, [rsp + {offset} + {_YMM_UPPER_SAVE_OFFSET}]\n"
        f"  vinsertf128 ymm{register}, ymm{register}, xmm15, 1\n"
    )


def is_fp_vex_fma_handler_key(key: str) -> bool:
    """Return whether a handler key names one of the supported packed FMAs."""
    parts = key.split("_", 1)
    return (
        len(parts) == _INSTRUCTION_PART_COUNT
        and parts[1] in _FP_VEX_FMA_MNEMONICS
        and parts[0]
        in {
            "fppackedvex",
            "fppackedvex256",
            "fppackedvexmem",
            "fppackedvexmemrip",
            "fppackedvexmemidx",
            "fppackedvexmemidxnb",
            "fppackedvex256mem",
            "fppackedvex256memrip",
            "fppackedvex256memidx",
            "fppackedvex256memidxnb",
        }
    )


def _fp_vex_fma_handler_asm(
    handler_key: str,
    key: str,
    field_perm: int = 0,
    preserve_ymm: bool = False,
) -> str:
    """Run a register-only packed FMA with the native operand ordering."""
    kind, instruction = handler_key.split("_", 1)
    offsets = triple_offsets("dst", "src1", "src2", field_perm)
    body = "".join(
        f"  movzx r{register}d, byte ptr [rsi+{offsets[name]}]\n"
        f"  xor r{register}b, {key}\n"
        f"  xor r{register}b, r13b\n"
        f"  shl r{register}, 4\n"
        for register, name in ((8, "dst"), (9, "src1"), (10, "src2"))
    )
    if kind == "fppackedvex256":
        body += _load_fma_ymm_from_frame("r8", 0)
        body += _load_fma_ymm_from_frame("r9", 1)
        body += _load_fma_ymm_from_frame("r10", 2)
        body += f"  {instruction} ymm0, ymm1, ymm2\n"
        body += _store_ymm_to_frame("r8")
    else:
        body += (
            f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
            f"  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
            f"  movups xmm2, [rsp + r10 + {_XMM_SAVE_OFFSET}]\n"
            f"  {instruction} xmm0, xmm1, xmm2\n"
            f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        )
        if preserve_ymm:
            body += f"  pxor xmm2, xmm2\n  movups [rsp + r8 + {_YMM_UPPER_SAVE_OFFSET}], xmm2\n"
    return body + "  add rsi, 4\n  jmp vm_dispatch\n"


def _fp_vex_fma_memory_handler_asm(handler_key: str, key: str, key_dword: str, config: VexMemoryHandlerConfig) -> str:
    """Run a packed FMA whose third source is the addressed memory operand."""
    kind, instruction = handler_key.split("_", 1)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, config.field_perm, config.addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, config.field_perm, config.addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, config.field_perm, config.addr_variant)
    body += f"  movzx r11d, byte ptr [rsi+{advance}]\n  xor r11b, {key}\n  xor r11b, r13b\n  shl r11, 4\n"
    if kind.startswith("fppackedvex256"):
        body += _load_fma_ymm_from_frame("r8", 0)
        body += _load_fma_ymm_from_frame("r11", 1)
        body += f"  {instruction} ymm0, ymm1, ymmword ptr [r10]\n"
        body += _store_ymm_to_frame("r8")
    else:
        body += (
            f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
            f"  movups xmm1, [rsp + r11 + {_XMM_SAVE_OFFSET}]\n"
            f"  {instruction} xmm0, xmm1, xmmword ptr [r10]\n"
            f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        )
        if config.preserve_ymm:
            body += f"  pxor xmm2, xmm2\n  movups [rsp + r8 + {_YMM_UPPER_SAVE_OFFSET}], xmm2\n"
    return body + f"  add rsi, {advance + 1}\n  jmp vm_dispatch\n"
