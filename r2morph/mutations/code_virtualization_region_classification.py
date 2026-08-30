"""Native-instruction classification for region virtualization."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    decode_instruction,
)
from r2morph.mutations.code_virtualization_region_decoders import (
    _decode_cmov,
    _decode_imul,
    _decode_imul3,
    _decode_leave,
    _decode_mov_from_rsp,
    _decode_mov_to_rsp,
    _decode_pop,
    _decode_push,
    _decode_rsp_arith,
    _decode_setcc,
    _decode_shift,
    _decode_shift_reg,
    _decode_two_operand,
    _parse_mem_operand,
)
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_arith,
    _decode_fp_arith_idx,
    _decode_fp_arith_mem,
    _decode_fp_arith_riprel,
    _decode_fp_compare,
    _decode_fp_compare_idx,
    _decode_fp_compare_mem,
    _decode_fp_convert,
    _decode_fp_indexed,
    _decode_fp_mem,
    _decode_fp_movd,
    _decode_fp_move,
    _decode_fp_packed_arith,
    _decode_fp_packed_arith_idx,
    _decode_fp_packed_arith_mem,
    _decode_fp_packed_arith_riprel,
    _decode_fp_packed_immediate,
    _decode_fp_packed_indexed,
    _decode_fp_packed_mem,
    _decode_fp_packed_riprel,
    _decode_fp_riprel,
    _decode_fp_vex_256_packed_arith,
    _decode_fp_vex_256_packed_arith_mem,
    _decode_fp_vex_256_packed_mem,
    _decode_fp_vex_256_packed_move,
    _decode_fp_vex_gp_move,
    _decode_fp_vex_packed_arith,
    _decode_fp_vex_packed_arith_mem,
    _decode_fp_vex_packed_immediate,
    _decode_fp_vex_packed_move,
    _decode_fp_vex_scalar_arith,
    _decode_fp_vex_scalar_arith_mem,
    _decode_fp_vex_scalar_move,
)
from r2morph.mutations.code_virtualization_region_fp_extra_decoders import _decode_fp_vex_extra
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _decode_bswap,
    _decode_bt,
    _decode_cmp_mem,
    _decode_cmpxchg_memory,
    _decode_cqo,
    _decode_div,
    _decode_incdec,
    _decode_lea,
    _decode_lea_indexed,
    _decode_locked_memory_rmw,
    _decode_memory_immediate,
    _decode_memory_mov,
    _decode_memory_mov_indexed,
    _decode_movx,
    _decode_not,
    _decode_op_mem,
    _decode_op_mem_indexed,
    _decode_op_memdst,
    _decode_riprel_mov,
    _decode_tls_memory_mov,
    _decode_xchg_memory,
    _parse_indexed_operand,
    _parse_riprel_operand,
)

_DIRECT_REGISTER_CALL_PART_COUNT = 2
_MAX_RET_CLEANUP = 0xFFFF


def _decode_ret_cleanup(text: str) -> int | None:
    """Return the immediate stack cleanup encoded by ret, if valid."""
    parts = text.strip().lower().split()
    if not parts or parts[0] not in ("ret", "retn"):
        return None
    if len(parts) == 1:
        return 0
    if len(parts) != _DIRECT_REGISTER_CALL_PART_COUNT:
        return None
    try:
        cleanup = int(parts[1], 0)
    except ValueError:
        return None
    return cleanup if 0 <= cleanup <= _MAX_RET_CLEANUP else None


# r2 branch mnemonic -> the native conditional jump the interpreter emits.
_CONDITION: dict[str, str] = {
    "je": "je",
    "jz": "je",
    "jne": "jne",
    "jnz": "jne",
    "jl": "jl",
    "jnge": "jl",
    "jge": "jge",
    "jnl": "jge",
    "jg": "jg",
    "jnle": "jg",
    "jle": "jle",
    "jng": "jle",
    "jb": "jb",
    "jc": "jb",
    "jnae": "jb",
    "jae": "jae",
    "jnc": "jae",
    "jnb": "jae",
    "jbe": "jbe",
    "jna": "jbe",
    "ja": "ja",
    "jnbe": "ja",
    "js": "js",
    "jns": "jns",
    "jo": "jo",
    "jno": "jno",
    "jp": "jp",
    "jpe": "jp",
    "jnp": "jnp",
    "jpo": "jnp",
}

# r2 instruction types for a register/memory-indirect jump (jmp reg / jmp [mem]) -
# the defining dispatch instruction of a computed-goto interpreter.
_COMPUTED_JUMP_TYPES = ("ujmp", "rjmp", "ijmp", "mjmp", "irjmp")


def _first_item(decoders: Iterable[Callable[[], Any]], prefix: tuple[Any, ...] = ()) -> list[Any] | None:
    for decoder in decoders:
        decoded = decoder()
        if decoded is not None:
            return [*prefix, *decoded]
    return None


def _classify_vector(text: str, address: int, size: int) -> list[Any] | None:
    return _first_item(
        (
            lambda: _decode_fp_vex_extra(text),
            lambda: _decode_fp_vex_scalar_move(text, address, size),
            lambda: _decode_fp_vex_gp_move(text),
            lambda: _decode_fp_vex_scalar_arith(text),
            lambda: _decode_fp_vex_scalar_arith_mem(text, address, size),
            lambda: _decode_fp_vex_packed_immediate(text),
            lambda: _decode_fp_vex_packed_arith_mem(text, address, size),
            lambda: _decode_fp_vex_256_packed_arith(text),
            lambda: _decode_fp_vex_256_packed_arith_mem(text, address, size),
            lambda: _decode_fp_vex_256_packed_move(text),
            lambda: _decode_fp_vex_256_packed_mem(text, address, size),
            lambda: _decode_fp_mem(text),
            lambda: _decode_fp_indexed(text),
            lambda: _decode_fp_riprel(text, address, size),
            lambda: _decode_fp_arith(text),
            lambda: _decode_fp_arith_mem(text),
            lambda: _decode_fp_arith_riprel(text, address, size),
            lambda: _decode_fp_arith_idx(text),
            lambda: _decode_fp_compare_mem(text),
            lambda: _decode_fp_compare_idx(text),
            lambda: _decode_fp_compare(text),
            lambda: _decode_fp_movd(text),
            lambda: _decode_fp_move(text),
            lambda: _decode_fp_vex_packed_arith(text),
            lambda: _decode_fp_vex_packed_move(text),
            lambda: _decode_fp_packed_arith(text),
            lambda: _decode_fp_packed_immediate(text),
            lambda: _decode_fp_packed_arith_mem(text),
            lambda: _decode_fp_packed_arith_riprel(text, address, size),
            lambda: _decode_fp_packed_arith_idx(text),
            lambda: _decode_fp_packed_mem(text),
            lambda: _decode_fp_packed_indexed(text),
            lambda: _decode_fp_packed_riprel(text, address, size),
        )
    )


def _classify_binary(kind: str, text: str, address: int, size: int) -> list[Any] | None:
    op = decode_instruction(text)
    if op is not None:
        return ["op", op]
    if kind in ("add", "sub"):
        rsp_arith = _decode_rsp_arith(text)
        if rsp_arith is not None:
            return [*rsp_arith]
    if kind == "mov":
        return _first_item(
            (
                lambda: _decode_tls_memory_mov(text),
                lambda: _decode_mov_from_rsp(text),
                lambda: _decode_mov_to_rsp(text),
                lambda: _decode_memory_immediate(text, address, size),
                lambda: _decode_memory_mov(text),
                lambda: _decode_memory_mov_indexed(text),
                lambda: _decode_riprel_mov(text, address, size),
                lambda: _decode_movx(text),
            )
        )
    return _first_item(
        (
            lambda: _decode_incdec(text),
            lambda: _decode_op_mem(text, kind, address, size),
            lambda: _decode_op_memdst(text, kind, address, size),
            lambda: _decode_op_mem_indexed(text, kind),
        )
    )


def _classify_compare(text: str, address: int, size: int) -> list[Any] | None:
    compare = _decode_two_operand(text, "cmp")
    if compare is not None:
        return ["cmp", *compare]
    return _first_item((lambda: _decode_bt(text), lambda: _decode_cmp_mem(text, address, size)))


def _classify_shift(text: str) -> list[Any] | None:
    shift = _decode_shift(text)
    return ["shift", *shift] if shift is not None else _first_item((lambda: _decode_shift_reg(text),))


def _classify_mul(text: str) -> list[Any] | None:
    imul = _decode_imul(text)
    return ["imul", *imul] if imul is not None else _first_item((lambda: _decode_imul3(text),), ("imul3",))


def _classify_simple(kind: str, text: str, address: int, size: int) -> list[Any] | None:
    classifiers: dict[str, Callable[[], list[Any] | None]] = {
        "cmp": lambda: _classify_compare(text, address, size),
        "acmp": lambda: _first_item((lambda: _decode_two_operand(text, "test"),), ("test",)),
        "shl": lambda: _classify_shift(text),
        "shr": lambda: _classify_shift(text),
        "sar": lambda: _classify_shift(text),
        "rol": lambda: _classify_shift(text),
        "ror": lambda: _classify_shift(text),
        "rcl": lambda: _classify_shift(text),
        "rcr": lambda: _classify_shift(text),
        "mul": lambda: _classify_mul(text),
        "not": lambda: _first_item((lambda: _decode_not(text),)),
        "div": lambda: _first_item((lambda: _decode_div(text),)),
        "lea": lambda: _first_item((lambda: _decode_lea(text, address, size), lambda: _decode_lea_indexed(text))),
        "cmov": lambda: _first_item((lambda: _decode_setcc(text), lambda: _decode_cmov(text))),
    }
    classifier = classifiers.get(kind)
    return classifier() if classifier is not None else None


def _classify_stack(kind: str, text: str, allow_computed_jump: bool) -> list[Any] | None:
    mnemonic = text.partition(" ")[0].lower()
    if allow_computed_jump and mnemonic in ("pushfq", "pushfd", "pushf"):
        return ["fsave"]
    if allow_computed_jump and mnemonic in ("popfq", "popfd", "popf"):
        return ["frestore"]
    if kind in ("push", "upush", "rpush"):
        return _first_item((lambda: _decode_push(text),))
    if kind in ("pop", "rpop"):
        return _first_item((lambda: _decode_leave(text), lambda: _decode_pop(text)))
    return None


def _classify_call(kind: str, text: str, insn: dict[str, Any]) -> list[Any] | None:
    result: list[Any] | None = None
    if kind == "call":
        target = insn.get("jump", -1)
        if isinstance(target, int) and target > 0:
            result = ["call", target]
    elif kind == "rcall":
        parts = text.split()
        if len(parts) == _DIRECT_REGISTER_CALL_PART_COUNT and parts[1] in GP_REGISTERS and parts[1] != "rsp":
            result = ["icall", GP_REGISTERS.index(parts[1])]
    elif kind == "ircall":
        operand = text.split(None, 1)[1] if " " in text else ""
        memory = _parse_mem_operand(operand)
        rip_relative = _parse_riprel_operand(operand, insn.get("addr", 0), insn.get("size", 0))
        if memory is not None:
            base_slot, displacement, _width = memory
            result = ["callmem", base_slot, displacement]
        elif rip_relative is not None:
            result = ["callmemrip", rip_relative[0]]
    elif kind == "ucall":
        operand = text.split(None, 1)[1] if " " in text else ""
        indexed = _parse_indexed_operand(operand, base_optional=True)
        if indexed is not None:
            base_slot, index_slot, scale_shift, displacement = indexed
            result = (
                ["callmemidxnb", index_slot, scale_shift, displacement]
                if base_slot < 0
                else ["callmemidx", base_slot, index_slot, scale_shift, displacement]
            )
    return result


def _classify_jump(kind: str, text: str, insn: dict[str, Any], allow_computed_jump: bool) -> list[Any] | None:
    result: list[Any] | None = None
    if kind == "jmp":
        result = ["jmp", insn.get("jump", -1)]
    elif allow_computed_jump and kind in _COMPUTED_JUMP_TYPES:
        parts = text.split()
        if len(parts) == _DIRECT_REGISTER_CALL_PART_COUNT and parts[1] in GP_REGISTERS and parts[1] != "rsp":
            result = ["ijmp", GP_REGISTERS.index(parts[1])]
        else:
            operand = text.split(None, 1)[1] if " " in text else ""
            indexed = _parse_indexed_operand(operand, base_optional=True)
            if indexed is not None:
                base_slot, index_slot, scale_shift, displacement = indexed
                result = (
                    ["ijmpmemnb", index_slot, scale_shift, displacement]
                    if base_slot < 0
                    else ["ijmpmem", base_slot, index_slot, scale_shift, displacement]
                )
    elif kind == "cjmp":
        condition = _CONDITION.get(text.split(None, 1)[0].lower())
        if condition is not None:
            result = ["jcc", condition, insn.get("jump", -1)]
    return result


def _classify(insn: dict[str, Any], allow_computed_jump: bool = False) -> list[Any] | None:
    """Build the VM item for one body instruction, or ``None`` if unsupported.

    ``allow_computed_jump`` opts in to lowering a register-indirect jump to an
    ``ijmp`` item. It is off by default so the straight-line region contract keeps
    rejecting computed jumps; only the dispatch-region contract enables it.
    """
    kind = insn.get("type", "")
    text = insn.get("opcode", "")
    if kind == "syscall":
        return ["syscall"]
    if text.strip().lower() == "vzeroupper":
        return ["vzeroupper"]
    if text.strip().lower() == "vzeroall":
        return ["vzeroall"]
    address = insn.get("addr", 0)
    size = insn.get("size", 0)
    result = _first_item(
        (
            lambda: _decode_fp_convert(text),
            lambda: _decode_fp_compare(text),
            lambda: _decode_cmpxchg_memory(text),
            lambda: _decode_locked_memory_rmw(text, address, size),
            lambda: _decode_xchg_memory(text),
            lambda: _decode_bswap(text),
            lambda: _decode_cqo(text),
        )
    )
    opcode_lower = text.lower()
    has_vector_operand = any(register in opcode_lower for register in ("xmm", "ymm", "zmm"))
    if result is None and (insn.get("family") == "vec" or has_vector_operand):
        result = _classify_vector(text, address, size)
    elif result is None and kind == "nop":
        result = ["nop"]
    elif result is None and kind in ("mov", "add", "sub", "xor", "and", "or"):
        result = _classify_binary(kind, text, address, size)
    elif result is None:
        result = _classify_simple(kind, text, address, size)
    if result is None:
        result = _classify_stack(kind, text, allow_computed_jump)
    if result is None and kind in ("call", "rcall", "ircall", "ucall"):
        result = _classify_call(kind, text, insn)
    if result is None:
        result = _classify_jump(kind, text, insn, allow_computed_jump)
    return result


# Logical context slots of the division-implicit registers: the dividend/quotient
# lives in rax and the high dividend/remainder in rdx.
