"""Static gadget catalogs for junk code generation."""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from r2morph.analysis.os_flags import OSFlags
from r2morph.analysis.register_tracker import REG_16, REG_32, REG_64, REG_ALL


@dataclass
class GadgetCategory:
    name: str
    gadgets: dict[str, tuple[Callable, int, int]]
    description: str


def build_stack_gadgets() -> dict[str, tuple[Callable, Callable, int]]:
    return {
        "push_reg": (
            lambda reg: f"push {reg}",
            lambda reg: f"pop {reg}",
            1,
        ),
        "sub_mov": (
            lambda reg: f"sub rsp, 8; mov [rsp], {reg}",
            lambda reg: f"mov {reg}, [rsp]; add rsp, 8",
            1,
        ),
    }


def build_jump_gadgets() -> dict[str, tuple[Callable, int]]:
    return {
        "jz": (lambda lbl: f"jz {lbl}", 1),
        "jnz": (lambda lbl: f"jnz {lbl}", 1),
        "jg": (lambda lbl: f"jg {lbl}", 1),
        "jge": (lambda lbl: f"jge {lbl}", 1),
        "jl": (lambda lbl: f"jl {lbl}", 1),
        "jle": (lambda lbl: f"jle {lbl}", 1),
        "ja": (lambda lbl: f"ja {lbl}", 1),
        "jae": (lambda lbl: f"jae {lbl}", 1),
        "jb": (lambda lbl: f"jb {lbl}", 1),
        "jbe": (lambda lbl: f"jbe {lbl}", 1),
    }


def build_operate_gadgets(os_flags: OSFlags, stack_depth: int) -> dict[str, tuple[Callable, int, int]]:
    return {
        **_mov_gadgets(stack_depth),
        **_arithmetic_gadgets(stack_depth),
        **_lea_gadgets(stack_depth),
        **_bitwise_gadgets(os_flags),
    }


def _mov_gadgets(stack_depth: int) -> dict[str, tuple]:
    return {
        "mov_reg_reg": (
            lambda reg, sec_reg: f"mov {reg}, {sec_reg}",
            REG_ALL,
            30,
        ),
        "mov_reg_rsp": (
            lambda reg, sec_reg: f"mov {reg}, rsp",
            REG_64,
            30,
        ),
        "mov_reg_mem_rsp": (
            lambda reg, sec_reg: f"mov {reg}, [rsp + {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_ALL,
            30,
        ),
        "mov_reg_imm32": (
            lambda reg, sec_reg: f"mov {reg}, {random.randint(0, 0xFFFFFFFF)}",
            REG_64 | REG_32,
            5,
        ),
        "mov_reg_imm16": (
            lambda reg, sec_reg: f"mov {reg}, {random.randint(0, 0xFFFF)}",
            REG_64 | REG_32 | REG_16,
            15,
        ),
        "mov_reg_imm8": (
            lambda reg, sec_reg: f"mov {reg}, {random.randint(0, 0xFF)}",
            REG_ALL,
            20,
        ),
    }


def _arithmetic_gadgets(stack_depth: int) -> dict[str, tuple]:
    return {
        "add_reg_reg": (
            lambda reg, sec_reg: f"add {reg}, {sec_reg}",
            REG_ALL,
            5,
        ),
        "add_reg_mem": (
            lambda reg, sec_reg: f"add {reg}, [rsp + {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_ALL,
            10,
        ),
        "add_reg_imm": (
            lambda reg, sec_reg: f"add {reg}, {random.randint(-0x80000000, 0x7FFFFFFF)}",
            REG_ALL,
            5,
        ),
        "sub_reg_reg": (
            lambda reg, sec_reg: f"sub {reg}, {sec_reg}",
            REG_ALL,
            5,
        ),
        "sub_reg_mem": (
            lambda reg, sec_reg: f"sub {reg}, [rsp + {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_ALL,
            10,
        ),
        "sub_reg_imm": (
            lambda reg, sec_reg: f"sub {reg}, {random.randint(-0x80000000, 0x7FFFFFFF)}",
            REG_ALL,
            5,
        ),
        "inc_reg": (
            lambda reg, sec_reg: f"inc {reg}",
            REG_ALL,
            5,
        ),
        "dec_reg": (
            lambda reg, sec_reg: f"dec {reg}",
            REG_ALL,
            5,
        ),
    }


def _lea_gadgets(stack_depth: int) -> dict[str, tuple]:
    return {
        "lea_reg_mem": (
            lambda reg, sec_reg: f"lea {reg}, [{sec_reg}]",
            REG_64 | REG_32,
            5,
        ),
        "lea_reg_rsp": (
            lambda reg, sec_reg: f"lea {reg}, [rsp + {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_64 | REG_32,
            5,
        ),
        "lea_reg_rbp": (
            lambda reg, sec_reg: f"lea {reg}, [rbp - {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_64 | REG_32,
            5,
        ),
        "lea_reg_reg_sum": (
            lambda reg, sec_reg: f"lea {reg}, [{reg} + {sec_reg}]",
            REG_64 | REG_32,
            5,
        ),
        "lea_reg_rsp_reg": (
            lambda reg, sec_reg: f"lea {reg}, [rsp + {reg} + {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_64,
            5,
        ),
        "lea_reg_rsp_secreg": (
            lambda reg, sec_reg: f"lea {reg}, [rsp + {sec_reg} + {random.randint(0, max(0, stack_depth - 1)) * 8}]",
            REG_64,
            5,
        ),
        "lea_reg_plus_8": (
            lambda reg, sec_reg: f"lea {reg}, [{reg} + 8]",
            REG_64 | REG_32,
            5,
        ),
        "lea_secreg_plus_8": (
            lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + 8]",
            REG_64 | REG_32,
            5,
        ),
        "lea_reg_reg_imm": (
            lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + {random.randrange(2, 0x101, 2)}]",
            REG_64 | REG_32,
            5,
        ),
        "lea_reg_reg_mul2": (
            lambda reg, sec_reg: f"lea {reg}, [{reg} + {reg}*2]",
            REG_64 | REG_32,
            10,
        ),
        "lea_secreg_secreg_mul2": (
            lambda reg, sec_reg: f"lea {reg}, [{sec_reg} + {sec_reg}*2]",
            REG_64 | REG_32,
            10,
        ),
        "lea_reg_secreg_mul4": (
            lambda reg, sec_reg: f"lea {reg}, [{reg} + {sec_reg}*4]",
            REG_64 | REG_32,
            5,
        ),
    }


def _bitwise_gadgets(os_flags: OSFlags) -> dict[str, tuple]:
    return {
        "nop": (
            lambda reg, sec_reg: "nop",
            REG_ALL,
            1,
        ),
        "xor_reg_reg": (
            lambda reg, sec_reg: f"xor {reg}, {reg}",
            REG_ALL,
            5,
        ),
        "xor_reg_sec": (
            lambda reg, sec_reg: f"xor {reg}, {sec_reg}",
            REG_ALL,
            5,
        ),
        "xor_reg_imm": (
            lambda reg, sec_reg: f"xor {reg}, {os_flags.get_safe_imm32()}",
            REG_ALL,
            5,
        ),
        "and_reg_0": (
            lambda reg, sec_reg: f"and {reg}, 0",
            REG_ALL,
            5,
        ),
        "and_reg_sec": (
            lambda reg, sec_reg: f"and {reg}, {sec_reg}",
            REG_ALL,
            5,
        ),
        "and_reg_imm": (
            lambda reg, sec_reg: f"and {reg}, {os_flags.get_safe_imm32()}",
            REG_ALL,
            5,
        ),
        "or_reg_0xff": (
            lambda reg, sec_reg: f"or {reg}, 0xFFFFFFFFFFFFFFFF",
            REG_ALL,
            5,
        ),
        "or_reg_sec": (
            lambda reg, sec_reg: f"or {reg}, {sec_reg}",
            REG_ALL,
            5,
        ),
        "or_reg_imm": (
            lambda reg, sec_reg: f"or {reg}, {os_flags.get_safe_imm32()}",
            REG_ALL,
            5,
        ),
        "rol_reg_1": (lambda reg, sec_reg: f"rol {reg}, 1", REG_ALL, 3),
        "rol_reg_2": (lambda reg, sec_reg: f"rol {reg}, 2", REG_ALL, 3),
        "rol_reg_4": (lambda reg, sec_reg: f"rol {reg}, 4", REG_ALL, 3),
        "rol_reg_8": (lambda reg, sec_reg: f"rol {reg}, 8", REG_64 | REG_32 | REG_16, 3),
        "sar_reg_1": (lambda reg, sec_reg: f"sar {reg}, 1", REG_ALL, 3),
        "sar_reg_2": (lambda reg, sec_reg: f"sar {reg}, 2", REG_ALL, 3),
        "sar_reg_4": (lambda reg, sec_reg: f"sar {reg}, 4", REG_ALL, 3),
        "sar_reg_8": (lambda reg, sec_reg: f"sar {reg}, 8", REG_64 | REG_32 | REG_16, 3),
        "shr_reg_1": (lambda reg, sec_reg: f"shr {reg}, 1", REG_ALL, 5),
        "shr_reg_2": (lambda reg, sec_reg: f"shr {reg}, 2", REG_ALL, 5),
        "shr_reg_4": (lambda reg, sec_reg: f"shr {reg}, 4", REG_ALL, 5),
        "shr_reg_8": (lambda reg, sec_reg: f"shr {reg}, 8", REG_64 | REG_32 | REG_16, 5),
        "shl_reg_1": (lambda reg, sec_reg: f"shl {reg}, 1", REG_ALL, 5),
        "shl_reg_2": (lambda reg, sec_reg: f"shl {reg}, 2", REG_ALL, 5),
        "shl_reg_4": (lambda reg, sec_reg: f"shl {reg}, 4", REG_ALL, 5),
        "shl_reg_8": (lambda reg, sec_reg: f"shl {reg}, 8", REG_64 | REG_32 | REG_16, 5),
    }
