"""
Gadgets library for semantic-neutral code generation.

Provides categorized gadgets (instruction sequences) for generating
junk code that preserves program semantics.
"""

import random
from typing import Callable
from dataclasses import dataclass

from r2morph.analysis.register_tracker import (
    RegTracker,
    REG_64,
    REG_32,
    REG_16,
    REG_8H,
    REG_8L,
    REG_ALL,
)
from r2morph.analysis.os_flags import OSFlags


@dataclass
class GadgetCategory:
    name: str
    gadgets: dict[str, tuple[Callable, int, int]]
    description: str


class Gadgets:
    def __init__(self, os_type: str = "linux"):
        self.os_flags = OSFlags(os_type)
        self.reg_tracker = RegTracker()
        self._stack_depth: int = 0
        self._cnt_reg: str = ""
        self._in_loop: bool = False
        self._label_counter: int = 0
        self._os_type = os_type
        self._ensure_initialized()

    def get_asm_label(self) -> str:
        self._label_counter += 1
        return f"_junk_{self._label_counter}_{random.randint(0, 0xFFFF):04x}"

    def set_cnt_reg(self, reg: str) -> None:
        self._cnt_reg = reg

    @property
    def stack_depth(self) -> int:
        return self._stack_depth

    @stack_depth.setter
    def stack_depth(self, value: int) -> None:
        self._stack_depth = value

    def get_n_junk_ins(self, reg: str, sec_reg: str, n: int) -> str:
        gadget = ""
        gadget_keys, gadget_weights = self._get_subreg_gadgets(reg)

        for _ in range(n):
            tmp_gadget = ""
            attempts = 0
            while tmp_gadget == "" and attempts < 10:
                selected_key = random.choices(gadget_keys, weights=gadget_weights, k=1)[0]
                selected_func = self.operate_gadgets[selected_key][0]
                tmp_gadget = selected_func(reg, sec_reg)
                attempts += 1
            if tmp_gadget:
                gadget += tmp_gadget

        return gadget

    def _get_subreg_gadgets(self, reg: str) -> tuple[tuple[str, ...], list[int]]:
        from r2morph.analysis.register_tracker import REG_SIZES_MAP

        subreg_flags = REG_SIZES_MAP.get(reg, REG_ALL)

        gadget_keys = tuple(self.operate_gadgets.keys())
        gadget_weights = [self.operate_gadgets[k][2] for k in gadget_keys]
        gadget_flags = [self.operate_gadgets[k][1] for k in gadget_keys]

        updated_weights = [
            weight if (flags & subreg_flags) != 0 else 0 for weight, flags in zip(gadget_weights, gadget_flags)
        ]

        return gadget_keys, updated_weights

    stack_gadgets: dict[str, tuple[Callable, Callable, int]] = None

    def _init_stack_gadgets(self):
        self.stack_gadgets = {
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

    jump_gadgets: dict[str, tuple[Callable, int]] = None

    def _init_jump_gadgets(self):
        self.jump_gadgets = {
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

    operate_gadgets: dict[str, tuple[Callable, int, int]] = None

    def _init_operate_gadgets(self):
        self.operate_gadgets = {
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
                lambda reg, sec_reg: f"mov {reg}, [rsp + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
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
            "add_reg_reg": (
                lambda reg, sec_reg: f"add {reg}, {sec_reg}",
                REG_ALL,
                5,
            ),
            "add_reg_mem": (
                lambda reg, sec_reg: f"add {reg}, [rsp + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
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
                lambda reg, sec_reg: f"sub {reg}, [rsp + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
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
            "lea_reg_mem": (
                lambda reg, sec_reg: f"lea {reg}, [{sec_reg}]",
                REG_64 | REG_32,
                5,
            ),
            "lea_reg_rsp": (
                lambda reg, sec_reg: f"lea {reg}, [rsp + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
                REG_64 | REG_32,
                5,
            ),
            "lea_reg_rbp": (
                lambda reg, sec_reg: f"lea {reg}, [rbp - {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
                REG_64 | REG_32,
                5,
            ),
            "lea_reg_reg_sum": (
                lambda reg, sec_reg: f"lea {reg}, [{reg} + {sec_reg}]",
                REG_64 | REG_32,
                5,
            ),
            "lea_reg_rsp_reg": (
                lambda reg,
                sec_reg: f"lea {reg}, [rsp + {reg} + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
                REG_64,
                5,
            ),
            "lea_reg_rsp_secreg": (
                lambda reg,
                sec_reg: f"lea {reg}, [rsp + {sec_reg} + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
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
                lambda reg, sec_reg: f"xor {reg}, {self.os_flags.get_safe_imm32()}",
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
                lambda reg, sec_reg: f"and {reg}, {self.os_flags.get_safe_imm32()}",
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
                lambda reg, sec_reg: f"or {reg}, {self.os_flags.get_safe_imm32()}",
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

    branch_gadgets: dict[str, tuple[Callable, int, int]] = None

    def _init_branch_gadgets(self):
        self.branch_gadgets = {
            "check_alignment": (
                self._br_check_alignment,
                REG_ALL,
                10,
            ),
            "check_and_set_0": (
                self._br_check_and_set_0,
                REG_ALL,
                10,
            ),
            "check_regs": (
                self._br_check_regs,
                REG_ALL,
                10,
            ),
            "check_flags": (
                self._br_check_flags,
                REG_ALL,
                10,
            ),
        }

    loop_gadgets: dict[str, tuple[Callable, int, int]] = None

    def _init_loop_gadgets(self):
        self.loop_gadgets = {
            "loop_to_0": (
                self._lo_to_0,
                REG_ALL,
                10,
            ),
        }

    def _br_check_alignment(self, reg: str, sec_reg: str) -> str:
        label = self.get_asm_label()
        alignment = random.choice([0x1, 0x3, 0x7, 0xF, 0xFF, 0xFFF])
        mask = 0xFFFFFFFFFFFFFFFF ^ alignment
        choices = [
            f"{sec_reg}",
            f"[rsp + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
        ]
        gadget = ""
        gadget += f"mov {reg}, {random.choice(choices)};"
        gadget += f"test {reg}, {alignment};"
        gadget += f"jz {label};"
        gadget += f"and {reg}, {mask};"
        gadget += f"{label}:"
        return gadget

    def _br_check_and_set_0(self, reg: str, sec_reg: str) -> str:
        label = self.get_asm_label()
        choices = [
            f"{sec_reg}",
            f"[rsp + {random.randint(0, max(0, self._stack_depth - 1)) * 8}]",
        ]
        gadget = ""
        gadget += f"mov {reg}, {random.choice(choices)};"
        gadget += f"test {reg}, {reg};"
        gadget += f"jz {label};"
        gadget += f"xor {reg}, {reg};"
        gadget += f"{label}:"
        return gadget

    def _br_check_flags(self, reg: str, sec_reg: str) -> str:
        flag = random.choice(self.os_flags.flags)
        label = self.get_asm_label()
        gadget = ""
        if flag > 0x7FFFFFFF:
            sec_reg_tmp = self.reg_tracker.get_subregisters(sec_reg)
            if sec_reg_tmp and len(sec_reg_tmp) > 1:
                sec_reg_32 = sec_reg_tmp[1]
            else:
                sec_reg_32 = sec_reg
            gadget += f"mov {sec_reg}, {reg};"
            gadget += f"and {sec_reg_32}, {flag};"
        else:
            gadget += f"test {reg}, {flag};"
        gadget += f"jnz {label};"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1, 4))
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1, 2))
        return gadget

    def _br_check_regs(self, reg: str, sec_reg: str) -> str:
        label = self.get_asm_label()
        gadget_keys = tuple(self.jump_gadgets.keys())
        gadget_weights = [self.jump_gadgets[k][1] for k in gadget_keys]
        selected_key = random.choices(gadget_keys, weights=gadget_weights, k=1)[0]

        gadget = ""
        gadget += f"cmp {reg}, {sec_reg};"
        gadget += self.jump_gadgets[selected_key][0](label)
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1, 4))
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(0, 4))
        return gadget

    def _lo_to_0(self, reg: str, sec_reg: str) -> str:
        if (
            self._cnt_reg == ""
            or reg in self.reg_tracker.get_subregisters(self._cnt_reg)
            or sec_reg in self.reg_tracker.get_subregisters(self._cnt_reg)
        ):
            return ""

        gadget = ""
        label = self.get_asm_label()
        pushed_cnt = False
        set_in_loop = False

        if self._in_loop:
            gadget += f"push {self._cnt_reg};"
            pushed_cnt = True
        else:
            self._in_loop = True
            set_in_loop = True

        gadget += f"mov {self._cnt_reg}, {random.randint(0x3, 0x80)};"
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1, 6))
        gadget += f"dec {self._cnt_reg};"
        gadget += f"cmp {self._cnt_reg}, 0;"
        gadget += f"jne {label};"

        if pushed_cnt:
            gadget += f"pop {self._cnt_reg};"

        if set_in_loop:
            self._in_loop = False

        return gadget

    def _ensure_initialized(self):
        """Initialize gadget tables if not yet done."""
        if not hasattr(self, "_initialized"):
            self._init_stack_gadgets()
            self._init_jump_gadgets()
            self._init_operate_gadgets()
            self._init_branch_gadgets()
            self._init_loop_gadgets()
            self._initialized = True


def create_gadgets(os_type: str = "linux") -> Gadgets:
    gadgets = Gadgets(os_type)
    gadgets._init_stack_gadgets()
    gadgets._init_jump_gadgets()
    gadgets._init_operate_gadgets()
    gadgets._init_branch_gadgets()
    gadgets._init_loop_gadgets()
    return gadgets
