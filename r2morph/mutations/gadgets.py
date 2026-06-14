"""
Gadgets library for semantic-neutral code generation.

Provides categorized gadgets (instruction sequences) for generating
junk code that preserves program semantics.
"""

import random
from collections.abc import Callable

from r2morph.analysis.os_flags import OSFlags
from r2morph.analysis.register_tracker import REG_ALL, RegTracker
from r2morph.mutations.gadgets_catalogs import build_jump_gadgets, build_operate_gadgets, build_stack_gadgets


class Gadgets:
    def __init__(self, os_type: str = "linux"):
        self.os_flags = OSFlags(os_type)
        self.reg_tracker = RegTracker()
        self._stack_depth: int = 0
        self._cnt_reg: str = ""
        self._in_loop: bool = False
        self._label_counter: int = 0
        self._os_type = os_type
        self.stack_gadgets: dict[str, tuple[Callable, Callable, int]] = {}
        self.jump_gadgets: dict[str, tuple[Callable, int]] = {}
        self.operate_gadgets: dict[str, tuple[Callable, int, int]] = {}
        self.branch_gadgets: dict[str, tuple[Callable, int, int]] = {}
        self.loop_gadgets: dict[str, tuple[Callable, int, int]] = {}
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

    def _init_stack_gadgets(self) -> None:
        self.stack_gadgets = build_stack_gadgets()

    def _init_jump_gadgets(self) -> None:
        self.jump_gadgets = build_jump_gadgets()

    def _init_operate_gadgets(self) -> None:
        self.operate_gadgets = build_operate_gadgets(self.os_flags, self._stack_depth)

    def _init_branch_gadgets(self) -> None:
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

    def _init_loop_gadgets(self) -> None:
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
        gadget += str(self.jump_gadgets[selected_key][0](label))
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(1, 4))
        gadget += f"{label}:"
        gadget += self.get_n_junk_ins(reg, sec_reg, random.randint(0, 4))
        return gadget

    def _lo_to_0(self, reg: str, sec_reg: str) -> str:
        cnt_subregs = self.reg_tracker.get_subregisters(self._cnt_reg) or ()
        if self._cnt_reg == "" or reg in cnt_subregs or sec_reg in cnt_subregs:
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

    def _ensure_initialized(self) -> None:
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
