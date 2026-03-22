"""
Junk code generator for semantic-preserving mutations.

Generates semantically neutral junk code using Keystone assembler
and the gadgets library.
"""

import random
from typing import Optional
from dataclasses import dataclass

from r2morph.analysis.register_tracker import RegTracker, REG_SIZES_MAP, REG_64, REG_32, REG_16
from r2morph.mutations.gadgets import Gadgets, create_gadgets


@dataclass
class GeneratedCode:
    code: bytes
    size: int
    store_gadget: Optional[bytes] = None
    restore_gadget: Optional[bytes] = None


class JunkGenerator:
    """
    Generates semantically neutral junk code using Keystone assembler.

    Uses gadgets library to produce instruction sequences that preserve
    program semantics while increasing code entropy.
    """

    def __init__(self, os_type: str = "linux"):
        self.os_type = os_type
        self._reg_tracker = RegTracker()
        self._gadgets: Optional[Gadgets] = None
        self._assembler = None
        self._init_assembler()

    def _init_assembler(self):
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_64

            self._assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        except ImportError:
            self._assembler = None

    def _get_gadgets(self) -> Gadgets:
        if self._gadgets is None:
            self._gadgets = create_gadgets(self.os_type)
            self._gadgets._stack_depth = self._reg_tracker.get_stack_depth()
        return self._gadgets

    def assemble(self, asm: str) -> tuple[bytes, int]:
        if self._assembler is None:
            return b"", 0

        try:
            encoding, count = self._assembler.asm(asm)
            return bytes(encoding), count
        except Exception:
            return b"", 0

    def get_register_choice(self) -> tuple[list[str], list[int]]:
        return self._reg_tracker.get_register_weights()

    def get_subregister_data(self, reg: str) -> tuple[tuple[str, ...], tuple[int, ...]]:
        result = self._reg_tracker.get_subregister_weights(reg)
        if result is None:
            return ((), ())
        return result

    def get_secondary_register(self, primary_reg: str) -> str:
        stored_regs = self._reg_tracker.get_stored_registers()
        if not stored_regs:
            return primary_reg

        regs, weights = self.get_register_choice()
        reg_weight_map = dict(zip(regs, weights))

        stored_weights = [0 if r == primary_reg else reg_weight_map.get(r, 0) for r in stored_regs]

        if set(stored_weights) == {0}:
            return primary_reg

        return random.choices(stored_regs, weights=stored_weights, k=1)[0]

    def store_register(self, reg: str) -> tuple[bytes, int]:
        gadgets = self._get_gadgets()

        gadget_keys = tuple(gadgets.stack_gadgets.keys())
        gadget_weights = [gadgets.stack_gadgets[k][2] for k in gadget_keys]
        selected_key = random.choices(gadget_keys, weights=gadget_weights, k=1)[0]

        store_func = gadgets.stack_gadgets[selected_key][0]
        restore_func = gadgets.stack_gadgets[selected_key][1]

        store_asm = store_func(reg)
        restore_asm = restore_func(reg)

        store_bytes, store_size = self.assemble(store_asm)
        restore_bytes, _ = self.assemble(restore_asm)

        self._reg_tracker.store_register(reg, restore_bytes)
        gadgets._stack_depth = self._reg_tracker.get_stack_depth()

        return store_bytes, store_size

    def restore_register(self) -> bytes:
        reg, gadget = self._reg_tracker.get_top_stack_register()
        if reg:
            self._reg_tracker.restore_register(reg)
            gadgets = self._get_gadgets()
            gadgets._stack_depth = self._reg_tracker.get_stack_depth()
        return gadget

    def get_junk_instruction(self, reg: str) -> tuple[bytes, int]:
        gadgets = self._get_gadgets()
        sec_reg = self.get_secondary_register(reg)

        gadget_keys = tuple(gadgets.operate_gadgets.keys())
        gadget_weights = [gadgets.operate_gadgets[k][2] for k in gadget_keys]

        subreg_names, subreg_weights = self.get_subregister_data(reg)
        if not subreg_names:
            return b"", 0

        subreg = random.choices(subreg_names, weights=subreg_weights, k=1)[0]

        sec_subregs, _ = self.get_subregister_data(sec_reg)
        if sec_subregs:
            idx = list(subreg_names).index(subreg) if subreg in subreg_names else 0
            sec_subreg = sec_subregs[idx] if idx < len(sec_subregs) else subreg
            if sec_subreg is None:
                sec_subreg = subreg_names[4] if len(subreg_names) > 4 else subreg
        else:
            sec_subreg = subreg

        gadget_weights_updated = []
        for key in gadget_keys:
            gadget_flags = gadgets.operate_gadgets[key][1]
            subreg_flags = REG_SIZES_MAP.get(subreg, 0)
            if gadget_flags & subreg_flags:
                gadget_weights_updated.append(gadget_weights[list(gadget_keys).index(key)])
            else:
                gadget_weights_updated.append(0)

        if set(gadget_weights_updated) == {0}:
            return b"", 0

        selected_key = random.choices(gadget_keys, weights=gadget_weights_updated, k=1)[0]
        gadget_func = gadgets.operate_gadgets[selected_key][0]

        gadgets.set_cnt_reg(sec_reg)

        asm = gadget_func(subreg, sec_subreg)
        code, size = self.assemble(asm)

        if code is None or len(code) == 0:
            return b"", 0

        return code, size

    def generate_junk_code(self, size: int) -> bytes:
        code = b""
        available = size

        while available > 0:
            regs, weights = self.get_register_choice()
            reg = random.choices(regs, weights=weights, k=1)[0]

            if not self._reg_tracker.is_stored(reg):
                if available <= 16:
                    continue
                store_code, store_size = self.store_register(reg)
                restore_code = (
                    self._reg_tracker.get_stored_registers()[-1] if self._reg_tracker.get_stored_registers() else None
                )
                if restore_code:
                    available -= store_size + len(self._reg_tracker.get_top_stack_register()[1])
                code += store_code

            if available > 0:
                ins, ins_size = self.get_junk_instruction(reg)

                attempts = 0
                while available - ins_size < 0 and attempts < 10:
                    ins, ins_size = self.get_junk_instruction(reg)
                    attempts += 1

                if ins_size > 0:
                    available -= ins_size
                    code += ins

        restore_code = self.restore_register()
        while restore_code:
            code += restore_code
            restore_code = self.restore_register()

        return code

    def generate_with_store_restore(self, reg: str, size: int) -> GeneratedCode:
        store_code, store_size = self.store_register(reg)
        junk = self.generate_junk_code(size - store_size)
        restore_code = self.restore_register()

        return GeneratedCode(
            code=store_code + junk + restore_code,
            size=store_size + len(junk) + len(restore_code),
            store_gadget=store_code,
            restore_gadget=restore_code,
        )

    def clear(self):
        self._reg_tracker.clear()
        if self._gadgets:
            self._gadgets._stack_depth = 0


def create_junk_generator(os_type: str = "linux") -> JunkGenerator:
    return JunkGenerator(os_type)
