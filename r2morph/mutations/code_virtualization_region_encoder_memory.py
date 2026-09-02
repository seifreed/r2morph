"""GP and memory item emission for the region bytecode encoder."""

from __future__ import annotations

from typing import Any

RegionItem = tuple[Any, ...]


class RegionEncoderMemoryMixin:
    """Emit memory-shaped region items using the encoder's shared primitives."""

    def _emit_gp_memory(self: Any, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("load", "store"):
            _, reg, base, disp, _width = item
            self._gp_mem(item, reg, base, disp)
        elif kind.startswith("notmem"):
            self._emit_not_memory(item)
        elif kind in ("tlsload", "tlsstore", "tlsloadidx", "tlsloadidxnb", "tlsstoreidx", "tlsstoreidxnb"):
            self._emit_tls_memory(item)
        elif kind in ("riprel_load", "riprel_store"):
            _, reg, target, _width = item
            self._gp_rip(item, reg, target)
        elif kind in ("cmpmem", "cmpriprel"):
            self._emit_compare_memory(item)
        elif kind in ("load", "store", "opmem", "lea"):
            offset = 1 if kind in ("load", "store") else 2
            reg, base, disp = item[offset], item[offset + 1], item[offset + 2]
            self._gp_mem(item, reg, base, disp)
        elif kind in (
            "xchgmem",
            "xchgmemidx",
            "cmpxchgmem",
            "cmpxchgmemidx",
            "atomicmem",
            "atomicmemrip",
            "atomicmemidx",
            "atomicmemidxnb",
        ):
            self._emit_atomic_memory(item)
        elif kind in ("opriprel", "learip"):
            reg, target = item[2], item[3]
            self._gp_rip(item, reg, target)
        elif kind == "leaidx":
            _, reg, base, index, shift, disp, _width = item
            self._gp_idx(item, (reg, base, index, shift, disp))
        elif kind == "leaidxnb":
            _, reg, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[reg], None, self.slot_of[index], shift, disp))
        elif kind == "opmemidx":
            _, _mnemonic, reg, base, index, shift, disp, _width = item
            self._gp_idx(item, (reg, base, index, shift, disp))
        else:
            return False
        return True

    def _emit_not_memory(self: Any, item: RegionItem) -> None:
        kind = item[0]
        if kind == "notmem":
            _, base, disp, _width = item
            self._mem(self._opcode(item), (self.slot_of[0], self.slot_of[base], disp))
        elif kind == "notmemrip":
            _, target, _width = item
            self._mem(self._opcode(item), (self.slot_of[0], None, target - self.bytecode_base))
        elif kind == "notmemidx":
            _, base, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        else:
            _, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[0], None, self.slot_of[index], shift, disp))

    def _emit_compare_memory(self: Any, item: RegionItem) -> None:
        if item[0] == "cmpmem":
            _, reg, base, disp, _width = item
            self._gp_mem(item, reg, base, disp)
        else:
            _, reg, target, _width = item
            self._gp_rip(item, reg, target)

    def _emit_memory_immediate(self: Any, item: RegionItem) -> bool:
        kind = item[0]
        if kind == "storei":
            _, value, base, disp, width = item
            self._mem_immediate(self._opcode(item), self.slot_of[base], disp, value, width)
        elif kind == "storeirip":
            _, value, target, width = item
            self._mem_immediate(self._opcode(item), None, target - self.bytecode_base, value, width)
        elif kind == "storeiidx":
            _, value, base, index, shift, disp, width = item
            self._idx_immediate(
                self._opcode(item),
                (self.slot_of[base], self.slot_of[index], shift, disp, value, width),
            )
        elif kind == "storeiidxnb":
            _, value, index, shift, disp, width = item
            self._idx_immediate(self._opcode(item), (None, self.slot_of[index], shift, disp, value, width))
        else:
            return False
        return True

    def _emit_tls_indexed(self: Any, item: RegionItem) -> None:
        kind = item[0]
        if kind.endswith("nb"):
            _, _reg, _segment, _base, index, shift, disp, _width = item
            operands = (self.slot_of[item[1]], None, self.slot_of[index], shift, disp)
        else:
            _, _reg, _segment, base, index, shift, disp, _width = item
            operands = (self.slot_of[item[1]], self.slot_of[base], self.slot_of[index], shift, disp)
        self._idx(self._opcode(item), operands)

    def _emit_tls_memory(self: Any, item: RegionItem) -> None:
        kind = item[0]
        if kind.endswith("idx") or kind.endswith("idxnb"):
            self._emit_tls_indexed(item)
            return
        _, reg, _segment, base, disp, _width = item
        self._mem(self._opcode(item), (self.slot_of[reg], None if base is None else self.slot_of[base], disp))

    def _emit_atomic_memory(self: Any, item: RegionItem) -> None:
        if item[0] in ("xchgmem", "cmpxchgmem"):
            self._gp_mem(item, item[1], item[2], item[3])
            return
        if item[0] == "atomicmem":
            self._gp_mem(item, item[2], item[3], item[4])
            return
        if item[0] == "atomicmemrip":
            self._gp_rip(item, item[2], item[3])
            return
        if item[0] == "atomicmemidxnb":
            _, _mnemonic, register, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[register], None, self.slot_of[index], shift, disp))
            return
        if item[0] == "atomicmemidx":
            _, _mnemonic, register, base, index, shift, disp, _width = item
            self._idx(
                self._opcode(item),
                (self.slot_of[register], self.slot_of[base], self.slot_of[index], shift, disp),
            )
            return
        _, register, base, index, shift, disp, _width = item
        self._gp_idx(item, (register, base, index, shift, disp))

    def _emit_bt_memory(self: Any, item: RegionItem) -> bool:
        kind = item[0]
        if not kind.startswith("btmem"):
            return False
        position = self._opcode(item)
        if kind == "btmem":
            _, base, disp, bit, immediate, _width = item
            self._mem(position, (self.slot_of[0], self.slot_of[base], disp))
        elif kind == "btmemrip":
            _, target, bit, immediate, _width = item
            self._mem(position, (self.slot_of[0], None, target - self.bytecode_base))
        elif kind == "btmemidx":
            _, base, index, shift, disp, bit, immediate, _width = item
            self._idx(position, (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        else:
            _, index, shift, disp, bit, immediate, _width = item
            self._idx(position, (self.slot_of[0], None, self.slot_of[index], shift, disp))
        encoded_bit = bit if immediate else self.slot_of[bit]
        self.plain.append(encoded_bit ^ position)
        return True

    def _emit_div_memory(self: Any, item: RegionItem) -> bool:
        kind = item[0]
        if not kind.startswith("divmem"):
            return False
        position = self._opcode(item)
        if kind == "divmem":
            _, _signedness, base, disp, _width = item
            self._mem(position, (self.slot_of[0], self.slot_of[base], disp))
        elif kind == "divmemrip":
            _, _signedness, target, _width = item
            self._mem(position, (self.slot_of[0], None, target - self.bytecode_base))
        elif kind == "divmemidx":
            _, _signedness, base, index, shift, disp, _width = item
            self._idx(position, (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        else:
            _, _signedness, index, shift, disp, _width = item
            self._idx(position, (self.slot_of[0], None, self.slot_of[index], shift, disp))
        return True
