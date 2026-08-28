"""Stateful item encoder for region virtualization."""

from __future__ import annotations

import struct
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_engine import VirtualizedOp, pack_immediate
from r2morph.mutations.code_virtualization_layout import (
    idx_permuted_fields,
    imul3_permuted_fields,
    mem_permuted_fields,
    op_permuted_fields,
    pair_permuted_fields,
    permuted_fields,
    shift_permuted_fields,
)
from r2morph.mutations.code_virtualization_region_models import RegionScheme, _required_key

RegionItem = tuple[Any, ...]


class RegionEncoder:
    """Emit one region with deterministic opcode selection and field masking."""

    def __init__(
        self,
        scheme: RegionScheme,
        offsets: list[int],
        bytecode_base: int,
        checksum: int,
    ) -> None:
        self.scheme = scheme
        self.offsets = offsets
        self.bytecode_base = bytecode_base
        self.checksum = checksum
        self.slot_of = scheme.slot_perm
        self.pick = random.Random(scheme.junk_seed).choice
        self.plain = bytearray()

    def encode(self, items: list[RegionItem]) -> bytes:
        emitters = (
            self._emit_virtual,
            self._emit_integer,
            self._emit_fp_scalar,
            self._emit_fp_memory,
            self._emit_gp_memory,
            self._emit_misc,
            self._emit_calls,
            self._emit_branches,
        )
        for item in items:
            for emit in emitters:
                if emit(item):
                    break
        return bytes(byte ^ (self.checksum & 0xFF) for byte in self.plain)

    def _opcode(self, item: RegionItem, key: str | None = None) -> int:
        position = len(self.plain) & 0xFF
        opcode = self.pick(self.scheme.dup[key or _required_key(item)])
        self.plain.append(opcode ^ position)
        return position

    def _imm(self, value: int, width: int, position: int) -> None:
        self.plain.extend(byte ^ position for byte in pack_immediate(value, width))

    def _disp(self, value: int, position: int) -> None:
        self.plain.extend(byte ^ position for byte in struct.pack("<i", value))

    def _target_offset(self, index: int) -> int:
        if not 0 <= index < len(self.offsets):
            raise struct.error(f"branch target item index {index} outside the region's {len(self.offsets)} items")
        return self.offsets[index]

    def _pair(self, position: int, first: int, second: int) -> None:
        values = {"a": first, "b": second}
        for name, _size in pair_permuted_fields("a", "b", self.scheme.field_perm):
            self.plain.append(values[name] ^ position)

    def _mem(self, position: int, operands: tuple[int, int | None, int]) -> None:
        reg_slot, base_slot, disp = operands
        fields = {"reg": bytes([reg_slot]), "disp": struct.pack("<i", disp)}
        if base_slot is not None:
            fields["base"] = bytes([base_slot])
        for name, _size in mem_permuted_fields(base_slot is None, self.scheme.field_perm):
            self.plain.extend(byte ^ position for byte in fields[name])

    def _idx(self, position: int, operands: tuple[int, int | None, int, int, int]) -> None:
        reg_slot, base_slot, index_slot, shift, disp = operands
        fields = {
            "reg": bytes([reg_slot]),
            "index": bytes([index_slot]),
            "shift": bytes([shift]),
            "disp": struct.pack("<i", disp),
        }
        if base_slot is not None:
            fields["base"] = bytes([base_slot])
        for name, _size in idx_permuted_fields(base_slot is None, self.scheme.field_perm):
            self.plain.extend(byte ^ position for byte in fields[name])

    def _emit_virtual(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("op", "opmba", "opsynth"):
            op: VirtualizedOp = item[1]
            key = _required_key(item)
            position = self._opcode(item)
            fields = {"dst": bytes([self.slot_of[op.dst_index]])}
            field = "imm" if op.is_immediate else "src"
            fields[field] = pack_immediate(op.value, op.width) if op.is_immediate else bytes([self.slot_of[op.value]])
            self._fields(position, permuted_fields(key, self.scheme.field_perm), fields)
        elif kind in ("vpush", "vpop", "vpop8", "vpop16"):
            self._slot(item, item[1])
        elif kind == "vpushi":
            position = self._opcode(item)
            self._imm(item[1], item[2], position)
        elif kind == "vshift":
            self.plain.append(item[2] ^ self._opcode(item))
        elif kind == "vshiftreg":
            self.plain.append(self.slot_of[1] ^ self._opcode(item))
        elif kind in ("vbinop", "vbinopsynth", "vcmpsynth"):
            self._opcode(item)
        elif kind in ("vload", "vstore", "vlea"):
            _, base, disp, _width = item
            self._mem(self._opcode(item), (self.slot_of[0], self.slot_of[base], disp))
        elif kind in ("vloadidx", "vstoreidx", "vleaidx"):
            _, base, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind in ("vloadrip", "vstorerip", "vlearip"):
            _, target, _width = item
            self._mem(self._opcode(item), (self.slot_of[0], None, target - self.bytecode_base))
        else:
            return False
        return True

    def _emit_integer(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind == "vleaidxnb":
            _, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[0], None, self.slot_of[index], shift, disp))
        elif kind == "vmovx":
            _, _ext, _src_size, _width, base, disp = item
            self._mem(self._opcode(item), (self.slot_of[0], self.slot_of[base], disp))
        elif kind == "vmovxidx":
            _, _ext, _src_size, _width, base, index, shift, disp = item
            self._idx(self._opcode(item), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "shift":
            _, _mnemonic, slot, count, _width = item
            position = self._opcode(item)
            fields = {"slot": bytes([self.slot_of[slot]]), "count": bytes([count])}
            self._fields(position, shift_permuted_fields(self.scheme.field_perm), fields)
        elif kind == "imul":
            _, dst, src, width = item
            position = self._opcode(item)
            fields = {"dst": bytes([self.slot_of[dst]]), "src": bytes([self.slot_of[src]])}
            self._fields(position, op_permuted_fields(False, width, self.scheme.field_perm), fields)
        elif kind == "imul3":
            _, dst, src, imm, _width = item
            position = self._opcode(item)
            fields = {
                "dst": bytes([self.slot_of[dst]]),
                "src": bytes([self.slot_of[src]]),
                "imm": pack_immediate(imm, 32),
            }
            self._fields(position, imul3_permuted_fields(self.scheme.field_perm), fields)
        elif kind in ("push", "pop"):
            self._slot(item, item[1])
        elif kind == "pushi":
            self._imm(item[1], 64, self._opcode(item))
        elif kind == "rspadj":
            self._imm(item[2], 32, self._opcode(item))
        elif kind in ("movfromrsp", "movtorsp", "leave"):
            self._slot(item, item[1])
        else:
            return False
        return True

    def _emit_fp_scalar(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("fpload", "fpstore"):
            _, xmm, base, disp, _width = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        elif kind in ("fploadrip", "fpstorerip"):
            _, xmm, target, _width = item
            self._mem(self._opcode(item), (xmm, None, target - self.bytecode_base))
        elif kind in ("fploadidx", "fpstoreidx"):
            _, xmm, base, index, shift, disp, _width = item
            self._idx(self._opcode(item), (xmm, self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind in ("fploadidxnb", "fpstoreidxnb"):
            _, xmm, index, shift, disp, _width = item
            self._idx(self._opcode(item), (xmm, None, self.slot_of[index], shift, disp))
        elif kind == "fparith":
            self._pair(self._opcode(item), item[2], item[3])
        elif kind == "cvti2f":
            self._pair(self._opcode(item), item[3], self.slot_of[item[4]])
        elif kind == "cvtf2i":
            self._pair(self._opcode(item), item[4], self.slot_of[item[3]])
        elif kind == "fpmovd":
            _, _direction, xmm, gp = item
            self._pair(self._opcode(item), xmm, self.slot_of[gp])
        elif kind in ("fpcmp", "fpmov", "fppacked"):
            self._pair(self._opcode(item), item[2], item[3])
        else:
            return False
        return True

    def _emit_fp_memory(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("fppload", "fppstore"):
            _, xmm, base, disp = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        elif kind == "fppackedmem":
            _, _mnemonic, xmm, base, disp = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        elif kind in ("fpploadrip", "fppstorerip"):
            _, xmm, target = item
            self._mem(self._opcode(item), (xmm, None, target - self.bytecode_base))
        elif kind == "fppackedmemrip":
            _, _mnemonic, xmm, target = item
            self._mem(self._opcode(item), (xmm, None, target - self.bytecode_base))
        elif kind in ("fpploadidx", "fppstoreidx"):
            _, xmm, base, index, shift, disp = item
            self._idx(self._opcode(item), (xmm, self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "fppackedmemidx":
            _, _mnemonic, xmm, base, index, shift, disp = item
            self._idx(self._opcode(item), (xmm, self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "fparithmem":
            _, _op, xmm, base, disp, _width = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        elif kind == "fparithmemrip":
            _, _op, xmm, target, _width = item
            self._mem(self._opcode(item), (xmm, None, target - self.bytecode_base))
        elif kind == "fparithmemidx":
            _, _op, xmm, base, index, shift, disp, _width = item
            self._idx(self._opcode(item), (xmm, self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "fpcmpmem":
            _, _mnemonic, xmm, base, disp, _width = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        else:
            return False
        return True

    def _emit_gp_memory(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("load", "store"):
            _, reg, base, disp, _width = item
            self._gp_mem(item, reg, base, disp)
        elif kind in ("tlsload", "tlsstore"):
            _, reg, _segment, base, disp, _width = item
            self._mem(self._opcode(item), (self.slot_of[reg], None if base is None else self.slot_of[base], disp))
        elif kind in ("riprel_load", "riprel_store"):
            _, reg, target, _width = item
            self._gp_rip(item, reg, target)
        elif kind == "cmpmem":
            _, reg, base, disp, _width = item
            self._gp_mem(item, reg, base, disp)
        elif kind == "cmpriprel":
            _, reg, target, _width = item
            self._gp_rip(item, reg, target)
        elif kind in ("opmem", "lea"):
            reg, base, disp = item[2], item[3], item[4]
            self._gp_mem(item, reg, base, disp)
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

    def _emit_misc(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("cmp", "test"):
            self._compare(item)
        elif kind in ("incdec", "not", "bswap"):
            reg = item[2] if kind == "incdec" else item[1]
            self._slot(item, reg)
        elif kind == "div":
            position = self._opcode(item)
            for slot in (item[2], 0, 2):
                self.plain.append(self.slot_of[slot] ^ position)
        elif kind == "cqo":
            position = self._opcode(item)
            self.plain.extend((self.slot_of[0] ^ position, self.slot_of[2] ^ position))
        elif kind == "bt":
            position = self._opcode(item)
            self.plain.append(self.slot_of[item[1]] ^ position)
            self.plain.append((item[2] if item[3] else self.slot_of[item[2]]) ^ position)
        elif kind == "movx":
            _, _ext, _src, _dst, reg, base, disp = item
            self._gp_mem(item, reg, base, disp)
        elif kind == "movxidx":
            _, _ext, _src, _dst, reg, base, index, shift, disp = item
            self._gp_idx(item, (reg, base, index, shift, disp))
        elif kind == "movxreg":
            position = self._opcode(item)
            self.plain.extend((self.slot_of[item[4]] ^ position, self.slot_of[item[5]] ^ position))
        elif kind == "opmemdst":
            self._gp_mem(item, item[2], item[3], item[4])
        elif kind == "opmemdstrip":
            self._gp_rip(item, item[2], item[3])
        else:
            return False
        return True

    def _emit_calls(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind == "call":
            self._disp(item[1] - self.bytecode_base, self._opcode(item, "call"))
        elif kind in ("icall", "ijmp"):
            self.plain.append(self.slot_of[item[1]] ^ self._opcode(item, kind))
        elif kind == "ijmpmem":
            _, base, index, shift, disp = item
            self._idx(self._opcode(item, kind), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "ijmpmemnb":
            _, index, shift, disp = item
            self._idx(self._opcode(item, kind), (self.slot_of[0], None, self.slot_of[index], shift, disp))
        elif kind == "callmem":
            _, base, disp = item
            self._mem(self._opcode(item, kind), (self.slot_of[0], self.slot_of[base], disp))
        elif kind == "callmemrip":
            self._mem(self._opcode(item, kind), (self.slot_of[0], None, item[1] - self.bytecode_base))
        elif kind == "callmemidx":
            _, base, index, shift, disp = item
            self._idx(self._opcode(item, kind), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        else:
            return False
        return True

    def _emit_branches(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("vcall", "jmp"):
            self._disp(self._target_offset(item[1]), self._opcode(item, kind))
        elif kind == "jcc":
            self._disp(self._target_offset(item[2]), self._opcode(item))
        elif kind == "setcc":
            self._slot(item, item[2])
        elif kind == "cmov":
            position = self._opcode(item)
            self.plain.extend((self.slot_of[item[2]] ^ position, self.slot_of[item[3]] ^ position))
        elif kind == "nop":
            self._opcode(item, "nop")
        elif kind in ("exit", "vret", "enter_inner", "inner_exit", "fsave", "frestore"):
            self._opcode(item)
        else:
            return False
        return True

    def _compare(self, item: RegionItem) -> None:
        _, slot, value, immediate, width = item
        position = self._opcode(item)
        fields = {"dst": bytes([self.slot_of[slot]])}
        field = "imm" if immediate else "src"
        fields[field] = pack_immediate(value, width) if immediate else bytes([self.slot_of[value]])
        self._fields(position, op_permuted_fields(immediate, width, self.scheme.field_perm), fields)

    def _fields(self, position: int, order: list[tuple[str, int]], fields: dict[str, bytes]) -> None:
        for name, _size in order:
            self.plain.extend(byte ^ position for byte in fields[name])

    def _slot(self, item: RegionItem, register: int) -> None:
        position = self._opcode(item)
        self.plain.append(self.slot_of[register] ^ position)

    def _gp_mem(self, item: RegionItem, register: int, base: int, disp: int) -> None:
        self._mem(self._opcode(item), (self.slot_of[register], self.slot_of[base], disp))

    def _gp_rip(self, item: RegionItem, register: int, target: int) -> None:
        self._mem(self._opcode(item), (self.slot_of[register], None, target - self.bytecode_base))

    def _gp_idx(
        self,
        item: RegionItem,
        operands: tuple[int, int, int, int, int],
    ) -> None:
        register, base, index, shift, disp = operands
        self._idx(
            self._opcode(item),
            (self.slot_of[register], self.slot_of[base], self.slot_of[index], shift, disp),
        )
