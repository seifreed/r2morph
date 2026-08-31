"""Stateful item encoder for region virtualization."""

from __future__ import annotations

import struct
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import ARCH_BITS_64
from r2morph.mutations.code_virtualization_engine import VirtualizedOp, pack_immediate
from r2morph.mutations.code_virtualization_layout import (
    idx_immediate_permuted_fields,
    idx_permuted_fields,
    imul3_permuted_fields,
    mem_immediate_permuted_fields,
    mem_permuted_fields,
    op_permuted_fields,
    pair_permuted_fields,
    permuted_fields,
    shift_permuted_fields,
    triple_permuted_fields,
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
            self._emit_fp_shift_immediate,
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

    def _triple(self, position: int, first: int, second: int, third: int) -> None:
        values = {"a": first, "b": second, "c": third}
        for name, _size in triple_permuted_fields("a", "b", "c", self.scheme.field_perm):
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

    def _mem_immediate(self, position: int, base_slot: int | None, disp: int, value: int, width: int) -> None:
        fields = {
            "reg": b"\x00",
            "disp": struct.pack("<i", disp),
            "imm": pack_immediate(value, ARCH_BITS_64 if width == ARCH_BITS_64 else 32),
        }
        if base_slot is not None:
            fields["base"] = bytes([base_slot])
        for name, _size in mem_immediate_permuted_fields(base_slot is None, width, self.scheme.field_perm):
            self.plain.extend(byte ^ position for byte in fields[name])

    def _idx_immediate(self, position: int, operands: tuple[int | None, int, int, int, int, int]) -> None:
        base_slot, index_slot, shift, disp, value, width = operands
        fields = {
            "reg": b"\x00",
            "index": bytes([index_slot]),
            "shift": bytes([shift]),
            "disp": struct.pack("<i", disp),
            "imm": pack_immediate(value, ARCH_BITS_64 if width == ARCH_BITS_64 else 32),
        }
        if base_slot is not None:
            fields["base"] = bytes([base_slot])
        for name, _size in idx_immediate_permuted_fields(base_slot is None, width, self.scheme.field_perm):
            self.plain.extend(byte ^ position for byte in fields[name])

    def _mem_with_source(self, position: int, destination: int, source: int, base: int | None, disp: int) -> None:
        self._mem(position, (destination, None if base is None else self.slot_of[base], disp))
        self.plain.append(source ^ position)

    def _idx_with_source(self, position: int, operands: tuple[int, int | None, int, int, int], source: int) -> None:
        destination, base, index, shift, disp = operands
        self._idx(
            position,
            (
                destination,
                None if base is None else self.slot_of[base],
                self.slot_of[index],
                shift,
                disp,
            ),
        )
        self.plain.append(source ^ position)

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
        elif kind in ("vloadidxnb", "vstoreidxnb"):
            _, index, shift, disp, _width = item
            self._idx(self._opcode(item), (self.slot_of[0], None, self.slot_of[index], shift, disp))
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
        if kind in ("fpmovvexscalar", "fpmovvexscalar3"):
            return self._emit_vex_scalar_register_move(item)
        if kind in ("fpmovvexgp", "fpmovvexgpd"):
            self._pair(self._opcode(item), item[2], self.slot_of[item[3]])
            return True
        if kind in ("fpmovmskb", "fpmovmskbvex", "fpmovmskbvex256"):
            self._pair(self._opcode(item), item[2], self.slot_of[item[1]])
            return True
        if kind in (
            "fpload",
            "fpstore",
            "fploadrip",
            "fpstorerip",
            "fploadidx",
            "fpstoreidx",
            "fploadidxnb",
            "fpstoreidxnb",
        ):
            return self._emit_fp_scalar_memory_move(item)
        if kind == "fparith":
            self._pair(self._opcode(item), item[2], item[3])
        elif kind == "fparithvex":
            self._triple(self._opcode(item), item[2], item[3], item[4])
        elif kind == "cvti2f":
            self._pair(self._opcode(item), item[3], self.slot_of[item[4]])
        elif kind == "cvtf2i":
            self._pair(self._opcode(item), item[4], self.slot_of[item[3]])
        elif kind in ("fpmovd", "fpmovq"):
            _, _direction, xmm, gp = item
            self._pair(self._opcode(item), xmm, self.slot_of[gp])
        elif kind in ("fpcmp", "fpmov", "fppacked", "fpmovvex", "fpmovvex256"):
            self._pair(self._opcode(item), item[2], item[3])
        elif kind in ("fppackedvex", "fppackedvex256"):
            self._triple(self._opcode(item), item[2], item[3], item[4])
        else:
            return False
        return True

    def _emit_fp_scalar_memory_move(self, item: RegionItem) -> bool:
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
        else:
            return False
        return True

    def _emit_vex_scalar_register_move(self, item: RegionItem) -> bool:
        kind = item[0]
        position = self._opcode(item)
        if kind == "fpmovvexscalar":
            self._pair(position, item[2], item[3])
        else:
            self._triple(position, item[2], item[3], item[4])
        return True

    def _emit_fp_shift_immediate(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind not in (
            "fppackedimm",
            "fppackedveximm",
            "fppackedvex256imm",
            "fppackedvex256permimm",
            "fppackedvex256permilimm",
        ):
            return False
        position = self._opcode(item)
        if kind == "fppackedimm":
            self.plain.append(item[2] ^ position)
            self.plain.append(item[3] ^ position)
        elif kind == "fppackedvex256permimm":
            self._triple(position, item[2], item[3], item[4])
            self.plain.append(item[5] ^ position)
        elif kind == "fppackedvex256permilimm":
            self._pair(position, item[2], item[3])
            self.plain.append(item[4] ^ position)
        else:
            self._pair(position, item[2], item[3])
            self.plain.append(item[4] ^ position)
        return True

    def _emit_fp_memory(self, item: RegionItem) -> bool:
        if item[0] in (
            "fploadvex",
            "fploadvexrip",
            "fploadvexidx",
            "fploadvexidxnb",
            "fpstorevex",
            "fpstorevexrip",
            "fpstorevexidx",
            "fpstorevexidxnb",
            "fpmovvexmem",
            "fpmovvexmemrip",
            "fpmovvexmemidx",
            "fpmovvexmemidxnb",
        ):
            return self._emit_vex_scalar_memory_move(item)
        if self._emit_fp_memory_move(item):
            return True
        return self._emit_fp_memory_arithmetic(item)

    def _emit_fp_memory_move(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind.startswith(("fppackedvexmem", "fppackedvex256mem")):
            return self._emit_vex_memory_arithmetic(item)
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
        elif kind in ("fpploadidx", "fppstoreidx", "fpploadidxnb", "fppstoreidxnb"):
            self._emit_fp_indexed(item)
        elif kind in ("fppackedmemidx", "fppackedmemidxnb"):
            self._emit_fp_packed_indexed(item)
        elif kind in ("fploadvex256", "fpstorevex256"):
            _, ymm, base, disp = item
            self._mem(self._opcode(item), (ymm, self.slot_of[base], disp))
        elif kind in ("fploadvex256rip", "fpstorevex256rip"):
            _, ymm, target = item
            self._mem(self._opcode(item), (ymm, None, target - self.bytecode_base))
        elif kind in ("fploadvex256idx", "fpstorevex256idx"):
            _, ymm, base, index, shift, disp = item
            self._idx(self._opcode(item), (ymm, self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind in ("fploadvex256idxnb", "fpstorevex256idxnb"):
            _, ymm, index, shift, disp = item
            self._idx(self._opcode(item), (ymm, None, self.slot_of[index], shift, disp))
        else:
            return False
        return True

    def _emit_vex_scalar_memory_move(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind.startswith(("fploadvex", "fpstorevex")):
            _, xmm, *operands, _width = item
            if kind.endswith("idxnb"):
                _, index, shift, disp = operands
                self._idx(self._opcode(item), (xmm, None, self.slot_of[index], shift, disp))
            elif kind.endswith("idx"):
                _, base, index, shift, disp = operands
                self._idx(self._opcode(item), (xmm, self.slot_of[base], self.slot_of[index], shift, disp))
            elif kind.endswith("rip"):
                (target,) = operands
                self._mem(self._opcode(item), (xmm, None, target - self.bytecode_base))
            else:
                base, disp = operands
                self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
            return True
        if kind == "fpmovvexmem":
            _, destination, source, base, disp, _width = item
            self._mem_with_source(self._opcode(item), destination, source, self.slot_of[base], disp)
        elif kind == "fpmovvexmemrip":
            _, destination, source, target, _width = item
            self._mem_with_source(self._opcode(item), destination, source, None, target - self.bytecode_base)
        elif kind == "fpmovvexmemidx":
            _, destination, source, base, index, shift, disp, _width = item
            self._idx_with_source(self._opcode(item), (destination, base, index, shift, disp), source)
        elif kind == "fpmovvexmemidxnb":
            _, destination, source, index, shift, disp, _width = item
            self._idx_with_source(self._opcode(item), (destination, None, index, shift, disp), source)
        else:
            return False
        return True

    def _emit_vex_memory_arithmetic(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("fppackedvexmem", "fppackedvex256mem"):
            _, _operation, destination, source, base, disp = item
            self._mem_with_source(self._opcode(item), destination, source, base, disp)
        elif kind in ("fppackedvexmemrip", "fppackedvex256memrip"):
            _, _operation, destination, source, target = item
            self._mem_with_source(self._opcode(item), destination, source, None, target - self.bytecode_base)
        elif kind in ("fppackedvexmemidx", "fppackedvex256memidx"):
            _, _operation, destination, source, base, index, shift, disp = item
            self._idx_with_source(self._opcode(item), (destination, base, index, shift, disp), source)
        elif kind in ("fppackedvexmemidxnb", "fppackedvex256memidxnb"):
            _, _operation, destination, source, index, shift, disp = item
            self._idx_with_source(self._opcode(item), (destination, None, index, shift, disp), source)
        else:
            return False
        return True

    def _emit_fp_memory_arithmetic(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind in ("fparithvexmem", "fparithvexmemrip", "fparithvexmemidx", "fparithvexmemidxnb"):
            return self._emit_vex_scalar_memory_arithmetic(item)
        if kind == "fparithmem":
            _, _op, xmm, base, disp, _width = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        elif kind == "fparithmemrip":
            _, _op, xmm, target, _width = item
            self._mem(self._opcode(item), (xmm, None, target - self.bytecode_base))
        elif kind in ("fparithmemidx", "fparithmemidxnb"):
            self._emit_fp_arith_indexed(item)
        elif kind == "fpcmpmem":
            _, _mnemonic, xmm, base, disp, _width = item
            self._mem(self._opcode(item), (xmm, self.slot_of[base], disp))
        elif kind in ("fpcmpmemidx", "fpcmpmemidxnb"):
            self._emit_fp_compare_indexed(item)
        else:
            return False
        return True

    def _emit_vex_scalar_memory_arithmetic(self, item: RegionItem) -> bool:
        kind = item[0]
        if kind == "fparithvexmem":
            _, _operation, destination, source, base, disp, _width = item
            self._mem_with_source(self._opcode(item), destination, source, self.slot_of[base], disp)
        elif kind == "fparithvexmemrip":
            _, _operation, destination, source, target, _width = item
            self._mem_with_source(self._opcode(item), destination, source, None, target - self.bytecode_base)
        elif kind == "fparithvexmemidx":
            _, _operation, destination, source, base, index, shift, disp, _width = item
            self._idx_with_source(self._opcode(item), (destination, base, index, shift, disp), source)
        elif kind == "fparithvexmemidxnb":
            _, _operation, destination, source, index, shift, disp, _width = item
            self._idx_with_source(self._opcode(item), (destination, None, index, shift, disp), source)
        else:
            return False
        return True

    def _emit_fp_packed_indexed(self, item: RegionItem) -> None:
        kind = item[0]
        operands: tuple[int, int | None, int, int, int]
        if kind.endswith("nb"):
            _, _mnemonic, xmm, index, shift, disp = item
            operands = (xmm, None, self.slot_of[index], shift, disp)
        else:
            _, _mnemonic, xmm, base, index, shift, disp = item
            operands = (xmm, self.slot_of[base], self.slot_of[index], shift, disp)
        self._idx(self._opcode(item), operands)

    def _emit_fp_indexed(self, item: RegionItem) -> None:
        kind = item[0]
        operands: tuple[int, int | None, int, int, int]
        if kind.endswith("nb"):
            _, xmm, index, shift, disp = item
            operands = (xmm, None, self.slot_of[index], shift, disp)
        else:
            _, xmm, base, index, shift, disp = item
            operands = (xmm, self.slot_of[base], self.slot_of[index], shift, disp)
        self._idx(self._opcode(item), operands)

    def _emit_fp_arith_indexed(self, item: RegionItem) -> None:
        kind = item[0]
        operands: tuple[int, int | None, int, int, int]
        if kind.endswith("nb"):
            _, _op, xmm, _base, index, shift, disp, _width = item
            operands = (xmm, None, self.slot_of[index], shift, disp)
        else:
            _, _op, xmm, base, index, shift, disp, _width = item
            operands = (xmm, self.slot_of[base], self.slot_of[index], shift, disp)
        self._idx(self._opcode(item), operands)

    def _emit_fp_compare_indexed(self, item: RegionItem) -> None:
        kind = item[0]
        operands: tuple[int, int | None, int, int, int]
        if kind.endswith("nb"):
            _, _mnemonic, xmm, _base, index, shift, disp, _width = item
            operands = (xmm, None, self.slot_of[index], shift, disp)
        else:
            _, _mnemonic, xmm, base, index, shift, disp, _width = item
            operands = (xmm, self.slot_of[base], self.slot_of[index], shift, disp)
        self._idx(self._opcode(item), operands)

    def _emit_gp_memory(self, item: RegionItem) -> bool:
        if self._emit_memory_immediate(item):
            return True
        kind = item[0]
        if kind in ("load", "store"):
            _, reg, base, disp, _width = item
            self._gp_mem(item, reg, base, disp)
        elif kind in ("tlsload", "tlsstore", "tlsloadidx", "tlsloadidxnb", "tlsstoreidx", "tlsstoreidxnb"):
            self._emit_tls_memory(item)
        elif kind in ("riprel_load", "riprel_store"):
            _, reg, target, _width = item
            self._gp_rip(item, reg, target)
        elif kind in ("cmpmem", "cmpriprel"):
            self._emit_compare_memory(item)
        elif kind in ("opmem", "lea"):
            reg, base, disp = item[2], item[3], item[4]
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

    def _emit_compare_memory(self, item: RegionItem) -> None:
        if item[0] == "cmpmem":
            _, reg, base, disp, _width = item
            self._gp_mem(item, reg, base, disp)
        else:
            _, reg, target, _width = item
            self._gp_rip(item, reg, target)

    def _emit_memory_immediate(self, item: RegionItem) -> bool:
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

    def _emit_tls_indexed(self, item: RegionItem) -> None:
        kind = item[0]
        operands: tuple[int, int | None, int, int, int]
        if kind.endswith("nb"):
            _, _reg, _segment, _base, index, shift, disp, _width = item
            operands = (self.slot_of[item[1]], None, self.slot_of[index], shift, disp)
        else:
            _, _reg, _segment, base, index, shift, disp, _width = item
            operands = (self.slot_of[item[1]], self.slot_of[base], self.slot_of[index], shift, disp)
        self._idx(self._opcode(item), operands)

    def _emit_tls_memory(self, item: RegionItem) -> None:
        kind = item[0]
        if kind.endswith("idx") or kind.endswith("idxnb"):
            self._emit_tls_indexed(item)
            return
        _, reg, _segment, base, disp, _width = item
        self._mem(self._opcode(item), (self.slot_of[reg], None if base is None else self.slot_of[base], disp))

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
            self._disp(item[1] - self.bytecode_base, self._opcode(item))
        elif kind == "icall":
            self.plain.append(self.slot_of[item[1]] ^ self._opcode(item))
        elif kind == "ijmp":
            self.plain.append(self.slot_of[item[1]] ^ self._opcode(item, kind))
        elif kind == "ijmpmem":
            _, base, index, shift, disp = item
            self._idx(self._opcode(item, kind), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "ijmpmemnb":
            _, index, shift, disp = item
            self._idx(self._opcode(item, kind), (self.slot_of[0], None, self.slot_of[index], shift, disp))
        elif kind == "callmem":
            base, disp = item[1], item[2]
            self._mem(self._opcode(item), (self.slot_of[0], self.slot_of[base], disp))
        elif kind == "callmemrip":
            self._mem(self._opcode(item), (self.slot_of[0], None, item[1] - self.bytecode_base))
        elif kind == "callmemidx":
            base, index, shift, disp = item[1], item[2], item[3], item[4]
            self._idx(self._opcode(item), (self.slot_of[0], self.slot_of[base], self.slot_of[index], shift, disp))
        elif kind == "callmemidxnb":
            index, shift, disp = item[1], item[2], item[3]
            self._idx(self._opcode(item), (self.slot_of[0], None, self.slot_of[index], shift, disp))
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
        elif kind in (
            "exit",
            "vret",
            "enter_inner",
            "inner_exit",
            "fsave",
            "frestore",
            "vzeroupper",
            "vzeroall",
        ):
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

    def _emit_atomic_memory(self, item: RegionItem) -> None:
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
