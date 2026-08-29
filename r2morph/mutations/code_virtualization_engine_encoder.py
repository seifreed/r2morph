"""Bytecode serialization for the engine VM."""

from __future__ import annotations

import struct

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_engine_common import (
    _FP_PACKED_VEX_OPERATIONS,
    _FP_PACKED_WIDTH,
    _FP_SCALAR_VEX_OPERATIONS,
    VMScheme,
    pack_immediate,
)
from r2morph.mutations.code_virtualization_engine_microops import (
    MICROOP_ARITH_MNEMONICS,
    MicroopEmitter,
    emit_arith_imm_microops,
    emit_arith_microops,
)
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedFpScalarVexOp,
    VirtualizedMemOp,
    VirtualizedOp,
)
from r2morph.mutations.code_virtualization_layout import (
    idx_permuted_fields,
    mem_permuted_fields,
    op_permuted_fields,
    pair_permuted_fields,
    triple_permuted_fields,
)

EngineOp = (
    VirtualizedOp
    | VirtualizedMemOp
    | VirtualizedFpMemOp
    | VirtualizedFpArithOp
    | VirtualizedFpConvertOp
    | VirtualizedFpArithMemOp
    | VirtualizedFpPackedOp
    | VirtualizedFpPackedMemOp
    | VirtualizedFpScalarVexOp
)


class _BytecodeEncoder:
    def __init__(self, scheme: VMScheme, checksum: int, bytecode_base: int) -> None:
        self.scheme = scheme
        self.checksum = checksum
        self.bytecode_base = bytecode_base
        self.slot_of = scheme.slot_perm
        self.field_perm = scheme.field_perm
        self.plain = bytearray()
        self._pending_padding = 0
        self._pending_position = 0
        self.padding_rng = random.Random(scheme.body_seed ^ 0xBADC0DE)
        self.pick = random.Random(scheme.junk_seed).choice
        self.microops = MicroopEmitter(
            scheme,
            self.slot_of,
            self._emit_opcode,
            self._emit_fields,
            self.pick,
        )

    def encode(self, ops: list[EngineOp]) -> bytes:
        for op in ops:
            if self._emit_fp(op) or self._emit_memory(op):
                continue
            if not isinstance(op, VirtualizedOp):
                raise TypeError(type(op).__name__)
            if op.mnemonic in MICROOP_ARITH_MNEMONICS:
                if op.is_immediate:
                    emit_arith_imm_microops(op, self.microops)
                else:
                    emit_arith_microops(op, self.microops)
                continue
            self._emit_gp(op)
        self._flush_pending_padding()
        self._emit_opcode(self.scheme.exit_opcode)
        return bytes(byte ^ (self.checksum & 0xFF) for byte in self.plain)

    def _emit_opcode(self, opcode: int) -> int:
        self._flush_pending_padding()
        position = len(self.plain) & 0xFF
        self.plain.append(opcode ^ position)
        self._pending_position = position
        self._pending_padding = self.scheme.record_padding[opcode] if opcode < len(self.scheme.record_padding) else 0
        return position

    def _emit_fields(self, position: int, order: list[tuple[str, int]], fields: dict[str, bytes]) -> None:
        for name, _size in order:
            self.plain.extend(byte ^ position for byte in fields[name])
        self._flush_pending_padding()

    def _flush_pending_padding(self) -> None:
        for _ in range(self._pending_padding):
            self.plain.append(self.padding_rng.randrange(256) ^ self._pending_position)
        self._pending_padding = 0

    def _emit_fp(self, op: object) -> bool:
        if isinstance(op, VirtualizedFpScalarVexOp):
            position = self._opcode("fparithvex", _FP_PACKED_WIDTH)
            fields = {
                "dst": bytes([op.dst_index]),
                "src1": bytes([op.src1_index]),
                "src2": bytes([op.src2_index]),
                "op": bytes([_FP_SCALAR_VEX_OPERATIONS.index(op.mnemonic)]),
            }
            order = [*triple_permuted_fields("dst", "src1", "src2", self.field_perm), ("op", 1)]
            self._emit_fields(position, order, fields)
        elif isinstance(op, VirtualizedFpPackedOp):
            if op.src1_index is None:
                position = self._opcode(op.mnemonic, _FP_PACKED_WIDTH)
                fields = {"dst": bytes([op.dst_index]), "src": bytes([op.src_index])}
                order = pair_permuted_fields("dst", "src", self.field_perm)
            else:
                position = self._opcode("fppackedvex", _FP_PACKED_WIDTH)
                fields = {
                    "dst": bytes([op.dst_index]),
                    "src1": bytes([op.src1_index]),
                    "src2": bytes([op.src_index]),
                    "op": bytes([_FP_PACKED_VEX_OPERATIONS.index(op.mnemonic)]),
                }
                order = [*triple_permuted_fields("dst", "src1", "src2", self.field_perm), ("op", 1)]
            self._emit_fields(position, order, fields)
        elif isinstance(op, VirtualizedFpPackedMemOp):
            position = self._opcode(op.kind, _FP_PACKED_WIDTH)
            fields = self._base_fields(op.xmm_index, op.base_index, op.disp)
            self._emit_fields(position, mem_permuted_fields(False, self.field_perm), fields)
        elif isinstance(op, VirtualizedFpArithMemOp):
            self._emit_fp_arith_memory(op)
        elif isinstance(op, VirtualizedFpConvertOp):
            position = self._opcode(f"{op.direction}{op.gp_width}", op.fp_width)
            fields = {"xmm": bytes([op.xmm_index]), "gp": bytes([self.slot_of[op.gp_slot]])}
            self._emit_fields(position, pair_permuted_fields("xmm", "gp", self.field_perm), fields)
        elif isinstance(op, VirtualizedFpArithOp):
            position = self._opcode(f"fp{op.op}", op.width)
            fields = {"dst": bytes([op.dst_index]), "src": bytes([op.src_index])}
            self._emit_fields(position, pair_permuted_fields("dst", "src", self.field_perm), fields)
        elif isinstance(op, VirtualizedFpMemOp):
            self._emit_fp_memory(op)
        else:
            return False
        return True

    def _emit_fp_arith_memory(self, op: VirtualizedFpArithMemOp) -> None:
        if op.index_index >= 0:
            if op.base_index < 0:
                kind = f"fparithmem{op.op}idxnb"
                fields = self._indexed_no_base_fields((op.xmm_index, op.index_index, op.scale, op.disp))
                order = idx_permuted_fields(True, self.field_perm)
            else:
                kind = f"fparithmem{op.op}idx"
                fields = self._indexed_fields((op.xmm_index, op.base_index, op.index_index, op.scale, op.disp))
                order = idx_permuted_fields(False, self.field_perm)
        elif op.base_index < 0:
            kind = f"fparithmem{op.op}rip"
            fields = self._rip_fields(op.xmm_index, op.disp)
            order = mem_permuted_fields(True, self.field_perm)
        else:
            kind = f"fparithmem{op.op}"
            fields = self._base_fields(op.xmm_index, op.base_index, op.disp)
            order = mem_permuted_fields(False, self.field_perm)
        self._emit_fields(self._opcode(kind, op.width), order, fields)

    def _emit_fp_memory(self, op: VirtualizedFpMemOp) -> None:
        position = self._opcode(op.kind, op.width)
        if op.kind.endswith("idxnb"):
            fields = self._indexed_no_base_fields((op.xmm_index, op.index_index, op.scale, op.disp))
            order = idx_permuted_fields(True, self.field_perm)
        elif op.kind.endswith("idx"):
            fields = self._indexed_fields((op.xmm_index, op.base_index, op.index_index, op.scale, op.disp))
            order = idx_permuted_fields(False, self.field_perm)
        elif op.kind.endswith("rip"):
            fields = self._rip_fields(op.xmm_index, op.disp)
            order = mem_permuted_fields(True, self.field_perm)
        else:
            fields = self._base_fields(op.xmm_index, op.base_index, op.disp)
            order = mem_permuted_fields(False, self.field_perm)
        self._emit_fields(position, order, fields)

    def _emit_memory(self, op: object) -> bool:
        if not isinstance(op, VirtualizedMemOp):
            return False
        position = self._opcode(op.kind, op.width)
        if op.kind.endswith("rip"):
            fields = self._rip_fields(op.reg_index, op.disp, permute_register=True)
            order = mem_permuted_fields(True, self.field_perm)
        elif op.kind.endswith("idx"):
            fields = self._indexed_fields(
                (op.reg_index, op.base_index, op.index_index, op.scale, op.disp),
                permute_register=True,
            )
            order = idx_permuted_fields(False, self.field_perm)
        else:
            fields = self._base_fields(op.reg_index, op.base_index, op.disp, permute_register=True)
            order = mem_permuted_fields(False, self.field_perm)
        self._emit_fields(position, order, fields)
        return True

    def _emit_gp(self, op: VirtualizedOp) -> None:
        position = self._opcode(op.mnemonic, op.width, op.is_immediate)
        if op.is_immediate:
            fields = {"dst": bytes([self.slot_of[op.dst_index]]), "imm": pack_immediate(op.value, op.width)}
        else:
            fields = {"dst": bytes([self.slot_of[op.dst_index]]), "src": bytes([self.slot_of[op.value]])}
        self._emit_fields(
            position,
            op_permuted_fields(op.is_immediate, op.width, self.field_perm),
            fields,
        )

    def _opcode(self, kind: str, width: int, immediate: bool = False) -> int:
        return self._emit_opcode(self.pick(self.scheme.dup[(kind, immediate, width)]))

    def _rip_fields(self, register: int, disp: int, *, permute_register: bool = False) -> dict[str, bytes]:
        reg = self.slot_of[register] if permute_register else register
        return {"reg": bytes([reg]), "disp": struct.pack("<i", disp - self.bytecode_base)}

    def _base_fields(
        self,
        register: int,
        base: int,
        disp: int,
        *,
        permute_register: bool = False,
    ) -> dict[str, bytes]:
        reg = self.slot_of[register] if permute_register else register
        return {
            "reg": bytes([reg]),
            "base": bytes([self.slot_of[base]]),
            "disp": struct.pack("<i", disp),
        }

    def _indexed_fields(
        self,
        operands: tuple[int, int, int, int, int],
        *,
        permute_register: bool = False,
    ) -> dict[str, bytes]:
        register, base, index, scale, disp = operands
        fields = self._base_fields(register, base, disp, permute_register=permute_register)
        fields.update({"index": bytes([self.slot_of[index]]), "shift": bytes([scale])})
        return fields

    def _indexed_no_base_fields(
        self,
        operands: tuple[int, int, int, int],
    ) -> dict[str, bytes]:
        register, index, scale, disp = operands
        fields = {
            "reg": bytes([register]),
            "index": bytes([self.slot_of[index]]),
            "shift": bytes([scale]),
            "disp": struct.pack("<i", disp),
        }
        return fields


def encode_bytecode(
    ops: list[EngineOp],
    scheme: VMScheme,
    checksum: int = 0,
    bytecode_base: int = 0,
) -> bytes:
    """Serialize operations to position-masked, checksum-encrypted bytecode."""
    return _BytecodeEncoder(scheme, checksum, bytecode_base).encode(ops)
