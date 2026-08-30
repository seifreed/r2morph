"""Instruction-handler assembly for the engine VM."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_engine_common import (
    _DWORD_BROADCAST,
    _FP_ARITH_KINDS,
    _FP_ARITH_MEM_KINDS,
    _FP_CONVERT_KINDS,
    _FP_MEM_KINDS,
    _FP_PACKED_ARITH_KINDS,
    _FP_PACKED_MEM_KINDS,
    _FP_PACKED_VEX_ARITH_KINDS,
    _FP_PACKED_VEX_OPERATIONS,
    _FP_SCALAR_VEX_ARITH_KINDS,
    _FP_SCALAR_VEX_OPERATIONS,
    _MEM_OP_KINDS,
    _MICROOP_BINOP_KINDS,
    _MICROOP_IMM_KINDS,
    _MICROOP_STACK_KINDS,
    _QWORD_BROADCAST,
    _SHIFT_KINDS,
    VMScheme,
)
from r2morph.mutations.code_virtualization_engine_frame import FrameLayout
from r2morph.mutations.code_virtualization_engine_isa import EngineISASpec
from r2morph.mutations.code_virtualization_engine_microops import MicroopHandlerConfig, microop_handler_body
from r2morph.mutations.code_virtualization_fold import addr_fold, arith_fold
from r2morph.mutations.code_virtualization_layout import (
    idx_offsets,
    mem_offsets,
    op_offsets,
    pair_offsets,
    triple_offsets,
)

_DWORD_WIDTH_BITS = 32
_QWORD_WIDTH_BITS = 64


def _byte_field_load(register: str, offset: int, variant: int) -> str:
    if variant & 2:
        return f"  mov {register}d, 0\n  mov {register}b, byte ptr [rsi+{offset}]\n"
    return f"  movzx {register}d, byte ptr [rsi+{offset}]\n"


class EngineHandlerGenerator:
    """Generate handlers against one scheme, frame layout, and ISA personality."""

    def __init__(self, scheme: VMScheme, layout: FrameLayout, isa: EngineISASpec) -> None:
        self.scheme = scheme
        self.layout = layout
        self.isa = isa
        self.key = f"byte ptr [rsp + {layout.checksum_offset}]"
        self.key_qword = f"qword ptr [rsp + {layout.key_qword_offset}]"
        self.key_dword = f"dword ptr [rsp + {layout.key_dword_offset}]"
        self.record_padding = 0
        self.advance_variant = 0
        self.handler_index = 0

    def handler_body(
        self,
        mnemonic: str,
        is_immediate: bool,
        width: int,
        arith_variant: int,
        body_variant: int = 0,
    ) -> str:
        self.advance_variant = body_variant & 2
        if mnemonic in _MICROOP_STACK_KINDS or mnemonic in _MICROOP_BINOP_KINDS or mnemonic in _MICROOP_IMM_KINDS:
            return microop_handler_body(
                mnemonic,
                width,
                MicroopHandlerConfig(
                    self.key,
                    self.key_dword,
                    self.key_qword,
                    self.layout.vsp_offset,
                    self.layout.vstack_base,
                    arith_variant,
                    self.record_padding,
                    self.advance_variant,
                ),
            )
        fp_body = self._fp_handler_body(mnemonic, width)
        if fp_body is not None:
            return fp_body
        if mnemonic in _MEM_OP_KINDS:
            return self._mem_handler_body(mnemonic, width, arith_variant)
        return self._gp_handler_body(mnemonic, is_immediate, width, body_variant)

    def set_record_padding(self, record_padding: int) -> None:
        self.record_padding = record_padding

    def _advance(self, base: int) -> str:
        amount = base + self.record_padding
        if self.advance_variant:
            return f"  lea rsi, [rsi + {amount}]\n"
        return f"  add rsi, {amount}\n"

    def _gp_handler_body(self, mnemonic: str, is_immediate: bool, width: int, body_variant: int = 0) -> str:
        off = op_offsets(is_immediate, width, self.scheme.field_perm)
        decrypt_dst = _byte_field_load("r8", off["dst"], body_variant) + f"  xor r8b, {self.key}\n  xor r8b, r13b\n"
        if is_immediate and width == _QWORD_WIDTH_BITS:
            load = (
                f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {self.key_qword}\n  xor rax, r10\n"
                f"  movzx r10, r13b\n  mov r11, {hex(_QWORD_BROADCAST)}\n  imul r10, r11\n  xor rax, r10\n"
            )
            advance = 10
        elif is_immediate:
            load = (
                f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {self.key_dword}\n  xor eax, r11d\n"
                f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            )
            advance = 6
        else:
            load = _byte_field_load("r9", off["src"], body_variant) + f"  xor r9b, {self.key}\n  xor r9b, r13b\n"
            load += (
                "  mov rax, qword ptr [rsp + r9*8]\n"
                if width == _QWORD_WIDTH_BITS
                else "  mov eax, dword ptr [rsp + r9*8]\n"
            )
            advance = 3
        apply = self._shift_body(mnemonic, width) if mnemonic in _SHIFT_KINDS else "  mov qword ptr [rsp + r8*8], rax\n"
        ordered_prefix = load + decrypt_dst if body_variant & 1 else decrypt_dst + load
        return ordered_prefix + apply + self._advance(advance) + "  jmp vm_dispatch\n"

    @staticmethod
    def _shift_body(mnemonic: str, width: int) -> str:
        register = "r10" if width == _QWORD_WIDTH_BITS else "r10d"
        load = (
            "  mov r10, qword ptr [rsp + r8*8]\n"
            if width == _QWORD_WIDTH_BITS
            else "  mov r10d, dword ptr [rsp + r8*8]\n"
        )
        store = (
            "  mov qword ptr [rsp + r8*8], r10\n"
            if width == _QWORD_WIDTH_BITS
            else "  mov r10d, r10d\n  mov qword ptr [rsp + r8*8], r10\n"
        )
        return f"  mov ecx, eax\n{load}  {mnemonic} {register}, cl\n{store}"

    def _mem_addr_prologue(self) -> str:
        off = mem_offsets(False, self.scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {self.key}\n  xor r9b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {self.key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r9*8]\n" + addr_fold("rax", "rcx", 0, self.isa.addr_variant)
        )

    def _mem_riprel_prologue(self) -> str:
        off = mem_offsets(True, self.scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {self.key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, r15\n" + addr_fold("rax", "rcx", 0, self.isa.addr_variant)
        )

    def _mem_idx_prologue(self) -> str:
        off = idx_offsets(False, self.scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {self.key}\n  xor r9b, r13b\n"
            f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {self.key}\n  xor r11b, r13b\n"
            f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {self.key}\n  xor cl, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {self.key_dword}\n  xor eax, r10d\n"
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r11*8]\n  shl r10, cl\n"
            "  mov r11, qword ptr [rsp + r9*8]\n"
            + addr_fold("r11", "rcx", 0, self.isa.addr_variant)
            + addr_fold("rax", "rcx", 0, self.isa.addr_variant)
        )

    def _mem_idx_no_base_prologue(self) -> str:
        off = idx_offsets(True, self.scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['index']}]\n  xor r9b, {self.key}\n  xor r9b, r13b\n"
            f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {self.key}\n  xor cl, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {self.key_dword}\n  xor eax, r10d\n"
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r9*8]\n  shl r10, cl\n"
            + addr_fold("rax", "rcx", 0, self.isa.addr_variant)
        )

    def _mem_handler_body(self, kind: str, width: int, arith_variant: int) -> str:
        if kind.endswith("rip"):
            kind, body, advance = kind[: -len("rip")], self._mem_riprel_prologue(), 6
        elif kind.endswith("idxnb"):
            kind, body, advance = kind[: -len("idxnb")], self._mem_idx_no_base_prologue(), 8
        elif kind.endswith("idx"):
            kind, body, advance = kind[: -len("idx")], self._mem_idx_prologue(), 9
        else:
            body, advance = self._mem_addr_prologue(), 7
        body += self._mem_transfer_body(kind, width, arith_variant)
        return body + self._advance(advance) + "  jmp vm_dispatch\n"

    @staticmethod
    def _mem_transfer_body(kind: str, width: int, arith_variant: int) -> str:
        if kind == "load":
            load = "  mov rax, qword ptr [r10]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [r10]\n"
            return load + "  mov qword ptr [rsp + r8*8], rax\n"
        if kind == "store":
            return (
                "  mov rax, qword ptr [rsp + r8*8]\n  mov qword ptr [r10], rax\n"
                if width == _QWORD_WIDTH_BITS
                else "  mov eax, dword ptr [rsp + r8*8]\n  mov dword ptr [r10], eax\n"
            )
        if kind == "lea":
            normalize = "  mov r10d, r10d\n" if width == _DWORD_WIDTH_BITS else ""
            return normalize + "  mov qword ptr [rsp + r8*8], r10\n"
        if kind.startswith(("movzx", "movsx")):
            return EngineHandlerGenerator._extend_memory_body(kind, width)
        mnemonic = kind[len("mem") :]
        body = "  mov rax, qword ptr [r10]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [r10]\n"
        if mnemonic == "sub":
            body += "  neg rax\n"
        body += (
            "  mov r10, qword ptr [rsp + r8*8]\n"
            if width == _QWORD_WIDTH_BITS
            else "  mov r10d, dword ptr [rsp + r8*8]\n"
        )
        body += arith_fold(mnemonic, 0, arith_variant)
        store = (
            "  mov qword ptr [rsp + r8*8], r10\n"
            if width == _QWORD_WIDTH_BITS
            else "  mov r10d, r10d\n  mov qword ptr [rsp + r8*8], r10\n"
        )
        return body + store

    @staticmethod
    def _extend_memory_body(kind: str, width: int) -> str:
        size_word = "byte" if kind.endswith("b") else "word"
        if kind.startswith("movzx"):
            body = f"  movzx eax, {size_word} ptr [r10]\n"
        elif width == _QWORD_WIDTH_BITS:
            body = f"  movsx rax, {size_word} ptr [r10]\n"
        else:
            body = f"  movsx eax, {size_word} ptr [r10]\n"
        return body + "  mov qword ptr [rsp + r8*8], rax\n"

    def _fp_base_addr_prologue(self) -> str:
        return self._mem_addr_prologue() + (f"  shl r8, 4\n  lea r11, [rsp + r8 + {self.layout.xmm_offset}]\n")

    def _fp_riprel_addr_prologue(self) -> str:
        return self._mem_riprel_prologue() + (f"  shl r8, 4\n  lea r11, [rsp + r8 + {self.layout.xmm_offset}]\n")

    def _fp_idx_addr_prologue(self) -> str:
        return self._mem_idx_prologue() + (f"  shl r8, 4\n  lea r11, [rsp + r8 + {self.layout.xmm_offset}]\n")

    def _fp_idx_no_base_addr_prologue(self) -> str:
        off = idx_offsets(True, self.scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['index']}]\n  xor r9b, {self.key}\n  xor r9b, r13b\n"
            f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {self.key}\n  xor cl, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {self.key_dword}\n  xor eax, r10d\n"
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r9*8]\n  shl r10, cl\n"
            + addr_fold("rax", "r11", 0, self.isa.addr_variant)
            + f"  shl r8, 4\n  lea r11, [rsp + r8 + {self.layout.xmm_offset}]\n"
        )

    def _fp_address(self, kind: str) -> tuple[str, str, int]:
        if kind.endswith("idxnb"):
            return kind[: -len("idxnb")], self._fp_idx_no_base_addr_prologue(), 8
        if kind.endswith("idx"):
            return kind[: -len("idx")], self._fp_idx_addr_prologue(), 9
        if kind.endswith("rip"):
            return kind[: -len("rip")], self._fp_riprel_addr_prologue(), 6
        return kind, self._fp_base_addr_prologue(), 7

    def _fp_mem_handler_body(self, kind: str, width: int) -> str:
        move = "movsd" if width == _QWORD_WIDTH_BITS else "movss"
        kind, body, advance = self._fp_address(kind)
        if kind == "fpload":
            body += f"  {move} xmm0, [r10]\n  movups xmmword ptr [r11], xmm0\n"
        else:
            body += f"  movups xmm0, xmmword ptr [r11]\n  {move} [r10], xmm0\n"
        return body + self._advance(advance) + "  jmp vm_dispatch\n"

    def _fp_arith_mem_handler_body(self, kind: str, width: int) -> str:
        suffix = "sd" if width == _QWORD_WIDTH_BITS else "ss"
        kind, body, advance = self._fp_address(kind)
        operation = kind[len("fparithmem") :]
        body += (
            f"  movups xmm0, xmmword ptr [r11]\n  {operation}{suffix} xmm0, [r10]\n"
            "  movups xmmword ptr [r11], xmm0\n"
        )
        return body + self._advance(advance) + "  jmp vm_dispatch\n"

    def _fp_arith_handler_body(self, kind: str, width: int) -> str:
        operation = kind[len("fp") :]
        suffix = "sd" if width == _QWORD_WIDTH_BITS else "ss"
        return (
            self._fp_pair_prologue()
            + (
                "  movups xmm0, xmmword ptr [r10]\n  movups xmm1, xmmword ptr [r11]\n"
                f"  {operation}{suffix} xmm0, xmm1\n  movups xmmword ptr [r10], xmm0\n"
            )
            + self._advance(3)
            + "  jmp vm_dispatch\n"
        )

    def _fp_pair_prologue(self) -> str:
        off = pair_offsets("dst", "src", self.scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {self.key}\n  xor r9b, r13b\n"
            f"  shl r8, 4\n  lea r10, [rsp + r8 + {self.layout.xmm_offset}]\n"
            f"  shl r9, 4\n  lea r11, [rsp + r9 + {self.layout.xmm_offset}]\n"
        )

    def _fp_convert_handler_body(self, kind: str, fp_width: int) -> str:
        direction, gp_width = kind[:6], int(kind[6:])
        off = pair_offsets("xmm", "gp", self.scheme.field_perm)
        suffix = "sd" if fp_width == _QWORD_WIDTH_BITS else "ss"
        body = (
            f"  movzx r8d, byte ptr [rsi+{off['xmm']}]\n  xor r8b, {self.key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['gp']}]\n  xor r9b, {self.key}\n  xor r9b, r13b\n"
            f"  shl r8, 4\n  lea r10, [rsp + r8 + {self.layout.xmm_offset}]\n"
            "  movups xmm0, xmmword ptr [r10]\n"
        )
        if direction == "cvti2f":
            source = "rax" if gp_width == _QWORD_WIDTH_BITS else "eax"
            body += f"  mov {source}, {'qword' if gp_width == _QWORD_WIDTH_BITS else 'dword'} ptr [rsp + r9*8]\n"
            body += f"  cvtsi2{suffix} xmm0, {source}\n  movups xmmword ptr [r10], xmm0\n"
        else:
            target = "rax" if gp_width == _QWORD_WIDTH_BITS else "eax"
            body += f"  cvtt{suffix}2si {target}, xmm0\n  mov qword ptr [rsp + r9*8], rax\n"
        return body + self._advance(3) + "  jmp vm_dispatch\n"

    def _fp_packed_arith_handler_body(self, mnemonic: str) -> str:
        return (
            self._fp_pair_prologue()
            + (
                "  movups xmm0, xmmword ptr [r10]\n  movups xmm1, xmmword ptr [r11]\n"
                f"  {mnemonic} xmm0, xmm1\n  movups xmmword ptr [r10], xmm0\n"
            )
            + self._advance(3)
            + "  jmp vm_dispatch\n"
        )

    def _fp_scalar_vex_arith_handler_body(self, handler_index: int) -> str:
        off = triple_offsets("dst", "src1", "src2", self.scheme.field_perm)
        fields = "".join(
            f"  movzx {register}d, byte ptr [rsi+{off[field]}]\n"
            f"  xor {register}b, {self.key}\n"
            f"  xor {register}b, r13b\n"
            for register, field in (("r8", "dst"), ("r9", "src1"), ("r10", "src2"))
        )
        selector = "  movzx ecx, byte ptr [rsi+4]\n" f"  xor cl, {self.key}\n  xor cl, r13b\n" + "".join(
            f"  cmp ecx, {index}\n  je fparithvex_{handler_index}_{index}\n"
            for index, _operation in enumerate(_FP_SCALAR_VEX_OPERATIONS)
        )
        operation_body = "".join(
            f"fparithvex_{handler_index}_{index}:\n"
            f"  {_operation} xmm0, xmm0, xmm1\n"
            f"  jmp fparithvex_done_{handler_index}\n"
            for index, _operation in enumerate(_FP_SCALAR_VEX_OPERATIONS)
        )
        return (
            fields
            + "  shl r8, 4\n  shl r9, 4\n  shl r10, 4\n"
            + f"  movups xmm0, [rsp + r9 + {self.layout.xmm_offset}]\n"
            + f"  movups xmm1, [rsp + r10 + {self.layout.xmm_offset}]\n"
            + selector
            + operation_body
            + f"fparithvex_done_{handler_index}:\n"
            + f"  movups [rsp + r8 + {self.layout.xmm_offset}], xmm0\n"
            + self._advance(5)
            + "  jmp vm_dispatch\n"
        )

    def _fp_packed_vex_arith_handler_body(self, handler_index: int) -> str:
        off = triple_offsets("dst", "src1", "src2", self.scheme.field_perm)
        fields = "".join(
            f"  movzx {register}d, byte ptr [rsi+{off[field]}]\n"
            f"  xor {register}b, {self.key}\n"
            f"  xor {register}b, r13b\n"
            for register, field in (("r8", "dst"), ("r9", "src1"), ("r10", "src2"))
        )
        selector = "  movzx ecx, byte ptr [rsi+4]\n" f"  xor cl, {self.key}\n  xor cl, r13b\n" + "".join(
            f"  cmp ecx, {index}\n  je fppackedvex_{handler_index}_{index}\n"
            for index, _operation in enumerate(_FP_PACKED_VEX_OPERATIONS)
        )
        operation_body = "".join(
            f"fppackedvex_{handler_index}_{index}:\n"
            f"  {_operation} xmm0, xmm0, xmm1\n"
            f"  jmp fppackedvex_done_{handler_index}\n"
            for index, _operation in enumerate(_FP_PACKED_VEX_OPERATIONS)
        )
        return (
            fields
            + "  shl r8, 4\n  shl r9, 4\n  shl r10, 4\n"
            + f"  movups xmm0, [rsp + r9 + {self.layout.xmm_offset}]\n"
            + f"  movups xmm1, [rsp + r10 + {self.layout.xmm_offset}]\n"
            + selector
            + operation_body
            + f"fppackedvex_done_{handler_index}:\n"
            + f"  movups [rsp + r8 + {self.layout.xmm_offset}], xmm0\n"
            + self._advance(5)
            + "  jmp vm_dispatch\n"
        )

    def _fp_packed_mem_handler_body(self, kind: str) -> str:
        body = self._fp_base_addr_prologue()
        if kind == "fppload":
            body += "  movups xmm0, xmmword ptr [r10]\n  movups xmmword ptr [r11], xmm0\n"
        else:
            body += "  movups xmm0, xmmword ptr [r11]\n  movups xmmword ptr [r10], xmm0\n"
        return body + self._advance(7) + "  jmp vm_dispatch\n"

    def _fp_handler_body(self, mnemonic: str, width: int) -> str | None:
        body = None
        if mnemonic in _FP_SCALAR_VEX_ARITH_KINDS:
            body = self._fp_scalar_vex_arith_handler_body(self.handler_index)
        elif mnemonic in _FP_PACKED_VEX_ARITH_KINDS:
            body = self._fp_packed_vex_arith_handler_body(self.handler_index)
        elif mnemonic in _FP_PACKED_ARITH_KINDS:
            body = self._fp_packed_arith_handler_body(mnemonic)
        elif mnemonic in _FP_PACKED_MEM_KINDS:
            body = self._fp_packed_mem_handler_body(mnemonic)
        elif mnemonic in _FP_ARITH_MEM_KINDS:
            body = self._fp_arith_mem_handler_body(mnemonic, width)
        elif mnemonic in _FP_CONVERT_KINDS:
            body = self._fp_convert_handler_body(mnemonic, width)
        elif mnemonic in _FP_ARITH_KINDS:
            body = self._fp_arith_handler_body(mnemonic, width)
        elif mnemonic in _FP_MEM_KINDS:
            body = self._fp_mem_handler_body(mnemonic, width)
        return body
