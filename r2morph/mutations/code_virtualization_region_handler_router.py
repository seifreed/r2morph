"""Handler-key routing for the region VM code generator."""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.mutations.code_virtualization_region_control_handlers import (
    CallBridgeConfig,
    CallMemoryHandlerConfig,
    VRetHandlerConfig,
    _call_handler_asm,
    _call_mem_handler_asm,
    _call_mem_idx_handler_asm,
    _cmov_handler_asm,
    _icall_handler_asm,
    _ijmp_handler_asm,
    _ijmpmem_handler_asm,
    _ijmpmemnb_handler_asm,
    _jcc_handler_asm,
    _movx_reg_handler_asm,
    _rdtsc_handler_asm,
    _setcc_handler_asm,
    _syscall_handler_asm,
    _vcall_handler_asm,
    _vret_handler_asm,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    _fp_packed_shift_immediate_handler_asm,
)
from r2morph.mutations.code_virtualization_region_handler_router_fp import FPHandlerRouterMixin
from r2morph.mutations.code_virtualization_region_handlers import (
    _GUARD,
    IntegerHandlerConfig,
    _bswap_handler_asm,
    _bt_handler_asm,
    _compare_handler_asm,
    _cqo_handler_asm,
    _div_handler_asm,
    _imul3_handler_asm,
    _imul_handler_asm,
    _incdec_handler_asm,
    _leave_handler_asm,
    _mov_from_rsp_handler_asm,
    _mov_to_rsp_handler_asm,
    _not_handler_asm,
    _op_handler_asm,
    _op_mba_handler_asm,
    _op_synth_handler_asm,
    _pop_handler_asm,
    _push_handler_asm,
    _pushi_handler_asm,
    _rspadj_handler_asm,
    _shift_handler_asm,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    AtomicMemoryOperationConfig,
    DivisionMemoryOperationConfig,
    MemoryImmediateOperationConfig,
    MemoryOperationConfig,
    _atomic_memory_rmw_handler_asm,
    _bt_memory_handler_asm,
    _cmp_memory_handler_asm,
    _cmpxchg_memory_handler_asm,
    _div_memory_handler_asm,
    _lea_handler_asm,
    _lea_indexed_handler_asm,
    _lea_indexed_nobase_handler_asm,
    _memory_handler_asm,
    _memory_immediate_handler_asm,
    _movx_handler_asm,
    _movx_indexed_handler_asm,
    _not_memory_handler_asm,
    _op_mem_indexed_handler_asm,
    _op_memdst_handler_asm,
    _op_memory_handler_asm,
    _riprel_handler_asm,
    _tls_memory_handler_asm,
    _xchg_memory_handler_asm,
    _xchg_memory_indexed_handler_asm,
)
from r2morph.mutations.code_virtualization_region_microops import (
    _frestore_handler_asm,
    _fsave_handler_asm,
    _vbinop_handler_asm,
    _vbinopsynth_handler_asm,
    _vcmpsynth_handler_asm,
    _vlea_handler_asm,
    _vleaidx_handler_asm,
    _vleaidxnb_handler_asm,
    _vload_handler_asm,
    _vloadidx_handler_asm,
    _vloadrip_handler_asm,
    _vmovx_handler_asm,
    _vmovxidx_handler_asm,
    _vpop_handler_asm,
    _vpop_partial_handler_asm,
    _vpush_handler_asm,
    _vpushi_handler_asm,
    _vshift_handler_asm,
    _vshiftreg_handler_asm,
    _vstore_handler_asm,
    _vstoreidx_handler_asm,
    _vstorerip_handler_asm,
)
from r2morph.mutations.code_virtualization_region_push import _pop_memory_handler_asm, _push_memory_handler_asm

_VRET_CLEANUP_INDEX = 2


@dataclass(frozen=True)
class HandlerContext:
    key: str
    key_qword: str
    key_dword: str
    rsp_off: int
    reload_seq: str
    retarget: str
    retarget_target: str
    frame_size: int
    slot: tuple[int, ...]
    bytecode_len: int = 0
    field_perm: int = 0
    body_seed: int = 0
    isa_seed: int = 0
    flags_offset: int = 0x80
    has_ymm: bool = False
    has_internal_indirect_call: bool = False
    stack_guard: int = _GUARD


class HandlerBodyRouter(FPHandlerRouterMixin):
    def __init__(self, context: HandlerContext) -> None:
        self.context = context

    def body(self, handler_key: str, index: int, variants: tuple[int, int, int, int, int]) -> str:
        flag, arithmetic, compare, shift, address = variants
        routes = (
            self._calls,
            self._branches,
            self._microop_stack,
            self._microop_memory,
            self._integer_arithmetic,
            self._integer_misc,
            self._tls_memory,
            self._atomic_memory,
            self._memory_immediate,
            self._div_memory,
            self._stack_memory,
            self._memory,
            self._fp_immediate,
            self._fp_vex,
            self._fp,
        )
        for route in routes:
            body = route(handler_key, index, (flag, arithmetic, compare, shift, address))
            if body is not None:
                return body
        raise ValueError(f"No VM handler is registered for {handler_key!r}")

    def _fp_immediate(self, key: str, _index: int, _variants: tuple[int, ...]) -> str | None:
        if key.startswith("fppackedimm_"):
            return _fp_packed_shift_immediate_handler_asm(key, self.context.key, self.context.field_perm)
        return None

    def _calls(self, key: str, index: int, variants: tuple[int, ...]) -> str | None:
        address = variants[4]
        stack_depth = (
            int(key.rsplit("_", 1)[1])
            if key.startswith(("call_", "icall_", "callmem_", "callmemrip_", "callmemidx_", "callmemidxnb_"))
            else 0
        )
        body = None
        if key.startswith("call_"):
            body = _call_handler_asm(
                index,
                self.context.key_dword,
                self.context.slot,
                CallBridgeConfig(
                    self.context.frame_size,
                    self.context.flags_offset,
                    stack_depth,
                    self.context.has_ymm,
                    stack_guard=self.context.stack_guard,
                ),
            )
        elif key.startswith("icall_"):
            body = _icall_handler_asm(
                index,
                self.context.key,
                self.context.slot,
                CallBridgeConfig(
                    self.context.frame_size,
                    self.context.flags_offset,
                    stack_depth,
                    self.context.has_ymm,
                    stack_guard=self.context.stack_guard,
                ),
                self.context.has_internal_indirect_call,
            )
        elif key.startswith(("callmem_", "callmemrip_")):
            config = CallMemoryHandlerConfig(
                index,
                self.context.key,
                self.context.key_dword,
                self.context.slot,
                self.context.field_perm,
                address,
                self.context.frame_size,
                self.context.flags_offset,
                stack_depth,
                self.context.has_ymm,
                self.context.stack_guard,
            )
            body = _call_mem_handler_asm(
                config,
                key.startswith("callmemrip_"),
                self.context.has_internal_indirect_call,
            )
        elif key.startswith(("callmemidx_", "callmemidxnb_")):
            config = CallMemoryHandlerConfig(
                index,
                self.context.key,
                self.context.key_dword,
                self.context.slot,
                self.context.field_perm,
                address,
                self.context.frame_size,
                self.context.flags_offset,
                stack_depth,
                self.context.has_ymm,
                self.context.stack_guard,
            )
            body = _call_mem_idx_handler_asm(
                config,
                key.startswith("callmemidxnb_"),
                self.context.has_internal_indirect_call,
            )
        elif key == "vcall":
            body = _vcall_handler_asm(self.context.retarget_target, self.context.rsp_off)
        elif key == "syscall":
            body = _syscall_handler_asm(self.context.slot)
        elif key == "rdtsc":
            body = _rdtsc_handler_asm(self.context.slot)
        return body

    def _branches(self, key: str, index: int, variants: tuple[int, ...]) -> str | None:
        address = variants[4]
        body = None
        if key == "jmp":
            body = self.context.retarget
        elif key == "ijmp":
            body = _ijmp_handler_asm(index, self.context.key)
        elif key == "ijmpmem":
            body = _ijmpmem_handler_asm(
                index,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key == "ijmpmemnb":
            body = _ijmpmemnb_handler_asm(
                index,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith("jcc_"):
            body = _jcc_handler_asm(key.split("_", 1)[1], self.context.retarget_target)
        elif key.startswith("setcc_"):
            body = _setcc_handler_asm(key.split("_", 1)[1], self.context.key)
        elif key.startswith("cmov_"):
            _, condition, width = key.split("_")
            body = _cmov_handler_asm(condition, int(width), self.context.key)
        elif key == "nop":
            body = "  add rsi, 1\n  jmp vm_dispatch\n"
        elif key.startswith("vret_"):
            parts = key.split("_")
            ret_addr = int(parts[1])
            stack_cleanup = int(parts[_VRET_CLEANUP_INDEX]) if len(parts) > _VRET_CLEANUP_INDEX else 0
            body = _vret_handler_asm(
                VRetHandlerConfig(
                    index,
                    ret_addr,
                    self.context.rsp_off,
                    self.context.bytecode_len,
                    self.context.reload_seq,
                    self.context.frame_size,
                    stack_cleanup,
                )
            )
        elif key.startswith("exit_"):
            exit_addr = int(key.split("_", 1)[1])
            body = f"{self.context.reload_seq}  add rsp, {self.context.frame_size}\n  jmp {hex(exit_addr)}\n"
        return body

    def _microop_stack(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        flag, arithmetic, compare, shift, _address = variants
        body = None
        if key == "vpush":
            body = _vpush_handler_asm(self.context.key)
        elif key == "vpop":
            body = _vpop_handler_asm(self.context.key)
        elif key in ("vpop8", "vpop16"):
            body = _vpop_partial_handler_asm(key, self.context.key)
        elif key == "fsave":
            body = _fsave_handler_asm()
        elif key == "frestore":
            body = _frestore_handler_asm()
        elif key.startswith("vpushi_"):
            body = _vpushi_handler_asm(key, self.context.key_qword, self.context.key_dword)
        elif key.startswith("vcmpsynth_"):
            body = _vcmpsynth_handler_asm(key, self.context.key, flag, arithmetic, compare)
        elif key.startswith("vbinopsynth_"):
            body = _vbinopsynth_handler_asm(key, self.context.key, flag, arithmetic)
        elif key.startswith("vbinop_"):
            body = _vbinop_handler_asm(key, self.context.key, arithmetic)
        elif key.startswith("vshift_"):
            body = _vshift_handler_asm(key, self.context.key, shift)
        elif key.startswith("vshiftreg_"):
            body = _vshiftreg_handler_asm(key, self.context.key)
        return body

    def _microop_memory(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        address = variants[4]
        arguments = (key, self.context.key, self.context.key_dword, self.context.field_perm, address)
        body = None
        if key.startswith(("vloadidx_", "vloadidxnb_")):
            body = _vloadidx_handler_asm(*arguments)
        elif key.startswith(("vstoreidx_", "vstoreidxnb_")):
            body = _vstoreidx_handler_asm(*arguments)
        elif key.startswith("vload_"):
            body = _vload_handler_asm(*arguments)
        elif key.startswith("vstore_"):
            body = _vstore_handler_asm(*arguments)
        elif key.startswith("vloadrip_"):
            body = _vloadrip_handler_asm(*arguments)
        elif key.startswith("vstorerip_"):
            body = _vstorerip_handler_asm(*arguments)
        elif key.startswith("vleaidxnb_"):
            body = _vleaidxnb_handler_asm(*arguments)
        elif key.startswith("vleaidx_"):
            body = _vleaidx_handler_asm(*arguments)
        elif key.startswith(("vlea_", "vlearip_")):
            body = _vlea_handler_asm(*arguments)
        elif key.startswith("vmovxidx_"):
            body = _vmovxidx_handler_asm(*arguments)
        elif key.startswith("vmovx_"):
            body = _vmovx_handler_asm(*arguments)
        return body

    def _integer_arithmetic(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        flag, arithmetic, compare, shift, _address = variants
        config = IntegerHandlerConfig(
            key,
            self.context.key,
            self.context.key_qword,
            self.context.key_dword,
            self.context.field_perm,
            flag,
            arithmetic,
            compare,
        )
        body = None
        if key.startswith("opsynth_"):
            body = _op_synth_handler_asm(config)
        elif key.startswith("opmba_"):
            body = _op_mba_handler_asm(config)
        elif key.startswith("op_"):
            body = _op_handler_asm(
                key,
                self.context.key,
                self.context.key_qword,
                self.context.key_dword,
                self.context.field_perm,
            )
        elif key.startswith(("cmp_", "test_")):
            body = _compare_handler_asm(config)
        elif key.startswith(("shl_", "shr_", "sar_")):
            body = _shift_handler_asm(key, self.context.key, self.context.field_perm, shift)
        elif key.startswith("imul3_"):
            body = _imul3_handler_asm(key, self.context.key, self.context.key_dword, self.context.field_perm)
        elif key.startswith("imul_"):
            body = _imul_handler_asm(key, self.context.key, self.context.field_perm)
        elif key.startswith("incdec_"):
            body = _incdec_handler_asm(key, self.context.key, flag, arithmetic)
        return body

    def _integer_misc(self, key: str, _index: int, _variants: tuple[int, ...]) -> str | None:
        body = None
        if key.startswith("push_"):
            body = _push_handler_asm(self.context.key, self.context.rsp_off)
        elif key.startswith("pop_"):
            body = _pop_handler_asm(self.context.key, self.context.rsp_off)
        elif key == "pushi":
            body = _pushi_handler_asm(self.context.key_qword, self.context.rsp_off)
        elif key.startswith("rspadj_"):
            body = _rspadj_handler_asm(key, self.context.key_dword, self.context.rsp_off)
        elif key == "movfromrsp":
            body = _mov_from_rsp_handler_asm(self.context.key, self.context.rsp_off)
        elif key == "movtorsp":
            body = _mov_to_rsp_handler_asm(self.context.key, self.context.rsp_off)
        elif key == "leave":
            body = _leave_handler_asm(self.context.key, self.context.rsp_off)
        elif key.startswith("not_"):
            body = _not_handler_asm(key, self.context.key)
        elif key.startswith("bswap_"):
            body = _bswap_handler_asm(key, self.context.key)
        elif key.startswith("div_"):
            body = _div_handler_asm(key, self.context.key)
        elif key.startswith("cqo_"):
            body = _cqo_handler_asm(key, self.context.key)
        elif key.startswith("bt_"):
            body = _bt_handler_asm(key, self.context.key)
        return body

    def _memory(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        flag, arithmetic, compare, _shift, address = variants
        config = MemoryOperationConfig(
            key,
            self.context.key,
            self.context.key_dword,
            self.context.field_perm,
            flag,
            arithmetic,
            compare,
            address,
        )
        body = None
        if key.startswith(("cmpmem_", "cmpriprel_")):
            body = _cmp_memory_handler_asm(config)
        elif key.startswith(("opmemdst_", "opmemdstrip_")):
            body = _op_memdst_handler_asm(config)
        elif key.startswith(("opmem_", "opriprel_")):
            body = _op_memory_handler_asm(config)
        elif key.startswith("leaidxnb_"):
            body = _lea_indexed_nobase_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith("leaidx_"):
            body = _lea_indexed_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith(("lea_", "learip_")):
            body = _lea_handler_asm(key, self.context.key, self.context.key_dword, self.context.field_perm, address)
        elif key.startswith("opmemidx_"):
            body = _op_mem_indexed_handler_asm(config)
        elif key.startswith("movxreg_"):
            body = _movx_reg_handler_asm(key, self.context.key)
        elif key.startswith("movxidx_"):
            body = _movx_indexed_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith("movx_"):
            body = _movx_handler_asm(key, self.context.key, self.context.key_dword, self.context.field_perm, address)
        elif key.startswith(("riprel_load_", "riprel_store_")):
            body = _riprel_handler_asm(key, self.context.key, self.context.key_dword, self.context.field_perm, address)
        elif key.startswith(("btmem_", "notmem_", "notmemrip_", "notmemidx_", "notmemidxnb_", "load_", "store_")):
            handler = next(
                (
                    handler
                    for prefix, handler in (("btmem", _bt_memory_handler_asm), ("notmem", _not_memory_handler_asm))
                    if key.startswith(prefix)
                ),
                _memory_handler_asm,
            )
            body = handler(key, self.context.key, self.context.key_dword, self.context.field_perm, address)
        return body

    def _stack_memory(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        if key.startswith(("pushmem_", "pushmemrip_", "pushmemidx_", "pushmemidxnb_")):
            return _push_memory_handler_asm(
                key,
                (self.context.key, self.context.key_dword),
                self.context.field_perm,
                variants[4],
                self.context.rsp_off,
            )
        if not key.startswith(("popmem_", "popmemrip_", "popmemidx_", "popmemidxnb_")):
            return None
        return _pop_memory_handler_asm(
            key,
            (self.context.key, self.context.key_dword),
            self.context.field_perm,
            variants[4],
            self.context.rsp_off,
        )

    def _div_memory(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        if not key.startswith("divmem_"):
            return None
        return _div_memory_handler_asm(
            DivisionMemoryOperationConfig(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.slot,
                self.context.field_perm,
                variants[4],
            )
        )

    def _memory_immediate(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        if not key.startswith(("storei_", "storeirip_", "storeiidx_", "storeiidxnb_")):
            return None
        return _memory_immediate_handler_asm(
            MemoryImmediateOperationConfig(
                key,
                self.context.key,
                self.context.key_qword,
                self.context.key_dword,
                self.context.field_perm,
                variants[4],
            )
        )

    def _atomic_memory(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        if key.startswith(("atomicmem_", "atomicmemrip_", "atomicmemidx_", "atomicmemidxnb_")):
            return _atomic_memory_rmw_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                variants[4],
            )
        if key.startswith("cmpxchgmemidx_"):
            return _cmpxchg_memory_handler_asm(
                AtomicMemoryOperationConfig(
                    key,
                    self.context.key,
                    self.context.key_dword,
                    self.context.slot,
                    self.context.field_perm,
                    variants[4],
                ),
                indexed=True,
            )
        if key.startswith("cmpxchgmem_"):
            return _cmpxchg_memory_handler_asm(
                AtomicMemoryOperationConfig(
                    key,
                    self.context.key,
                    self.context.key_dword,
                    self.context.slot,
                    self.context.field_perm,
                    variants[4],
                )
            )
        if key.startswith("xchgmemidx_"):
            return _xchg_memory_indexed_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                variants[4],
            )
        if not key.startswith("xchgmem_"):
            return None
        return _xchg_memory_handler_asm(
            key,
            self.context.key,
            self.context.key_dword,
            self.context.field_perm,
            variants[4],
        )

    def _tls_memory(self, key: str, _index: int, _variants: tuple[int, ...]) -> str | None:
        if not key.startswith(
            ("tlsload_", "tlsstore_", "tlsloadidx_", "tlsloadidxnb_", "tlsstoreidx_", "tlsstoreidxnb_")
        ):
            return None
        return _tls_memory_handler_asm(
            key, self.context.key, self.context.key_dword, self.context.field_perm, _variants[4]
        )
