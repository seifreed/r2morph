"""VEX and floating-point handler routing for the region VM."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_region_fp_fma import (
    _fp_vex_fma_handler_asm,
    _fp_vex_fma_memory_handler_asm,
    _fp_vex_scalar_fma_handler_asm,
    _fp_vex_scalar_fma_memory_handler_asm,
    is_fp_vex_fma_handler_key,
    is_fp_vex_scalar_fma_handler_key,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    VexMemoryHandlerConfig,
    _fp_arith_handler_asm,
    _fp_arith_mem_handler_asm,
    _fp_compare_handler_asm,
    _fp_compare_memory_handler_asm,
    _fp_convert_handler_asm,
    _fp_indexed_handler_asm,
    _fp_memory_handler_asm,
    _fp_movd_handler_asm,
    _fp_move_handler_asm,
    _fp_movmskb_handler_asm,
    _fp_packed_arith_handler_asm,
    _fp_packed_arith_mem_handler_asm,
    _fp_packed_mem_handler_asm,
    _fp_packed_vex_256_arith_handler_asm,
    _fp_packed_vex_arith_handler_asm,
    _fp_vex_256_memory_handler_asm,
    _fp_vex_256_move_handler_asm,
    _fp_vex_256_packed_arith_mem_handler_asm,
    _fp_vex_256_packed_shift_immediate_handler_asm,
    _fp_vex_256_permute_immediate_handler_asm,
    _fp_vex_256_permute_lane_immediate_handler_asm,
    _fp_vex_256_variable_blend_handler_asm,
    _fp_vex_256_variable_permute_handler_asm,
    _fp_vex_gp_move_handler_asm,
    _fp_vex_move_handler_asm,
    _fp_vex_packed_arith_mem_handler_asm,
    _fp_vex_packed_compare_handler_asm,
    _fp_vex_packed_compare_memory_handler_asm,
    _fp_vex_packed_shift_immediate_handler_asm,
    _fp_vex_scalar_arith_handler_asm,
    _fp_vex_scalar_arith_mem_handler_asm,
    _fp_vex_scalar_memory_move_handler_asm,
    _fp_vex_scalar_merge_handler_asm,
    _fp_vex_scalar_move_handler_asm,
    vzeroall_handler_asm,
    vzeroupper_handler_asm,
)

_FP_MOVE_HANDLERS = {
    "fpmovd": _fp_movd_handler_asm,
    "fpmovq": _fp_movd_handler_asm,
    "fpmov": _fp_move_handler_asm,
}

_FP_VEX_256_MEMORY_KEYS = frozenset(
    {
        "fploadvex256",
        "fpstorevex256",
        "fploadvex256rip",
        "fpstorevex256rip",
        "fploadvex256idx",
        "fpstorevex256idx",
        "fploadvex256idxnb",
        "fpstorevex256idxnb",
    }
)


class FPHandlerRouterMixin:
    """Route FP handlers while the main router owns the remaining VM families."""

    context: Any

    def _fp(self, key: str, _index: int, variants: tuple[int, ...]) -> str | None:
        if key == "vzeroupper":
            return vzeroupper_handler_asm()
        if key == "vzeroall":
            return vzeroall_handler_asm()
        address = variants[4]
        if key in _FP_VEX_256_MEMORY_KEYS:
            return _fp_vex_256_memory_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        return self._fp_standard(key, address)

    def _fp_standard(self, key: str, address: int) -> str | None:
        body = None
        if key.startswith(("fpload_", "fpstore_", "fploadrip_", "fpstorerip_")):
            body = _fp_memory_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith(("fploadidx_", "fpstoreidx_", "fploadidxnb_", "fpstoreidxnb_")):
            body = _fp_indexed_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith(("fparithmem_", "fparithmemrip_", "fparithmemidx_", "fparithmemidxnb_")):
            body = _fp_arith_mem_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith("fparith_"):
            body = _fp_arith_handler_asm(key, self.context.key, self.context.field_perm)
        elif key.startswith(("cvti2f_", "cvtf2i_")):
            body = _fp_convert_handler_asm(key, self.context.key, self.context.field_perm)
        elif key.startswith(("fpmovd_", "fpmovq_", "fpmov_")):
            body = _FP_MOVE_HANDLERS[key.split("_", 1)[0]](key, self.context.key, self.context.field_perm)
        elif key.startswith(("fpcmp_", "fpcmpvex256_", "fpcmpmem_", "fpcmpmemrip_", "fpcmpmemidx_", "fpcmpmemidxnb_")):
            if key.startswith(("fpcmpmem_", "fpcmpmemrip_", "fpcmpmemidx_", "fpcmpmemidxnb_")):
                body = _fp_compare_memory_handler_asm(
                    key,
                    self.context.key,
                    self.context.key_dword,
                    self.context.field_perm,
                    address,
                )
            else:
                body = _fp_compare_handler_asm(key, self.context.key, self.context.field_perm)
        elif key.startswith(("fppackedmem_", "fppackedmemrip_", "fppackedmemidx_", "fppackedmemidxnb_")):
            body = _fp_packed_arith_mem_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        elif key.startswith("fppacked_"):
            body = _fp_packed_arith_handler_asm(key, self.context.key, self.context.field_perm)
        elif key in (
            "fppload",
            "fppstore",
            "fpploadrip",
            "fppstorerip",
            "fpploadidx",
            "fppstoreidx",
            "fpploadidxnb",
            "fppstoreidxnb",
        ):
            body = _fp_packed_mem_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                self.context.field_perm,
                address,
            )
        return body

    def _fp_vex_scalar_move(self, key: str, variants: tuple[int, ...]) -> str | None:
        if key.startswith(("fpmovmskb_", "fpmovmskbvex_", "fpmovmskbvex256_")):
            return _fp_movmskb_handler_asm(key, self.context.key, self.context.field_perm)
        if key.startswith(("fpmovvexgp_", "fpmovvexgpd_")):
            return _fp_vex_gp_move_handler_asm(key, self.context.key, self.context.field_perm, self.context.has_ymm)
        if key.startswith(
            (
                "fploadvex_",
                "fploadvexrip_",
                "fploadvexidx_",
                "fploadvexidxnb_",
                "fpstorevex_",
                "fpstorevexrip_",
                "fpstorevexidx_",
                "fpstorevexidxnb_",
                "fpmovvexmem_",
            )
        ):
            return _fp_vex_scalar_memory_move_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                VexMemoryHandlerConfig(self.context.field_perm, variants[4], self.context.has_ymm),
            )
        if key.startswith("fpmovvexscalar3_"):
            return _fp_vex_scalar_merge_handler_asm(
                key, self.context.key, self.context.field_perm, self.context.has_ymm
            )
        if key.startswith("fpmovvexscalar_"):
            return _fp_vex_scalar_move_handler_asm(key, self.context.key, self.context.field_perm, self.context.has_ymm)
        return None

    def _fp_vex_256_immediate(self, key: str) -> str | None:
        if key.startswith("fppackedvex256var_"):
            return _fp_vex_256_variable_blend_handler_asm(key, self.context.key, self.context.field_perm)
        if key.startswith("fppackedvex256varpermil_"):
            return _fp_vex_256_variable_permute_handler_asm(key, self.context.key, self.context.field_perm)
        if key.startswith("fppackedvex256permimm_"):
            return _fp_vex_256_permute_immediate_handler_asm(key, self.context.key, self.context.field_perm)
        if key.startswith("fppackedvex256permilimm_"):
            return _fp_vex_256_permute_lane_immediate_handler_asm(key, self.context.key, self.context.field_perm)
        return None

    def _fp_vex_packed_compare(self, key: str, variants: tuple[int, ...]) -> str | None:
        if key.startswith(("fppackedvexcmpmem_", "fppackedvex256cmpmem_")):
            return _fp_vex_packed_compare_memory_handler_asm(
                key,
                self.context.key,
                self.context.key_dword,
                VexMemoryHandlerConfig(self.context.field_perm, variants[4], self.context.has_ymm),
            )
        if not key.startswith(("fppackedvexcmp_", "fppackedvex256cmp_")):
            return None
        return _fp_vex_packed_compare_handler_asm(key, self.context.key, self.context.field_perm, self.context.has_ymm)

    def _fp_vex_256_packed(self, key: str) -> str | None:
        if key.startswith("fppackedvex256_"):
            handler = (
                _fp_vex_fma_handler_asm if is_fp_vex_fma_handler_key(key) else _fp_packed_vex_256_arith_handler_asm
            )
            return handler(key, self.context.key, self.context.field_perm)
        if key.startswith("fppackedvex256imm_"):
            return _fp_vex_256_packed_shift_immediate_handler_asm(key, self.context.key, self.context.field_perm)
        return None

    def _fp_vex(self, key: str, _index: int, _variants: tuple[int, ...]) -> str | None:
        scalar_move = self._fp_vex_scalar_move(key, _variants)
        if scalar_move is not None:
            return scalar_move
        immediate = self._fp_vex_256_immediate(key)
        if immediate is not None:
            return immediate
        compare = self._fp_vex_packed_compare(key, _variants)
        if compare is not None:
            return compare
        packed_256 = self._fp_vex_256_packed(key)
        if packed_256 is not None:
            return packed_256
        body = None
        if key.startswith("fparithvexmem"):
            config = VexMemoryHandlerConfig(self.context.field_perm, _variants[4], self.context.has_ymm)
            body = (
                _fp_vex_scalar_fma_memory_handler_asm(key, self.context.key, self.context.key_dword, config)
                if is_fp_vex_scalar_fma_handler_key(key)
                else _fp_vex_scalar_arith_mem_handler_asm(key, self.context.key, self.context.key_dword, config)
            )
        elif key.startswith("fppackedvexmem"):
            config = VexMemoryHandlerConfig(self.context.field_perm, _variants[4], self.context.has_ymm)
            body = (
                _fp_vex_fma_memory_handler_asm(key, self.context.key, self.context.key_dword, config)
                if is_fp_vex_fma_handler_key(key)
                else _fp_vex_packed_arith_mem_handler_asm(key, self.context.key, self.context.key_dword, config)
            )
        elif key.startswith("fppackedvex256mem"):
            config = VexMemoryHandlerConfig(self.context.field_perm, _variants[4], self.context.has_ymm)
            body = (
                _fp_vex_fma_memory_handler_asm(key, self.context.key, self.context.key_dword, config)
                if is_fp_vex_fma_handler_key(key)
                else _fp_vex_256_packed_arith_mem_handler_asm(
                    key, self.context.key, self.context.key_dword, self.context.field_perm, _variants[4]
                )
            )
        elif key.startswith("fpmovvex256_"):
            body = _fp_vex_256_move_handler_asm(key, self.context.key, self.context.field_perm)
        elif key.startswith("fparithvex_"):
            body = (
                _fp_vex_scalar_fma_handler_asm(key, self.context.key, self.context.field_perm, self.context.has_ymm)
                if is_fp_vex_scalar_fma_handler_key(key)
                else _fp_vex_scalar_arith_handler_asm(
                    key, self.context.key, self.context.field_perm, self.context.has_ymm
                )
            )
        elif key.startswith("fppackedvex_"):
            handler = _fp_vex_fma_handler_asm if is_fp_vex_fma_handler_key(key) else _fp_packed_vex_arith_handler_asm
            body = handler(key, self.context.key, self.context.field_perm, self.context.has_ymm)
        elif key.startswith("fppackedveximm_"):
            body = _fp_vex_packed_shift_immediate_handler_asm(
                key, self.context.key, self.context.field_perm, self.context.has_ymm
            )
        elif key.startswith("fpmovvex_"):
            body = _fp_vex_move_handler_asm(key, self.context.key, self.context.field_perm, self.context.has_ymm)
        return body
