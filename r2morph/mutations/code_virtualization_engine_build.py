"""Assemble and encrypt a generated engine VM blob."""

from __future__ import annotations

import logging
import struct
from importlib import import_module

from r2morph.mutations.code_virtualization_antidebug import (
    _TRACER_ISLAND_LEN,
    patch_tracer_constants,
)
from r2morph.mutations.code_virtualization_bootstrap import (
    BOOTSTRAP_TABLE_SIZE,
    encrypt_bootstrap_table,
    table_entry_key,
    table_key_mix,
)
from r2morph.mutations.code_virtualization_engine_codegen import (
    _interpreter_asm,
    encode_bytecode,
)
from r2morph.mutations.code_virtualization_engine_common import VMScheme
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedMemOp,
    VirtualizedOp,
)
from r2morph.mutations.code_virtualization_region_integrity import compute_build_checksum

logger = logging.getLogger(__name__)


def build_vm_blob(
    ops: list[
        VirtualizedOp
        | VirtualizedMemOp
        | VirtualizedFpMemOp
        | VirtualizedFpArithOp
        | VirtualizedFpConvertOp
        | VirtualizedFpArithMemOp
        | VirtualizedFpPackedOp
        | VirtualizedFpPackedMemOp
    ],
    cave_vaddr: int,
    continuation_vaddr: int,
    scheme: VMScheme,
) -> bytes | None:
    """Assemble the interpreter and append checksum-encrypted bytecode."""
    try:
        keystone = import_module("keystone")
    except ImportError:
        logger.warning("keystone unavailable; cannot virtualize")
        return None

    has_fp = any(
        isinstance(
            op,
            (
                VirtualizedFpMemOp,
                VirtualizedFpArithOp,
                VirtualizedFpConvertOp,
                VirtualizedFpArithMemOp,
                VirtualizedFpPackedOp,
                VirtualizedFpPackedMemOp,
            ),
        )
        for op in ops
    )
    vex_destinations = frozenset(op.dst_index for op in ops if isinstance(op, VirtualizedFpPackedOp) and op.vex)
    asm = _interpreter_asm(continuation_vaddr, scheme, has_fp, vex_destinations)
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("VM interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        logger.debug("VM interpreter assembly produced no bytes")
        return None

    data = bytearray(encoding)
    total = sum(len(indices) for indices in scheme.dup.values())
    island_start = len(data) - _TRACER_ISLAND_LEN
    bootstrap_start = island_start - BOOTSTRAP_TABLE_SIZE
    table_start = bootstrap_start - total * 4
    bootstrap_checksum = compute_build_checksum(
        bytes(engine.asm(asm[: asm.index("vm_bootstrap:") + len("vm_bootstrap:")], cave_vaddr)[0]),
        scheme.xor_key,
        scheme.checksum_bytewise,
        scheme.checksum_reverse,
    )
    checksum = compute_build_checksum(
        bytes(data[:table_start]), scheme.xor_key, scheme.checksum_bytewise, scheme.checksum_reverse
    )
    table_mix = scheme.table_key & 0x7FFFFFFF | 1
    for entry_index in range(total):
        offset = table_start + entry_index * 4
        entry_key = table_entry_key(checksum, entry_index, table_mix)
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ entry_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
    encrypt_bootstrap_table(data, bootstrap_start, bootstrap_checksum, table_key_mix(scheme.junk_seed))
    patch_tracer_constants(data, island_start, bootstrap_checksum)
    bytecode_base = cave_vaddr + len(data)
    try:
        bytecode = encode_bytecode(ops, scheme, checksum, bytecode_base)
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; leaving run native")
        return None
    return bytes(data) + bytecode
