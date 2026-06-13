"""Multi-VM virtualization helpers."""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.code_virtualization_vm import (
    MULTI_VM_PROFILES,
    VMInstruction,
    VMOpcode,
    VMProfile,
    generate_multi_vm_dispatcher_x64,
    translate_instruction_to_vm,
)

logger = logging.getLogger(__name__)


def resolve_multi_vm_profiles(profile_names: list[str], num_vms: int) -> list[VMProfile]:
    available = {p.name: p for p in MULTI_VM_PROFILES}
    active_profiles: list[VMProfile] = []

    for name in profile_names[:num_vms]:
        active_profiles.append(available.get(name, MULTI_VM_PROFILES[0]))

    if not active_profiles:
        active_profiles = [MULTI_VM_PROFILES[0]]
    return active_profiles


def select_multi_vm_profile(active_profiles: list[VMProfile], randomize_selection: bool, func_addr: int) -> VMProfile:
    if randomize_selection:
        return random.choice(active_profiles)
    return active_profiles[func_addr % len(active_profiles)]


def virtualize_with_profile(
    instructions: list[dict[str, Any]], arch: str, profile: VMProfile
) -> tuple[list[VMInstruction], bytes]:
    vm_insns: list[VMInstruction] = [VMInstruction(VMOpcode.VM_ENTER, [], "vm_enter")]

    for insn in instructions:
        vm_insn = translate_instruction_to_vm(insn, arch)
        if vm_insn:
            vm_insns.append(
                VMInstruction(
                    VMOpcode(int(vm_insn.opcode) + profile.opcode_base),
                    vm_insn.operands,
                    vm_insn.original_asm,
                )
            )
        else:
            vm_insns.append(VMInstruction(VMOpcode.VM_NOP, [], f"; skipped: {insn.get('mnemonic', 'unknown')}"))

    vm_insns.append(VMInstruction(VMOpcode.VM_EXIT, [], "vm_exit"))

    bytecode = bytearray()
    for vm_insn in vm_insns:
        vm_insn.bytecode_offset = len(bytecode)
        bytecode.extend(vm_insn.to_bytecode())

    return vm_insns, bytes(bytecode)


def build_multi_vm_dispatchers(active_profiles: list[VMProfile]) -> dict[str, str]:
    return {profile.name: generate_multi_vm_dispatcher_x64(profile) for profile in active_profiles}


def apply_multi_vm_virtualization(pass_obj: Any, binary: Any) -> dict[str, Any]:
    pass_obj._reset_random()
    logger.info("Applying multi-VM virtualization with %d VMs", len(pass_obj.active_profiles))

    functions = binary.get_functions()
    virtualized_count = 0
    skipped_count = 0
    total_insns = 0
    total_bytecode = 0
    profiles_used: dict[str, int] = {p.name: 0 for p in pass_obj.active_profiles}

    arch_info = binary.get_arch_info()
    arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"

    for func in functions:
        if virtualized_count >= pass_obj.max_functions:
            break
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue
        if random.random() > pass_obj.probability:
            skipped_count += 1
            continue

        try:
            blocks = binary.get_basic_blocks(func["addr"])
        except Exception as exc:
            logger.debug("Failed to get blocks: %s", exc)
            continue

        profile = select_multi_vm_profile(pass_obj.active_profiles, pass_obj.randomize_selection, func.get("addr", 0))
        profiles_used[profile.name] += 1

        for block in blocks:
            try:
                insns = binary.r2.cmdj(f"pdj {block['size']} @ {block['addr']}")
            except Exception:
                continue

            if not insns:
                continue

            can_virt, reason = pass_obj._can_virtualize(insns)
            if not can_virt:
                logger.debug("Cannot virtualize: %s", reason)
                continue

            _, bytecode = virtualize_with_profile(insns, arch, profile)
            total_insns += len(insns)
            total_bytecode += len(bytecode)
            virtualized_count += 1
            logger.debug(
                "Virtualized block at 0x%x with VM '%s': %d insns -> %d bytes bytecode",
                block["addr"],
                profile.name,
                len(insns),
                len(bytecode),
            )

    dispatchers = {}
    if pass_obj.include_dispatcher and virtualized_count > 0:
        dispatchers = build_multi_vm_dispatchers(pass_obj.active_profiles)
        for profile_name in dispatchers:
            logger.debug("Generated VM dispatcher for '%s'", profile_name)

    return {
        "functions_virtualized": virtualized_count,
        "functions_skipped": skipped_count,
        "total_instructions": total_insns,
        "total_bytecode_bytes": total_bytecode,
        "architecture": arch,
        "profiles_used": profiles_used,
        "dispatchers_generated": len(dispatchers),
        "active_profiles": [p.name for p in pass_obj.active_profiles],
    }
