"""
Code Virtualization - Transform code to custom VM bytecode.

Translates native code instructions into bytecode for a custom
virtual machine, making reverse engineering significantly harder
by obscuring the actual operations performed.

This is similar to techniques used by VMProtect, Themida,
and other commercial obfuscators.

Example transformation:

    Original:
        mov eax, 1
        add eax, 5
        ret

    Virtualized:
        push 0x0003        ; VM_EXIT
        push 0x0005        ; operand 5
        push 0x0001        ; ADD opcode
        push 0x0001        ; operand 1
        push 0x0000        ; MOV opcode
        call vm_execute    ; run VM

    The VM interprets these opcodes, performing the operations
    without exposing the actual native instructions.

VM Architecture:
    - Stack-based VM with operand stack
    - Handler table for each opcode
    - Context registers (vreg0-vreg7 map to real registers)
    - Control flow through opcode dispatch

Opcode Categories:
    - Data movement: MOV, PUSH, POP
    - Arithmetic: ADD, SUB, MUL, DIV, INC, DEC
    - Logic: AND, OR, XOR, NOT
    - Control flow: JMP, JZ, JNZ, CALL, RET
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.code_virtualization_multi_vm import (
    apply_multi_vm_virtualization,
    resolve_multi_vm_profiles,
)
from r2morph.mutations.code_virtualization_vm import (  # noqa: F401
    CONDITION_CODES,
    MULTI_VM_PROFILES,
    REG_MAP_X64,
    REG_MAP_X86,
    VMContext,
    VMHandler,
    VMInstruction,
    VMOpcode,
    VMProfile,
    generate_multi_vm_dispatcher_x64,
    generate_multi_vm_handler_x64,
    generate_vm_bytecode,
    generate_vm_dispatcher_x64,
    generate_vm_dispatcher_x86,
    generate_vm_handler_x64,
    translate_instruction_to_vm,
    virtualize_block_to_vm_instructions,
)

logger = logging.getLogger(__name__)


class CodeVirtualizationPass(MutationPass):
    """
    Mutation pass that virtualizes code into custom VM bytecode.

    Transforms selected functions to run on a virtual machine,
    making reverse engineering much harder.

    Config options:
        - probability: Probability of virtualizing each function (default: 0.3)
        - max_functions: Maximum functions to virtualize (default: 5)
        - include_dispatcher: Include dispatcher in output (default: True)
        - opcode_randomization: Randomize opcode mapping (default: True)
        - junk_handlers: Add junk handlers (default: True)
    """

    SUPPORTED_INSNS = {
        "mov",
        "add",
        "sub",
        "xor",
        "and",
        "or",
        "inc",
        "dec",
        "push",
        "pop",
        "cmp",
        "jmp",
        "call",
        "ret",
        "lea",
        "xchg",
        "nop",
        "jz",
        "jnz",
        "je",
        "jne",
        "jg",
        "jl",
        "jge",
        "jle",
        "test",
        "shl",
        "shr",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeVirtualization", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 5)
        self.include_dispatcher = self.config.get("include_dispatcher", True)
        self.opcode_randomization = self.config.get("opcode_randomization", True)
        self.junk_handlers = self.config.get("junk_handlers", True)
        self.set_support(
            formats=("ELF", "PE"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "transforms code to VM bytecode",
                "generates custom dispatcher for each run",
                "opcode mapping can be randomized",
            ),
        )

    def _can_virtualize(self, instructions: list[dict[str, Any]]) -> tuple[bool, str]:
        """Check if instructions can be virtualized."""
        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()

            if mnemonic not in self.SUPPORTED_INSNS:
                return False, f"unsupported instruction: {mnemonic}"

            if insn.get("type") in ("rep", "repz", "repnz"):
                return False, "rep prefix not supported"

            if any(p in insn.get("disasm", "").lower() for p in ["rip", "[rsp", "[rbp"]):
                return False, "rip-relative or stack addressing"

        return True, ""

    def _virtualize_block(self, instructions: list[dict[str, Any]], arch: str) -> list[VMInstruction]:
        """Virtualize a basic block to VM bytecode."""
        return virtualize_block_to_vm_instructions(instructions, arch)

    def _generate_bytecode(self, vm_insns: list[VMInstruction]) -> bytes:
        """Generate bytecode from VM instructions."""
        return generate_vm_bytecode(vm_insns)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply code virtualization.

        Args:
            binary: Any to virtualize

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying code virtualization")

        functions = binary.get_functions()
        virtualized_count = 0
        skipped_count = 0
        total_insns = 0
        total_bytecode = 0

        arch_info = binary.get_arch_info()
        arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"

        for func in functions:
            if virtualized_count >= self.max_functions:
                break

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            if random.random() > self.probability:
                skipped_count += 1
                continue

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks: {e}")
                continue

            for block in blocks:
                try:
                    insns = binary.r2.cmdj(f"pdj {block['size']} @ {block['addr']}")
                except Exception:
                    continue

                if not insns:
                    continue

                can_virt, reason = self._can_virtualize(insns)
                if not can_virt:
                    logger.debug(f"Cannot virtualize: {reason}")
                    continue

                vm_insns = self._virtualize_block(insns, arch)
                bytecode = self._generate_bytecode(vm_insns)

                block_addr = block.get("addr", 0)
                block_size = block.get("size", 0)

                if len(bytecode) <= block_size:
                    mutation_checkpoint = self._create_mutation_checkpoint("virtualize")
                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])

                    original_bytes = binary.read_bytes(block_addr, block_size)
                    if not original_bytes:
                        logger.debug(
                            "Skipping virtualization at 0x%x: cannot read %d original "
                            "bytes (no safe rollback target)",
                            block_addr,
                            block_size,
                        )
                        continue

                    if binary.write_bytes(block_addr, bytecode):
                        mutated_bytes = binary.read_bytes(block_addr, block_size)
                        if not mutated_bytes:
                            logger.debug(
                                "Virtualization wrote 0x%x but read-back failed; rolling back",
                                block_addr,
                            )
                            if self._session is not None and mutation_checkpoint is not None:
                                self._session.rollback_to(mutation_checkpoint)
                            binary.reload()
                            if self._rollback_policy == "fail-fast":
                                raise RuntimeError("code_virtualization read-back failed; aborting (fail-fast)")
                            continue
                        record = self._record_mutation(
                            function_address=func["addr"],
                            start_address=block_addr,
                            end_address=block_addr + block_size - 1,
                            original_bytes=original_bytes,
                            mutated_bytes=mutated_bytes,
                            original_disasm=f"; {len(insns)} instructions virtualized",
                            mutated_disasm=f"; VM bytecode ({len(bytecode)} bytes)",
                            mutation_kind="code_virtualization",
                            metadata={
                                "instructions_count": len(insns),
                                "bytecode_size": len(bytecode),
                                "structural_baseline": baseline,
                            },
                        )
                        if self._validation_manager is not None:
                            outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
                            if not outcome.passed and mutation_checkpoint is not None:
                                self._rollback_mutation(binary, mutation_checkpoint)
                                continue

                        total_insns += len(insns)
                        total_bytecode += len(bytecode)
                        virtualized_count += 1
                        logger.debug(
                            f"Virtualized block at 0x{block_addr:x}: {len(insns)} insns -> {len(bytecode)} bytes bytecode"
                        )

        if self.include_dispatcher and virtualized_count > 0:
            if arch == "x64":
                generate_vm_dispatcher_x64()
            else:
                generate_vm_dispatcher_x86()
            logger.debug("Generated VM dispatcher")

        return {
            "functions_virtualized": virtualized_count,
            "functions_skipped": skipped_count,
            "total_instructions": total_insns,
            "total_bytecode_bytes": total_bytecode,
            "architecture": arch,
            "include_dispatcher": self.include_dispatcher,
        }


class MultiVMVirtualizationPass(CodeVirtualizationPass):
    """
    Enhanced code virtualization using multiple VM profiles.

    Uses different VM configurations for different functions,
    making reverse engineering significantly harder as analysts
    must understand multiple VM implementations.

    Config options:
        - num_vms: Number of VM profiles to use (default: 2)
        - profiles: List of VM profile names to use (default: ["simple", "obfuscated"])
        - randomize_selection: Randomize which VM is used (default: True)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        config["opcode_randomization"] = True
        super().__init__(config=config)
        self.num_vms = self.config.get("num_vms", 2)
        self.profile_names = self.config.get("profiles", ["simple", "obfuscated"])
        self.randomize_selection = self.config.get("randomize_selection", True)
        self.active_profiles: list[VMProfile] = resolve_multi_vm_profiles(self.profile_names, self.num_vms)

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply multi-VM virtualization."""
        return apply_multi_vm_virtualization(self, binary)
