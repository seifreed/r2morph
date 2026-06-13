"""Contract tests for the virtualization VM support module."""

from r2morph.mutations.code_virtualization_vm import (
    MULTI_VM_PROFILES,
    VMInstruction,
    VMOpcode,
    generate_multi_vm_dispatcher_x64,
    generate_vm_dispatcher_x64,
    translate_instruction_to_vm,
)


def test_vm_support_module_exports_core_primitives() -> None:
    assert VMOpcode.NOP == 0x00
    insn = VMInstruction(VMOpcode.NOP, [], "nop")
    assert insn.to_bytecode() == bytes([VMOpcode.NOP])


def test_vm_support_translation_and_dispatcher_generation() -> None:
    vm = translate_instruction_to_vm({"mnemonic": "mov", "op1": "rax", "op2": "7"})
    assert vm is not None
    assert vm.opcode == VMOpcode.MOV_REG_IMM
    assert "vm_execute" in generate_vm_dispatcher_x64()
    assert "vm_execute_simple" in generate_multi_vm_dispatcher_x64(MULTI_VM_PROFILES[0])
