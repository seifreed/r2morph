"""
Regression test: VM translation must reject operands it cannot encode.

``VMInstruction.to_bytecode`` encodes an integer operand in 1, 2 or 4
signed bytes by magnitude; an operand outside signed-32-bit range falls
into the 4-byte branch and ``op.to_bytes(4, "little", signed=True)``
raises ``OverflowError: int too big to convert``. 64-bit immediates and
addresses are routine in real x86-64 code (e.g. ``mov rax,
0x100000000``), so ``CodeVirtualizationPass._generate_bytecode`` crashed
on them. The failure was contained by the pipeline's per-pass isolation
boundary, so the pass was silently non-functional on such functions
while the test suite (tiny fixtures) stayed green.

The translation layer already routes untranslatable instructions through
a ``VM_NOP`` fallback; an operand too wide for the VM encoding is just
another untranslatable case. These tests exercise the real
``translate_instruction_to_vm`` and the real
``CodeVirtualizationPass._generate_bytecode`` (no mocks, no monkeypatch),
mirroring the production caller pattern.
"""

from r2morph.mutations.code_virtualization import (
    CodeVirtualizationPass,
    VMInstruction,
    VMOpcode,
    translate_instruction_to_vm,
)


def test_translate_rejects_operand_exceeding_int32() -> None:
    insn = {"mnemonic": "mov", "op1": "rax", "op2": str(0x100000000)}  # 2**32
    assert translate_instruction_to_vm(insn) is None


def test_translate_preserves_in_range_immediate() -> None:
    insn = {"mnemonic": "mov", "op1": "rax", "op2": "4096"}
    vm = translate_instruction_to_vm(insn)
    assert vm is not None
    assert vm.opcode == VMOpcode.MOV_REG_IMM
    assert vm.operands == ["rax", 4096]


def test_generate_bytecode_no_overflow_through_caller_path() -> None:
    # Exactly the production pattern: translate, else fall back to VM_NOP.
    insn = {"mnemonic": "mov", "op1": "rax", "op2": str(0x140000000)}
    vm = translate_instruction_to_vm(insn)

    vm_insns = [VMInstruction(VMOpcode.VM_ENTER, [], "vm_enter")]
    vm_insns.append(vm if vm is not None else VMInstruction(VMOpcode.VM_NOP, [], "; skipped"))
    vm_insns.append(VMInstruction(VMOpcode.VM_EXIT, [], "vm_exit"))

    bytecode = CodeVirtualizationPass()._generate_bytecode(vm_insns)
    assert isinstance(bytecode, bytes)
    assert len(bytecode) > 0


def test_generate_bytecode_in_range_operand_still_encodes() -> None:
    insn = {"mnemonic": "mov", "op1": "rax", "op2": "1000000"}  # fits int32
    vm = translate_instruction_to_vm(insn)
    assert vm is not None
    bytecode = CodeVirtualizationPass()._generate_bytecode([vm])
    assert isinstance(bytecode, bytes)
    assert len(bytecode) > 0
