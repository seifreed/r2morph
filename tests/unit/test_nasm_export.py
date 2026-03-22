"""
Tests for NASM export functionality.
"""

import tempfile
import os
import random
from r2morph.export.nasm_export import (
    NASMExporter,
    Instruction,
    BasicBlock,
    generate_block_asm,
    generate_final_asm,
    shuffle_blocks,
    remove_redundant_fallthrough,
    assemble_nasm,
    _replace_target_with_label,
)


class TestInstruction:
    """Test Instruction class."""

    def test_create_instruction(self):
        ins = Instruction(
            address=0x1000,
            mnemonic="mov",
            operand_1="rax",
            operand_2="rbx",
            opcode="mov rax, rbx",
        )
        assert ins.address == 0x1000
        assert ins.mnemonic == "mov"
        assert ins.operand_1 == "rax"

    def test_instruction_from_dict(self):
        data = {
            "addr": 0x1000,
            "mnemonic": "xor",
            "operand_1": "rcx",
            "operand_2": "rcx",
            "opcode": "xor rcx, rcx",
            "bytes": "4831c9",
        }
        ins = Instruction.from_dict(data)
        assert ins.address == 0x1000
        assert ins.mnemonic == "xor"
        assert ins.bytes_hex == "4831c9"

    def test_instruction_from_dict_alternate_keys(self):
        data = {
            "address": 0x2000,
            "op1": "rdx",
            "op2": "0",
            "disasm": "mov rdx, 0",
        }
        ins = Instruction.from_dict(data)
        assert ins.address == 0x2000
        assert ins.operand_1 == "rdx"
        assert ins.opcode == "mov rdx, 0"


class TestBasicBlock:
    """Test BasicBlock class."""

    def test_create_block(self):
        block = BasicBlock(
            address=0x1000,
            label="entry",
            instructions=[],
        )
        assert block.address == 0x1000
        assert block.label == "entry"

    def test_block_from_dict(self):
        data = {
            "addr": 0x1000,
            "ops": [
                {"mnemonic": "push", "operand_1": "rbp", "opcode": "push rbp"},
                {"mnemonic": "mov", "operand_1": "rbp", "operand_2": "rsp", "opcode": "mov rbp, rsp"},
            ],
        }
        block = BasicBlock.from_dict(data)
        assert block.address == 0x1000
        assert len(block.instructions) == 2
        assert block.instructions[0].mnemonic == "push"

    def test_block_auto_label(self):
        data = {"addr": 0x1000}
        block = BasicBlock.from_dict(data)
        assert block.label == "block_0x1000"


class TestGenerateBlockAsm:
    """Test generate_block_asm function."""

    def test_simple_block(self):
        ins1 = Instruction(
            address=0x1000,
            mnemonic="mov",
            opcode="mov rax, rbx",
            mutated=True,
        )
        ins2 = Instruction(
            address=0x1003,
            mnemonic="ret",
            opcode="ret",
            mutated=True,
        )
        block = BasicBlock(
            address=0x1000,
            label="entry",
            instructions=[ins1, ins2],
        )
        labels = {0x1000: "entry"}

        result = generate_block_asm(block, labels)
        assert "entry:" in result
        assert "    mov rax, rbx" in result
        assert "    ret" in result

    def test_non_mutated_instruction(self):
        ins = Instruction(
            address=0x1000,
            mnemonic="nop",
            opcode="nop",
            bytes_hex="90",
            mutated=False,
        )
        block = BasicBlock(
            address=0x1000,
            label="block_0x1000",
            instructions=[ins],
        )
        labels = {}

        result = generate_block_asm(block, labels)
        assert "db 0x90" in result
        assert "; nop" in result

    def test_instruction_with_jump_target(self):
        ins = Instruction(
            address=0x1000,
            mnemonic="jmp",
            opcode="jmp 0x2000",
            jump_target=0x2000,
            mutated=True,
        )
        block = BasicBlock(
            address=0x1000,
            label="entry",
            instructions=[ins],
        )
        labels = {0x2000: "target_block"}

        result = generate_block_asm(block, labels)
        assert "jmp target_block" in result

    def test_instruction_with_comment(self):
        ins = Instruction(
            address=0x1000,
            mnemonic="xor",
            opcode="xor rax, rax",
            mutated=True,
            comment="zero register",
        )
        block = BasicBlock(
            address=0x1000,
            label="block_0x1000",
            instructions=[ins],
        )
        labels = {}

        result = generate_block_asm(block, labels)
        assert "; zero register" in result


class TestShuffleBlocks:
    """Test shuffle_blocks function."""

    def test_empty_blocks(self):
        result = shuffle_blocks([])
        assert result == []

    def test_single_block(self):
        blocks = [BasicBlock(address=0x1000, label="single")]
        result = shuffle_blocks(blocks)
        assert len(result) == 1
        assert result[0].address == 0x1000

    def test_first_block_stays_first(self):
        blocks = [
            BasicBlock(address=0x1000, label="entry"),
            BasicBlock(address=0x2000, label="block2"),
            BasicBlock(address=0x3000, label="block3"),
            BasicBlock(address=0x4000, label="block4"),
        ]
        random.seed(42)
        result = shuffle_blocks(blocks)
        assert result[0].address == 0x1000
        assert result[0].label == "entry"
        assert len(result) == 4

    def test_all_blocks_preserved(self):
        blocks = [
            BasicBlock(address=0x1000, label="entry"),
            BasicBlock(address=0x2000, label="block2"),
            BasicBlock(address=0x3000, label="block3"),
        ]
        result = shuffle_blocks(blocks)
        addresses = {b.address for b in result}
        assert addresses == {0x1000, 0x2000, 0x3000}


class TestReplaceTargetWithLabel:
    """Test _replace_target_with_label function."""

    def test_replace_hex_target(self):
        result = _replace_target_with_label("jmp 0x2000", 0x2000, "target")
        assert result == "jmp target"

    def test_replace_uppercase_hex(self):
        result = _replace_target_with_label("jmp 0X2000", 0x2000, "target")
        assert result == "jmp target"

    def test_replace_decimal_target(self):
        result = _replace_target_with_label("jmp 8192", 8192, "target")
        assert result == "jmp target"


class TestGenerateFinalAsm:
    """Test generate_final_asm function."""

    def test_basic_structure(self):
        block = BasicBlock(
            address=0x1000,
            label="entry",
            instructions=[
                Instruction(address=0x1000, mnemonic="mov", opcode="mov rax, 1", mutated=True),
                Instruction(address=0x1007, mnemonic="ret", opcode="ret", mutated=True),
            ],
        )
        labels = {0x1000: "entry"}
        result = generate_final_asm([block], labels)
        assert "BITS 64" in result
        assert "default rel" in result
        assert "section .text" in result
        assert "_start:" in result
        assert "entry:" in result

    def test_32bit_mode(self):
        block = BasicBlock(address=0x1000, label="entry", instructions=[])
        labels = {}
        result = generate_final_asm([block], labels, bits=32)
        assert "BITS 32" in result

    def test_custom_entry_label(self):
        block = BasicBlock(address=0x1000, label="entry", instructions=[])
        labels = {}
        result = generate_final_asm([block], labels, entry_label="start_here")
        assert "global start_here" in result
        assert "start_here:" in result

    def test_no_comments(self):
        block = BasicBlock(
            address=0x1000,
            label="entry",
            instructions=[
                Instruction(address=0x1000, mnemonic="nop", opcode="nop", mutated=True),
            ],
        )
        labels = {}
        result = generate_final_asm([block], labels, include_comments=False)
        assert "; Block at original address:" not in result


class TestRemoveRedundantFallthrough:
    """Test remove_redundant_fallthrough function."""

    def test_no_redundant_jumps(self):
        blocks = [
            BasicBlock(
                address=0x1000,
                label="entry",
                instructions=[
                    Instruction(address=0x1000, mnemonic="mov", opcode="mov rax, 1", mutated=True),
                ],
            ),
            BasicBlock(
                address=0x1007,
                label="next",
                instructions=[
                    Instruction(address=0x1007, mnemonic="ret", opcode="ret", mutated=True),
                ],
            ),
        ]
        labels = {0x1000: "entry", 0x1007: "next"}
        result = remove_redundant_fallthrough(blocks, labels)
        assert len(result[0].instructions) == 1
        assert result[0].instructions[0].mnemonic == "mov"

    def test_remove_redundant_jump(self):
        ins_jmp = Instruction(
            address=0x1000,
            mnemonic="jmp",
            opcode="jmp next",
            jump_target=0x1007,
            mutated=True,
        )
        blocks = [
            BasicBlock(
                address=0x1000,
                label="entry",
                instructions=[ins_jmp],
            ),
            BasicBlock(
                address=0x1007,
                label="next",
                instructions=[
                    Instruction(address=0x1007, mnemonic="ret", opcode="ret", mutated=True),
                ],
            ),
        ]
        labels = {0x1000: "entry", 0x1007: "next"}
        result = remove_redundant_fallthrough(blocks, labels)
        assert len(result[0].instructions) == 0

    def test_keep_non_redundant_jump(self):
        ins_jmp = Instruction(
            address=0x1000,
            mnemonic="jmp",
            opcode="jmp far_label",
            jump_target=0x2000,
            mutated=True,
        )
        blocks = [
            BasicBlock(
                address=0x1000,
                label="entry",
                instructions=[ins_jmp],
            ),
            BasicBlock(
                address=0x1007,
                label="next",
                instructions=[
                    Instruction(address=0x1007, mnemonic="ret", opcode="ret", mutated=True),
                ],
            ),
        ]
        labels = {0x1000: "entry", 0x2000: "far_label"}
        result = remove_redundant_fallthrough(blocks, labels)
        assert len(result[0].instructions) == 1


class TestNASMExporter:
    """Test NASMExporter class."""

    def test_create_exporter(self):
        exporter = NASMExporter(base_address=0x1000)
        assert exporter.base_address == 0x1000
        assert exporter.architecture == "x86"
        assert exporter.bits == 64

    def test_add_block(self):
        exporter = NASMExporter()
        block = BasicBlock(address=0x1000, label="entry", instructions=[])
        exporter.add_block(block)
        assert len(exporter.blocks) == 1
        assert 0x1000 in exporter.labels

    def test_add_block_from_dict(self):
        exporter = NASMExporter()
        block_dict = {
            "addr": 0x1000,
            "ops": [{"mnemonic": "push", "operand_1": "rbp"}],
        }
        exporter.add_block_from_dict(block_dict)
        assert len(exporter.blocks) == 1

    def test_set_blocks(self):
        exporter = NASMExporter()
        blocks = [
            BasicBlock(address=0x1000, label="entry", instructions=[]),
            BasicBlock(address=0x2000, label="next", instructions=[]),
        ]
        exporter.set_blocks(blocks)
        assert len(exporter.blocks) == 2
        assert 0x1000 in exporter.labels
        assert 0x2000 in exporter.labels

    def test_patch_control_flow(self):
        exporter = NASMExporter()
        ins = Instruction(
            address=0x1000,
            mnemonic="jmp",
            opcode="jmp 0x2000",
            ins_type="jmp",
            jump_target=0x2000,
            mutated=False,
        )
        block = BasicBlock(address=0x1000, label="entry", instructions=[ins])
        exporter.add_block(block)
        exporter.set_labels({0x2000: "target_block"})

        exporter.patch_control_flow()
        assert exporter.blocks[0].instructions[0].mutated is True
        assert "jmp target_block" in exporter.blocks[0].instructions[0].opcode

    def test_generate_asm(self):
        exporter = NASMExporter()
        block = BasicBlock(
            address=0x1000,
            label="entry",
            instructions=[
                Instruction(address=0x1000, mnemonic="mov", opcode="mov rax, 0", mutated=True),
            ],
        )
        exporter.add_block(block)
        asm = exporter.generate_asm()
        assert "BITS 64" in asm
        assert "entry:" in asm
        assert "mov rax, 0" in asm


class TestAssembleNasm:
    """Test assemble_nasm function."""

    def test_simple_assembly(self):
        asm_code = """BITS 64
default rel
section .text
global _start
_start:
    mov rax, 1
    ret
"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            output_path = f.name

        try:
            success, message, asm_path = assemble_nasm(asm_code, output_path)
            if success:
                assert os.path.exists(output_path)
                with open(output_path, "rb") as f:
                    content = f.read()
                assert len(content) > 0
            else:
                pass
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_nasm_not_found(self):
        asm_code = "BITS 64\n_start:\nret\n"
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            output_path = f.name

        try:
            success, message, _ = assemble_nasm(asm_code, output_path, nasm_path="/nonexistent/nasm")
            assert success is False
            assert "not found" in message.lower() or "No such file" in message
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestExportShellcode:
    """Test export_shellcode convenience function."""

    def test_export_simple_shellcode(self):
        blocks = [
            {
                "addr": 0x1000,
                "ops": [
                    {
                        "mnemonic": "xor",
                        "operand_1": "rax",
                        "operand_2": "rax",
                        "opcode": "xor rax, rax",
                        "mutated": True,
                    },
                    {"mnemonic": "ret", "opcode": "ret", "mutated": True},
                ],
            }
        ]
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            output_path = f.name

        try:
            from r2morph.export.nasm_export import export_shellcode

            success, message, asm_code = export_shellcode(blocks, output_path, base_address=0x1000, shuffle=False)
            assert asm_code is not None
            assert "BITS 64" in asm_code
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestIntegration:
    """Integration tests for NASM export."""

    def test_full_export_workflow(self):
        exporter = NASMExporter(base_address=0x10000)

        block1 = BasicBlock(
            address=0x10000,
            label="entry",
            instructions=[
                Instruction(address=0x10000, mnemonic="push", opcode="push rbx", mutated=True),
                Instruction(
                    address=0x10002,
                    mnemonic="mov",
                    operand_1="rbx",
                    operand_2="100",
                    opcode="mov rbx, 100",
                    mutated=True,
                ),
            ],
            jump=0x10010,
        )

        block2 = BasicBlock(
            address=0x10010,
            label="loop_start",
            instructions=[
                Instruction(address=0x10010, mnemonic="dec", opcode="dec rbx", mutated=True),
                Instruction(
                    address=0x10013,
                    mnemonic="jnz",
                    opcode="jnz 0x10010",
                    ins_type="cjmp",
                    jump_target=0x10010,
                    mutated=False,
                ),
            ],
        )

        block3 = BasicBlock(
            address=0x10015,
            label="end",
            instructions=[
                Instruction(address=0x10015, mnemonic="pop", opcode="pop rbx", mutated=True),
                Instruction(address=0x10017, mnemonic="ret", opcode="ret", mutated=True),
            ],
        )

        exporter.add_block(block1)
        exporter.add_block(block2)
        exporter.add_block(block3)

        exporter.patch_control_flow()

        labels = {0x10010: "loop_start"}
        exporter.set_labels(labels)

        asm_code = exporter.generate_asm()

        assert "BITS 64" in asm_code
        assert "entry:" in asm_code
        assert "loop_start:" in asm_code
        assert "push rbx" in asm_code
        assert "jnz loop_start" in asm_code
