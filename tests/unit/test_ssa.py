"""
Unit tests for SSA (Static Single Assignment) form generation.
"""

import pytest

from r2morph.analysis.ssa import SSAVariable, PhiFunction, SSABlock, SSAConverter


class TestSSAVariable:
    def test_ssa_variable_creation(self):
        var = SSAVariable(base_name="eax", version=0)
        assert var.base_name == "eax"
        assert var.version == 0

    def test_ssa_variable_repr(self):
        var = SSAVariable(base_name="eax", version=1)
        assert repr(var) == "eax_1"

    def test_ssa_variable_equality(self):
        var1 = SSAVariable(base_name="eax", version=1)
        var2 = SSAVariable(base_name="eax", version=1)
        var3 = SSAVariable(base_name="eax", version=2)
        var4 = SSAVariable(base_name="ebx", version=1)

        assert var1 == var2
        assert var1 != var3
        assert var1 != var4

    def test_ssa_variable_hash(self):
        var1 = SSAVariable(base_name="eax", version=1)
        var2 = SSAVariable(base_name="eax", version=1)
        var3 = SSAVariable(base_name="eax", version=2)

        d = {var1: "first"}
        assert d[var2] == "first"
        assert var3 not in d

    def test_ssa_variable_with_definition_address(self):
        var = SSAVariable(base_name="eax", version=1, definition_address=0x1000)
        assert var.definition_address == 0x1000

    def test_ssa_variable_with_original_register(self):
        var = SSAVariable(base_name="r0", version=1, original_register="x0")
        assert var.original_register == "x0"


class TestPhiFunction:
    def test_phi_function_creation(self):
        result = SSAVariable(base_name="eax", version=2)
        operands = [
            SSAVariable(base_name="eax", version=0),
            SSAVariable(base_name="eax", version=1),
        ]
        phi = PhiFunction(result=result, operands=operands, block_address=0x1000)
        assert phi.result == result
        assert len(phi.operands) == 2
        assert phi.block_address == 0x1000

    def test_phi_function_repr(self):
        result = SSAVariable(base_name="eax", version=2)
        operands = [
            SSAVariable(base_name="eax", version=0),
            SSAVariable(base_name="eax", version=1),
        ]
        phi = PhiFunction(result=result, operands=operands, block_address=0x1000)
        assert "eax_2" in repr(phi)
        assert "eax_0" in repr(phi)
        assert "eax_1" in repr(phi)

    def test_phi_function_to_dict(self):
        result = SSAVariable(base_name="eax", version=2)
        operands = [
            SSAVariable(base_name="eax", version=0),
            SSAVariable(base_name="eax", version=1),
        ]
        phi = PhiFunction(result=result, operands=operands, block_address=0x1000)
        d = phi.to_dict()
        assert d["result"] == "eax_2"
        assert len(d["operands"]) == 2
        assert "0x1000" in d["block_address"]


class TestSSABlock:
    def test_ssa_block_creation(self):
        block = SSABlock(address=0x1000)
        assert block.address == 0x1000
        assert len(block.instructions) == 0
        assert len(block.phi_functions) == 0
        assert len(block.definitions) == 0

    def test_ssa_block_with_instructions(self):
        instructions = [
            {"offset": 0x1000, "disasm": "mov eax, 1"},
            {"offset": 0x1002, "disasm": "mov ebx, 2"},
        ]
        block = SSABlock(address=0x1000, instructions=instructions)
        assert len(block.instructions) == 2

    def test_ssa_block_with_phi_functions(self):
        phi = PhiFunction(
            result=SSAVariable(base_name="eax", version=2),
            operands=[SSAVariable(base_name="eax", version=0)],
            block_address=0x1000,
        )
        block = SSABlock(address=0x1000, phi_functions=[phi])
        assert len(block.phi_functions) == 1

    def test_ssa_block_with_edges(self):
        block = SSABlock(
            address=0x1000,
            predecessors=[0x900],
            successors=[0x1100, 0x1200],
        )
        assert len(block.predecessors) == 1
        assert len(block.successors) == 2

    def test_ssa_block_to_dict(self):
        block = SSABlock(address=0x1000)
        d = block.to_dict()
        assert "0x1000" in d["address"]


class TestSSAConverter:
    @pytest.fixture
    def converter(self):
        return SSAConverter()

    def test_converter_initialization(self, converter):
        assert converter._version_counter == {}
        assert converter._current_def == {}
        assert len(converter._sealed_blocks) == 0

    def test_convert_simple_cfg(self, converter):
        blocks = {
            0x1000: {
                "instructions": [{"offset": 0x1000, "disasm": "mov eax, 1"}],
                "predecessors": [],
                "successors": [],
            }
        }
        cfg_edges = []

        result = converter.convert_to_ssa(blocks, cfg_edges)

        assert 0x1000 in result

    def test_convert_linear_cfg(self, converter):
        blocks = {
            0x1000: {
                "instructions": [{"offset": 0x1000, "disasm": "mov eax, 1"}],
                "predecessors": [],
                "successors": [0x1005],
            },
            0x1005: {
                "instructions": [{"offset": 0x1005, "disasm": "mov ebx, eax"}],
                "predecessors": [0x1000],
                "successors": [],
            },
        }
        cfg_edges = [(0x1000, 0x1005)]

        result = converter.convert_to_ssa(blocks, cfg_edges)

        assert len(result) == 2
        assert 0x1000 in result
        assert 0x1005 in result

    def test_convert_with_branch(self, converter):
        blocks = {
            0x1000: {
                "instructions": [{"offset": 0x1000, "disasm": "mov eax, 1"}],
                "predecessors": [],
                "successors": [0x1005, 0x1010],
            },
            0x1005: {
                "instructions": [{"offset": 0x1005, "disasm": "mov ebx, 2"}],
                "predecessors": [0x1000],
                "successors": [0x1020],
            },
            0x1010: {
                "instructions": [{"offset": 0x1010, "disasm": "mov ebx, 3"}],
                "predecessors": [0x1000],
                "successors": [0x1020],
            },
            0x1020: {
                "instructions": [{"offset": 0x1020, "disasm": "add ecx, ebx"}],
                "predecessors": [0x1005, 0x1010],
                "successors": [],
            },
        }
        cfg_edges = [
            (0x1000, 0x1005),
            (0x1000, 0x1010),
            (0x1005, 0x1020),
            (0x1010, 0x1020),
        ]

        result = converter.convert_to_ssa(blocks, cfg_edges)

        assert len(result) == 4

    def test_get_new_version(self, converter):
        v0 = converter._get_new_version("eax")
        assert v0 == 0

        v1 = converter._get_new_version("eax")
        assert v1 == 1

        v2 = converter._get_new_version("eax")
        assert v2 == 2

    def test_get_current_version(self, converter):
        converter._get_new_version("eax")
        converter._get_new_version("eax")
        converter._get_new_version("eax")

        current = converter._get_current_version("eax")
        assert current == 2

        new_reg = converter._get_current_version("ebx")
        assert new_reg == 0

    def test_extract_defined_registers_mov(self, converter):
        defined = converter._extract_defined_registers("mov eax, 1")
        assert "eax" in defined

    def test_extract_defined_registers_lea(self, converter):
        defined = converter._extract_defined_registers("lea eax, [ebx]")
        assert "eax" in defined

    def test_extract_defined_registers_pop(self, converter):
        defined = converter._extract_defined_registers("pop eax")
        assert "eax" in defined

    def test_extract_used_registers(self, converter):
        used = converter._extract_used_registers("mov eax, ebx")
        assert "ebx" in used

    def test_extract_used_registers_multiple(self, converter):
        used = converter._extract_used_registers("mov eax, ebx, ecx")
        assert "ebx" in used
        assert "ecx" in used

    def test_extract_used_registers_64bit(self, converter):
        used = converter._extract_used_registers("mov rax, rbx")
        assert "rbx" in used

    def test_get_ssa_variable_at(self, converter):
        blocks = {
            0x1000: SSABlock(
                address=0x1000,
                definitions={"eax": SSAVariable(base_name="eax", version=1)},
            )
        }

        var = converter.get_ssa_variable_at("eax", 0x1000, blocks)
        assert var is not None
        assert var.base_name == "eax"

    def test_get_ssa_variable_at_not_found(self, converter):
        blocks = {0x1000: SSABlock(address=0x1000)}

        var = converter.get_ssa_variable_at("nonexistent", 0x1000, blocks)
        assert var is None

    def test_get_all_versions(self, converter):
        blocks = {
            0x1000: SSABlock(
                address=0x1000,
                definitions={"eax": SSAVariable(base_name="eax", version=0)},
            ),
            0x1005: SSABlock(
                address=0x1005,
                definitions={"eax": SSAVariable(base_name="eax", version=1)},
            ),
        }

        versions = converter.get_all_versions("eax", blocks)
        assert len(versions) == 2
        assert versions[0].version == 0
        assert versions[1].version == 1

    def test_compute_live_variables_ssa_single_block(self, converter):
        blocks = {
            0x1000: SSABlock(
                address=0x1000,
                instructions=[{"disasm": "mov eax, 1"}],
            )
        }

        live_info = converter.compute_live_variables_ssa(blocks)

        assert 0x1000 in live_info
        live_in, live_out = live_info[0x1000]
        assert isinstance(live_in, set)
        assert isinstance(live_out, set)

    def test_compute_live_variables_ssa_multiple_blocks(self, converter):
        blocks = {
            0x1000: SSABlock(
                address=0x1000,
                instructions=[{"disasm": "mov eax, 1"}],
                successors=[0x1005],
            ),
            0x1005: SSABlock(
                address=0x1005,
                instructions=[{"disasm": "add ebx, eax"}],
                predecessors=[0x1000],
            ),
        }

        live_info = converter.compute_live_variables_ssa(blocks)

        assert len(live_info) == 2


class TestSSAIntegration:
    @pytest.fixture
    def converter(self):
        return SSAConverter()

    def test_full_ssa_conversion(self, converter):
        blocks = {
            0x1000: {
                "instructions": [
                    {"offset": 0x1000, "disasm": "mov eax, 1"},
                    {"offset": 0x1002, "disasm": "mov ebx, 2"},
                ],
                "predecessors": [],
                "successors": [0x1008],
            },
            0x1008: {
                "instructions": [
                    {"offset": 0x1008, "disasm": "add ecx, eax"},
                    {"offset": 0x100A, "disasm": "add ecx, ebx"},
                ],
                "predecessors": [0x1000],
                "successors": [],
            },
        }

        result = converter.convert_to_ssa(blocks, [(0x1000, 0x1008)])

        assert len(result) == 2
        assert 0x1000 in result
        assert 0x1008 in result

    def test_convert_empty_cfg(self, converter):
        blocks = {}
        cfg_edges = []

        result = converter.convert_to_ssa(blocks, cfg_edges)

        assert result == {}
