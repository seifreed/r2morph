"""
Unit tests for SSA (Static Single Assignment) form generation.
"""

import pytest

from r2morph.analysis.ssa import PhiFunction, SSABlock, SSAConverter, SSAVariable
from tests.utils.assertions import expect

_EXPECTED_BLOCK_ADDRESS_4096 = 0x1000
_EXPECTED_CURRENT_2 = 2
_EXPECTED_LEN_BLOCK_INSTRUCTIONS_2 = 2
_EXPECTED_LEN_BLOCK_SUCCESSORS_2 = 2
_EXPECTED_LEN_D_OPERANDS_2 = 2
_EXPECTED_LEN_EAX_PHI_OPERANDS_2 = 2
_EXPECTED_LEN_LIVE_INFO_2 = 2
_EXPECTED_LEN_PHI_OPERANDS_2 = 2
_EXPECTED_LEN_RESULT_2 = 2
_EXPECTED_LEN_RESULT_2_2 = 2
_EXPECTED_LEN_RESULT_4 = 4
_EXPECTED_LEN_VERSIONS_2 = 2
_EXPECTED_LIVE_INFO_4096 = 0x1000
_EXPECTED_PHI_BLOCK_ADDRESS_4096 = 0x1000
_EXPECTED_RESULT_4096 = 0x1000
_EXPECTED_RESULT_4096_2 = 0x1000
_EXPECTED_RESULT_4096_3 = 0x1000
_EXPECTED_RESULT_4101 = 0x1005
_EXPECTED_RESULT_4104 = 0x1008
_EXPECTED_V2_2 = 2
_EXPECTED_VAR_DEFINITION_ADDRESS_4096 = 0x1000


class TestSSAVariable:
    def test_ssa_variable_creation(self):
        var = SSAVariable(base_name="eax", version=0)
        expect(var.base_name == "eax")
        expect(var.version == 0)

    def test_ssa_variable_repr(self):
        var = SSAVariable(base_name="eax", version=1)
        expect(repr(var) == "eax_1")

    def test_ssa_variable_equality(self):
        var1 = SSAVariable(base_name="eax", version=1)
        var2 = SSAVariable(base_name="eax", version=1)
        var3 = SSAVariable(base_name="eax", version=2)
        var4 = SSAVariable(base_name="ebx", version=1)

        expect(var1 == var2)
        expect(var1 != var3)
        expect(var1 != var4)

    def test_ssa_variable_hash(self):
        var1 = SSAVariable(base_name="eax", version=1)
        var2 = SSAVariable(base_name="eax", version=1)
        var3 = SSAVariable(base_name="eax", version=2)

        d = {var1: "first"}
        expect(d[var2] == "first")
        expect(var3 not in d)

    def test_ssa_variable_with_definition_address(self):
        var = SSAVariable(base_name="eax", version=1, definition_address=0x1000)
        expect(var.definition_address == _EXPECTED_VAR_DEFINITION_ADDRESS_4096)

    def test_ssa_variable_with_original_register(self):
        var = SSAVariable(base_name="r0", version=1, original_register="x0")
        expect(var.original_register == "x0")


class TestPhiFunction:
    def test_phi_function_creation(self):
        result = SSAVariable(base_name="eax", version=2)
        operands = [
            SSAVariable(base_name="eax", version=0),
            SSAVariable(base_name="eax", version=1),
        ]
        phi = PhiFunction(result=result, operands=operands, block_address=0x1000)
        expect(phi.result == result)
        expect(len(phi.operands) == _EXPECTED_LEN_PHI_OPERANDS_2)
        expect(phi.block_address == _EXPECTED_PHI_BLOCK_ADDRESS_4096)

    def test_phi_function_repr(self):
        result = SSAVariable(base_name="eax", version=2)
        operands = [
            SSAVariable(base_name="eax", version=0),
            SSAVariable(base_name="eax", version=1),
        ]
        phi = PhiFunction(result=result, operands=operands, block_address=0x1000)
        expect(not ("eax_2" not in repr(phi)))
        expect(not ("eax_0" not in repr(phi)))
        expect(not ("eax_1" not in repr(phi)))

    def test_phi_function_to_dict(self):
        result = SSAVariable(base_name="eax", version=2)
        operands = [
            SSAVariable(base_name="eax", version=0),
            SSAVariable(base_name="eax", version=1),
        ]
        phi = PhiFunction(result=result, operands=operands, block_address=0x1000)
        d = phi.to_dict()
        expect(d["result"] == "eax_2")
        expect(len(d["operands"]) == _EXPECTED_LEN_D_OPERANDS_2)
        expect(not ("0x1000" not in d["block_address"]))


class TestSSABlock:
    def test_ssa_block_creation(self):
        block = SSABlock(address=0x1000)
        expect(block.address == _EXPECTED_BLOCK_ADDRESS_4096)
        expect(len(block.instructions) == 0)
        expect(len(block.phi_functions) == 0)
        expect(len(block.definitions) == 0)

    def test_ssa_block_with_instructions(self):
        instructions = [
            {"offset": 0x1000, "disasm": "mov eax, 1"},
            {"offset": 0x1002, "disasm": "mov ebx, 2"},
        ]
        block = SSABlock(address=0x1000, instructions=instructions)
        expect(len(block.instructions) == _EXPECTED_LEN_BLOCK_INSTRUCTIONS_2)

    def test_ssa_block_with_phi_functions(self):
        phi = PhiFunction(
            result=SSAVariable(base_name="eax", version=2),
            operands=[SSAVariable(base_name="eax", version=0)],
            block_address=0x1000,
        )
        block = SSABlock(address=0x1000, phi_functions=[phi])
        expect(len(block.phi_functions) == 1)

    def test_ssa_block_with_edges(self):
        block = SSABlock(
            address=0x1000,
            predecessors=[0x900],
            successors=[0x1100, 0x1200],
        )
        expect(len(block.predecessors) == 1)
        expect(len(block.successors) == _EXPECTED_LEN_BLOCK_SUCCESSORS_2)

    def test_ssa_block_to_dict(self):
        block = SSABlock(address=0x1000)
        d = block.to_dict()
        expect(not ("0x1000" not in d["address"]))


class TestSSAConverter:
    @pytest.fixture
    def converter(self):
        return SSAConverter()

    def test_converter_initialization(self, converter):
        expect(converter._version_counter == {})
        expect(converter._current_def == {})
        expect(len(converter._sealed_blocks) == 0)

    def test_convert_simple_cfg(self, converter):
        blocks = {
            0x1000: {
                "instructions": [{"offset": 0x1000, "disasm": "mov eax, 1"}],
                "predecessors": [],
                "successors": [],
            }
        }

        result = converter.convert_to_ssa(blocks)

        expect(not (_EXPECTED_RESULT_4096 not in result))

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

        result = converter.convert_to_ssa(blocks)

        expect(len(result) == _EXPECTED_LEN_RESULT_2)
        expect(not (_EXPECTED_RESULT_4096_2 not in result))
        expect(not (_EXPECTED_RESULT_4101 not in result))

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

        result = converter.convert_to_ssa(blocks)

        expect(len(result) == _EXPECTED_LEN_RESULT_4)

    def test_get_new_version(self, converter):
        v0 = converter._get_new_version("eax")
        expect(v0 == 0)

        v1 = converter._get_new_version("eax")
        expect(v1 == 1)

        v2 = converter._get_new_version("eax")
        expect(v2 == _EXPECTED_V2_2)

    def test_get_current_version(self, converter):
        converter._get_new_version("eax")
        converter._get_new_version("eax")
        converter._get_new_version("eax")

        current = converter._get_current_version("eax")
        expect(current == _EXPECTED_CURRENT_2)

        new_reg = converter._get_current_version("ebx")
        expect(new_reg == 0)

    def test_extract_defined_registers_mov(self, converter):
        defined = converter._extract_defined_registers("mov eax, 1")
        expect(not ("eax" not in defined))

    def test_extract_defined_registers_lea(self, converter):
        defined = converter._extract_defined_registers("lea eax, [ebx]")
        expect(not ("eax" not in defined))

    def test_extract_defined_registers_pop(self, converter):
        defined = converter._extract_defined_registers("pop eax")
        expect(not ("eax" not in defined))

    def test_extract_defined_registers_read_modify_write(self, converter):
        defined = converter._extract_defined_registers("add eax, ebx")
        expect(defined == {"eax"})

    def test_extract_used_registers(self, converter):
        used = converter._extract_used_registers("mov eax, ebx")
        expect(not ("ebx" not in used))

    def test_extract_used_registers_multiple(self, converter):
        used = converter._extract_used_registers("mov eax, ebx, ecx")
        expect(not ("ebx" not in used))
        expect(not ("ecx" not in used))

    def test_extract_used_registers_64bit(self, converter):
        used = converter._extract_used_registers("mov rax, rbx")
        expect(not ("rbx" not in used))

    def test_extract_used_registers_read_modify_write_destination(self, converter):
        used = converter._extract_used_registers("add eax, ebx")
        expect(used == {"eax", "ebx"})

    def test_get_ssa_variable_at(self, converter):
        blocks = {
            0x1000: SSABlock(
                address=0x1000,
                definitions={"eax": SSAVariable(base_name="eax", version=1)},
            )
        }

        var = converter.get_ssa_variable_at("eax", 0x1000, blocks)
        expect(var is not None)
        expect(var.base_name == "eax")

    def test_get_ssa_variable_at_not_found(self, converter):
        blocks = {0x1000: SSABlock(address=0x1000)}

        var = converter.get_ssa_variable_at("nonexistent", 0x1000, blocks)
        expect(not (var is not None))

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
        expect(len(versions) == _EXPECTED_LEN_VERSIONS_2)
        expect(versions[0].version == 0)
        expect(versions[1].version == 1)

    def test_compute_live_variables_ssa_single_block(self, converter):
        blocks = {
            0x1000: SSABlock(
                address=0x1000,
                instructions=[{"disasm": "mov eax, 1"}],
            )
        }

        live_info = converter.compute_live_variables_ssa(blocks)

        expect(not (_EXPECTED_LIVE_INFO_4096 not in live_info))
        live_in, live_out = live_info[0x1000]
        expect(isinstance(live_in, set))
        expect(isinstance(live_out, set))

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

        expect(len(live_info) == _EXPECTED_LEN_LIVE_INFO_2)


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

        result = converter.convert_to_ssa(blocks)

        expect(len(result) == _EXPECTED_LEN_RESULT_2_2)
        expect(not (_EXPECTED_RESULT_4096_3 not in result))
        expect(not (_EXPECTED_RESULT_4104 not in result))

    def test_convert_empty_cfg(self, converter):
        blocks = {}

        result = converter.convert_to_ssa(blocks)

        expect(result == {})


class TestPhiPlacement:
    @pytest.fixture
    def converter(self):
        return SSAConverter()

    def test_convert_places_phi_at_merge_for_register_defined_on_both_branches(self, converter):
        blocks = {
            0x1000: {
                "instructions": [{"offset": 0x1000, "disasm": "cmp edi, 0"}],
                "predecessors": [],
                "successors": [0x1010, 0x1020],
            },
            0x1010: {
                "instructions": [{"offset": 0x1010, "disasm": "mov eax, 1"}],
                "predecessors": [0x1000],
                "successors": [0x1030],
            },
            0x1020: {
                "instructions": [{"offset": 0x1020, "disasm": "mov eax, 2"}],
                "predecessors": [0x1000],
                "successors": [0x1030],
            },
            0x1030: {
                "instructions": [{"offset": 0x1030, "disasm": "mov ebx, eax"}],
                "predecessors": [0x1010, 0x1020],
                "successors": [],
            },
        }

        result = converter.convert_to_ssa(blocks)

        phi_targets = {phi.result.base_name for phi in result[0x1030].phi_functions}
        expect(not ("eax" not in phi_targets))

    def test_convert_phi_has_one_operand_per_predecessor(self, converter):
        blocks = {
            0x1000: {
                "instructions": [{"offset": 0x1000, "disasm": "cmp edi, 0"}],
                "predecessors": [],
                "successors": [0x1010, 0x1020],
            },
            0x1010: {
                "instructions": [{"offset": 0x1010, "disasm": "mov eax, 1"}],
                "predecessors": [0x1000],
                "successors": [0x1030],
            },
            0x1020: {
                "instructions": [{"offset": 0x1020, "disasm": "mov eax, 2"}],
                "predecessors": [0x1000],
                "successors": [0x1030],
            },
            0x1030: {
                "instructions": [{"offset": 0x1030, "disasm": "mov ebx, eax"}],
                "predecessors": [0x1010, 0x1020],
                "successors": [],
            },
        }

        result = converter.convert_to_ssa(blocks)

        eax_phi = next(phi for phi in result[0x1030].phi_functions if phi.result.base_name == "eax")
        expect(len(eax_phi.operands) == _EXPECTED_LEN_EAX_PHI_OPERANDS_2)
