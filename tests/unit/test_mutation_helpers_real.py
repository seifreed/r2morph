from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import BasicBlock
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass


def test_block_reordering_helpers():
    reorder = BlockReorderingPass({"probability": 1.0})

    func = {"size": 100}
    blocks = [{"addr": 0x1000, "size": 8}, {"addr": 0x1008, "size": 8}]

    assert reorder._can_reorder_function(func, blocks)

    new_order = reorder._generate_reordering(blocks)
    assert new_order[0] == 0

    cost = reorder._calculate_jump_cost([0, 1], [0, 1])
    assert cost == 0


def test_control_flow_flattening_helpers():
    cff = ControlFlowFlatteningPass({"probability": 1.0})

    assert cff._is_conditional_jump("je", "x86")
    assert cff._is_conditional_jump("b.ne", "arm")
    assert not cff._is_conditional_jump("jmp", "x86")

    instructions = [
        {"mnemonic": "nop", "offset": 0x1000, "size": 1},
        {"mnemonic": "nop", "offset": 0x1001, "size": 1},
        {"mnemonic": "nop", "offset": 0x1002, "size": 1},
        {"mnemonic": "mov", "offset": 0x1003, "size": 2},
    ]
    sequences = cff._find_nop_sequences(instructions)
    assert sequences

    x86_predicates = cff._get_x86_opaque_predicates(64)
    arm_predicates = cff._get_arm_opaque_predicates(64)
    assert x86_predicates
    assert arm_predicates

    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        blocks = [BasicBlock(address=0x1000, size=4), BasicBlock(address=0x1004, size=4)]
        dispatcher = cff._generate_dispatcher(bin_obj, blocks)
        assert dispatcher


def test_instruction_expansion_helpers():
    expander = InstructionExpansionPass()

    instruction = {"disasm": "mov eax, 1", "mnemonic": "mov"}
    expansions = expander._match_expansion_pattern(instruction, "x86")
    assert isinstance(expansions, list)

    built = expander._build_instruction_from_pattern(
        ("xor", "reg", "reg"),
        ["mov", "eax", "1"],
    )
    assert built is None or "xor" in built

    size_increase = expander._get_expansion_size_increase(
        [("mov", "eax", "1"), ("add", "eax", "1")]
    )
    assert size_increase >= 0

    safe = expander._is_safe_to_expand({"type": "nop"}, 200)
    assert isinstance(safe, bool)


def test_register_substitution_helpers():
    substituter = RegisterSubstitutionPass()

    reg_class = substituter._get_register_class("x86")
    assert "caller_saved" in reg_class

    instructions = [
        {"disasm": "mov eax, ebx"},
        {"disasm": "add eax, 1"},
        {"disasm": "mov ecx, eax"},
    ]

    candidates = substituter._find_substitution_candidates(instructions, "x86")
    assert isinstance(candidates, list)

    uses = substituter._count_register_uses(instructions, "eax")
    assert uses >= 1

    safe = substituter._is_safe_size_extension_substitution("movzx eax, bl", "eax", "ecx")
    assert isinstance(safe, bool)

    lea_safe = substituter._is_safe_lea_substitution("lea eax, [ebx]", "eax", "ecx")
    assert isinstance(lea_safe, bool)
