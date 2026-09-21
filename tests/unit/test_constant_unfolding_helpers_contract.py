from r2morph.mutations.constant_unfolding_helpers import (
    calculate_sequence_size,
    flags_preserved_for_unfold,
    get_reg_mapping,
    match_unfold_pattern,
    select_candidates,
    unfold_constant_add,
    unfold_constant_move,
    unfold_constant_sub,
    unfold_one,
    unfold_zero,
)
from tests.utils.assertions import expect

_EXPECTED_ADDR_4096 = 0x1000
_EXPECTED_ADDR_8192 = 0x2000
_EXPECTED_CALCULATE_SEQUENCE_SIZE_XOR_EAX_EAX_INC_EAX_B_3 = 3


class _Binary:
    def get_function_disasm(self, addr: int):
        if addr == _EXPECTED_ADDR_4096:
            return [
                {"disasm": "mov eax, 0"},
                {"disasm": "add eax, 3"},
            ]
        if addr == _EXPECTED_ADDR_8192:
            return [{"disasm": "mov rax, 1"}]
        raise ValueError(addr)

    def assemble(self, insn: str, base_addr: int):
        return {
            "xor eax, eax": b"\x31\xc0",
            "inc eax": b"\x40",
            "dec eax": b"\x48",
            "add eax, 1": b"\x83\xc0\x01",
            "orr w1, wzr, 64": b"\x21\x00\x01\x32",
            "movz w8, 93": b"\xa8\x0b\x80\x52",
            "movw r2, 40": b"\x28\x20\x00\xe3",
        }.get(insn)


def test_constant_unfolding_helpers_cover_the_core_paths() -> None:
    binary = _Binary()
    functions = [{"name": "main", "addr": 0x1000, "size": 64}, {"name": "tiny", "addr": 0x2000, "size": 4}]

    expect(get_reg_mapping(64)["rax"])
    expect(unfold_zero("eax", 32, binary, 0x1000))
    expect(unfold_one("eax", 32, binary, 0x1000))
    expect(unfold_constant_add("eax", 3, 32, 10) == ["inc eax", "inc eax", "inc eax"])
    expect(unfold_constant_sub("eax", 2, 32, 10) == ["dec eax", "dec eax"])
    expect(
        calculate_sequence_size(["xor eax, eax", "inc eax"], binary, 4096)
        == _EXPECTED_CALCULATE_SEQUENCE_SIZE_XOR_EAX_EAX_INC_EAX_B_3
    )
    unfolded, is_constant = match_unfold_pattern("mov eax, 0", 32, binary, 0x1000, 10)
    expect(not (is_constant is not True))
    expect(unfolded)
    expect(select_candidates(binary, functions, 2)[0][0]["name"] == "main")


def test_constant_unfolding_preserves_even_split_immediate() -> None:
    expect(unfold_constant_add("eax", 4, 32, 10) == ["add eax, 2", "add eax, 2"])


def test_constant_unfolding_preserves_uneven_split_immediate() -> None:
    expect(unfold_constant_sub("eax", 5, 32, 10) == ["sub eax, 2", "sub eax, 3"])


def test_constant_unfolding_rejects_flag_changing_split_when_flags_are_live() -> None:
    expect(not flags_preserved_for_unfold("sub eax, 10", ["sub eax, 5", "sub eax, 5"], True))


def test_constant_unfolding_accepts_flag_neutral_mov_when_flags_are_live() -> None:
    expect(flags_preserved_for_unfold("mov eax, 1", ["mov eax, 1"], True))


def test_constant_unfolding_rejects_arm32_one_without_in_place_equivalent() -> None:
    expect(unfold_one("r7", 32, _Binary(), _EXPECTED_ADDR_4096) is None)


def test_constant_unfolding_uses_arm64_alternate_constant_encoding() -> None:
    binary = _Binary()
    expect(
        unfold_constant_move("w1", 0x40, 64, binary, _EXPECTED_ADDR_4096) == ["orr w1, wzr, 64"]
        and match_unfold_pattern("mov w1, #0x40", 64, binary, _EXPECTED_ADDR_4096, 10) == (["orr w1, wzr, 64"], True)
    )


def test_constant_unfolding_uses_arm64_movz_for_non_logical_immediate() -> None:
    expect(unfold_constant_move("w8", 93, 64, _Binary(), _EXPECTED_ADDR_4096) == ["movz w8, 93"])


def test_constant_unfolding_uses_arm32_movw_for_fixed_width_constant() -> None:
    expect(unfold_constant_move("r2", 40, 32, _Binary(), _EXPECTED_ADDR_4096) == ["movw r2, 40"])
