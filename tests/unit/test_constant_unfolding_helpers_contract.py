from r2morph.mutations.constant_unfolding_helpers import (
    calculate_sequence_size,
    get_reg_mapping,
    match_unfold_pattern,
    select_candidates,
    unfold_constant_add,
    unfold_constant_sub,
    unfold_one,
    unfold_zero,
)


class _Binary:
    def get_function_disasm(self, addr: int):
        if addr == 0x1000:
            return [
                {"disasm": "mov eax, 0"},
                {"disasm": "add eax, 3"},
            ]
        if addr == 0x2000:
            return [{"disasm": "mov rax, 1"}]
        raise ValueError(addr)

    def assemble(self, insn: str, base_addr: int):
        return {"xor eax, eax": b"\x31\xc0", "inc eax": b"\x40", "dec eax": b"\x48", "add eax, 1": b"\x83\xc0\x01"}.get(
            insn
        )


def test_constant_unfolding_helpers_cover_the_core_paths() -> None:
    binary = _Binary()
    functions = [{"name": "main", "addr": 0x1000, "size": 64}, {"name": "tiny", "addr": 0x2000, "size": 4}]

    assert get_reg_mapping(64)["rax"]
    assert unfold_zero("eax", 32, binary, 0x1000)
    assert unfold_one("eax", 32, binary, 0x1000)
    assert unfold_constant_add("eax", 3, 32, 10) == ["inc eax", "inc eax", "inc eax"]
    assert unfold_constant_sub("eax", 2, 32, 10) == ["dec eax", "dec eax"]
    assert calculate_sequence_size(["xor eax, eax", "inc eax"], binary, 0x1000) == 3
    unfolded, is_constant = match_unfold_pattern("mov eax, 0", 32, binary, 0x1000, 10)
    assert is_constant is True
    assert unfolded
    assert select_candidates(binary, functions, 2)[0][0]["name"] == "main"
