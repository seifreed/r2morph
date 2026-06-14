import r2morph.mutations.nop_insertion_helpers as nop_helpers
from r2morph.mutations.nop_insertion_helpers import (
    generate_jmp_dead_code,
    init_nop_equivalents,
    is_safe_self_redundancy,
    select_candidates,
)


class _Binary:
    def get_function_disasm(self, addr: int):
        if addr == 0x1000:
            return [{"disasm": "mov eax, eax", "addr": 0x10, "size": 2, "type": "mov"}]
        if addr == 0x2000:
            return [{"disasm": "nop", "addr": 0x20, "size": 4, "type": "nop"}]
        raise ValueError(addr)

    def assemble(self, insn: str, function_addr: int | None = None):
        table = {
            "jmp 1": b"\xeb\x01",
            "inc eax": b"\x40",
            "push eax": b"\x50",
            "pop eax": b"\x58",
        }
        return table.get(insn)


def test_nop_insertion_helpers_cover_the_core_paths(monkeypatch) -> None:
    monkeypatch.setattr(nop_helpers.random, "choice", lambda seq: seq[0])
    monkeypatch.setattr(nop_helpers.random, "shuffle", lambda seq: None)

    binary = _Binary()
    functions = [
        {"name": "main", "offset": 0x1000, "size": 64},
        {"name": "tiny", "offset": 0x2000, "size": 4},
    ]

    assert is_safe_self_redundancy("eax", 32) is True
    assert is_safe_self_redundancy("rbx", 64) is False
    assert init_nop_equivalents()["x86"]
    assert generate_jmp_dead_code(3, 32, binary, 0x1000) is not None
    assert select_candidates(binary, functions, "x86", 32, 5)[0][0]["name"] == "main"
