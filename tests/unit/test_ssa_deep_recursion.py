"""
Regression tests: SSA renaming must survive deep control-flow graphs.

r2morph analyzes real (often malicious) binaries. A single function —
especially a control-flow-flattened or heavily obfuscated one, exactly
the kind r2morph targets — can have a CFG whose longest simple path is
far deeper than CPython's default recursion limit (~1000 frames).
``SSAConverter._rename_in_block`` performed a recursive DFS over CFG
successors, so such a function raised ``RecursionError`` and crashed SSA
construction.

These tests drive the public ``convert_to_ssa`` API only (no mocks, no
monkeypatch). Before the iterative rewrite the deep-CFG cases raised
``RecursionError``; afterwards they complete and the behavior on small
graphs (including the path-sensitive reprocessing of blocks reachable by
multiple acyclic paths) is unchanged.
"""

from r2morph.analysis.ssa import SSAConverter

DEEP = 6000
BASE = 0x1000
STRIDE = 0x10


def _linear_blocks(n: int) -> tuple[dict[int, dict[str, object]], list[tuple[int, int]]]:
    addrs = [BASE + i * STRIDE for i in range(n)]
    blocks: dict[int, dict[str, object]] = {}
    edges: list[tuple[int, int]] = []
    for i, addr in enumerate(addrs):
        succ = [addrs[i + 1]] if i + 1 < n else []
        pred = [addrs[i - 1]] if i > 0 else []
        blocks[addr] = {
            "instructions": [{"offset": addr, "disasm": "mov eax, ebx"}],
            "predecessors": pred,
            "successors": succ,
        }
        if succ:
            edges.append((addr, succ[0]))
    return blocks, edges


def test_ssa_deep_linear_cfg_no_recursion_error() -> None:
    blocks, edges = _linear_blocks(DEEP)

    result = SSAConverter().convert_to_ssa(blocks, edges)

    assert len(result) == DEEP
    assert set(result) == set(blocks)


def test_ssa_deep_cyclic_cfg_no_recursion_error() -> None:
    """Deep chain that loops back to the entry. The per-path `visited`
    set breaks the cycle; the traversal must terminate without
    RecursionError and still produce every SSA block."""
    blocks, edges = _linear_blocks(DEEP)
    addrs = sorted(blocks)
    last, first = addrs[-1], addrs[0]
    # `first` is the chain entry, so it had no predecessors; assigning
    # fresh lists avoids reading the object-typed mapping values.
    blocks[last]["successors"] = [first]
    blocks[first]["predecessors"] = [last]
    edges.append((last, first))

    result = SSAConverter().convert_to_ssa(blocks, edges)

    assert len(result) == DEEP


def test_ssa_linear_small_preserved() -> None:
    """Behavior-preservation: small linear CFG returns every block
    (independent, mock-free echo of the existing test_ssa contract)."""
    blocks, edges = _linear_blocks(3)

    result = SSAConverter().convert_to_ssa(blocks, edges)

    assert set(result) == set(blocks)
    assert len(result) == 3


def test_ssa_diamond_shared_block_reachable() -> None:
    """Behavior-preservation: a diamond (entry -> b, entry -> c, b -> d,
    c -> d). The shared block d is reprocessed once per acyclic path by
    the original path-sensitive DFS; the rewrite must still return all
    four blocks and not raise."""
    entry, b, c, d = BASE, BASE + 0x10, BASE + 0x20, BASE + 0x30
    blocks: dict[int, dict[str, object]] = {
        entry: {"instructions": [{"offset": entry, "disasm": "mov eax, 1"}], "predecessors": [], "successors": [b, c]},
        b: {"instructions": [{"offset": b, "disasm": "mov ebx, 2"}], "predecessors": [entry], "successors": [d]},
        c: {"instructions": [{"offset": c, "disasm": "mov ebx, 3"}], "predecessors": [entry], "successors": [d]},
        d: {"instructions": [{"offset": d, "disasm": "add ecx, ebx"}], "predecessors": [b, c], "successors": []},
    }
    edges = [(entry, b), (entry, c), (b, d), (c, d)]

    result = SSAConverter().convert_to_ssa(blocks, edges)

    assert set(result) == {entry, b, c, d}
