"""
Regression tests: CallGraph traversals must survive deep call graphs.

r2morph analyzes real (often malicious) binaries whose call graphs can be
far deeper than Python's default recursion limit (~1000 frames). Any
traversal implemented as unbounded recursion raises ``RecursionError`` on
such input, crashing the public analysis API.

These tests build a deep linear call chain purely through the public
``add_node`` / ``add_edge`` API (no mocks, no monkeypatch) and assert the
traversal both survives and returns a correct result.

Before the iterative rewrite ``topological_sort`` recursed once per chain
node and raised ``RecursionError`` on this input; afterwards it returns a
valid topological order.
"""

from r2morph.analysis.call_graph import CallEdge, CallGraph, CallNode, CallType

# Chain length comfortably beyond CPython's default recursion limit so the
# recursive implementation is guaranteed to overflow the interpreter stack.
CHAIN_LENGTH = 6000
BASE_ADDRESS = 0x1000
STRIDE = 0x10


def _build_linear_chain(length: int) -> tuple[CallGraph, list[int]]:
    """Build f0 -> f1 -> ... -> f(length-1) where fi calls f(i+1)."""
    cg = CallGraph()
    addresses = [BASE_ADDRESS + i * STRIDE for i in range(length)]
    for i, addr in enumerate(addresses):
        cg.add_node(CallNode(address=addr, name=f"f{i}"))
    for caller, callee in zip(addresses, addresses[1:]):
        cg.add_edge(CallEdge(caller, callee, CallType.DIRECT))
    return cg, addresses


def test_topological_sort_deep_chain_no_recursion_error() -> None:
    cg, addresses = _build_linear_chain(CHAIN_LENGTH)

    order = cg.topological_sort()

    assert len(order) == CHAIN_LENGTH
    assert set(order) == set(addresses)
    # Every callee must precede its caller in a valid topological order.
    position = {addr: idx for idx, addr in enumerate(order)}
    for caller, callee in zip(addresses, addresses[1:]):
        assert position[callee] < position[caller]


def test_topological_sort_small_chain_orders_callees_first() -> None:
    """Behavior-preservation check on a small graph (same contract as the
    pre-existing topological_sort test, independent of mocks)."""
    cg, addresses = _build_linear_chain(4)

    order = cg.topological_sort()

    assert order == list(reversed(addresses))


def test_topological_sort_diamond_is_valid() -> None:
    """Diamond: a -> b, a -> c, b -> d, c -> d. Every edge respected."""
    a, b, c, d = 0x1000, 0x1010, 0x1020, 0x1030
    cg = CallGraph()
    for addr, name in ((a, "a"), (b, "b"), (c, "c"), (d, "d")):
        cg.add_node(CallNode(address=addr, name=name))
    cg.add_edge(CallEdge(a, b, CallType.DIRECT))
    cg.add_edge(CallEdge(a, c, CallType.DIRECT))
    cg.add_edge(CallEdge(b, d, CallType.DIRECT))
    cg.add_edge(CallEdge(c, d, CallType.DIRECT))

    order = cg.topological_sort()

    assert len(order) == 4
    position = {addr: idx for idx, addr in enumerate(order)}
    for caller, callee in ((a, b), (a, c), (b, d), (c, d)):
        assert position[callee] < position[caller]


def test_get_depth_deep_chain_no_recursion_error() -> None:
    cg, addresses = _build_linear_chain(CHAIN_LENGTH)

    # Depth of the root of an N-node linear chain is N - 1.
    assert cg.get_depth(addresses[0]) == CHAIN_LENGTH - 1
    assert cg.get_depth(addresses[-1]) == 0


def test_get_depth_small_chain_values() -> None:
    """Behavior-preservation: same contract as the pre-existing
    test_get_depth (callee-distance values), mock-free."""
    cg, addresses = _build_linear_chain(4)

    assert cg.get_depth(addresses[0]) == 3
    assert cg.get_depth(addresses[1]) == 2
    assert cg.get_depth(addresses[2]) == 1
    assert cg.get_depth(addresses[3]) == 0


def test_get_depth_diamond_preserves_shared_visited_semantics() -> None:
    """Diamond a->b, a->c, b->d, c->d. The recursive implementation shares
    one `visited` set across the whole descent (d, reached first via b, is
    pruned when reached again via c), yielding depth 2. The iterative
    rewrite must reproduce this exact value, not a pure longest path."""
    a, b, c, d = 0x1000, 0x1010, 0x1020, 0x1030
    cg = CallGraph()
    for addr, name in ((a, "a"), (b, "b"), (c, "c"), (d, "d")):
        cg.add_node(CallNode(address=addr, name=name))
    cg.add_edge(CallEdge(a, b, CallType.DIRECT))
    cg.add_edge(CallEdge(a, c, CallType.DIRECT))
    cg.add_edge(CallEdge(b, d, CallType.DIRECT))
    cg.add_edge(CallEdge(c, d, CallType.DIRECT))

    assert cg.get_depth(a) == 2
    assert cg.get_depth(b) == 1
    assert cg.get_depth(d) == 0


def test_get_depth_handles_cycles() -> None:
    """Self-referential cycle a->b, b->a. The shared `visited` set breaks
    the cycle; get_depth(a) is 2 (a -> b -> a, second a pruned)."""
    a, b = 0x2000, 0x2010
    cg = CallGraph()
    cg.add_node(CallNode(address=a, name="a"))
    cg.add_node(CallNode(address=b, name="b"))
    cg.add_edge(CallEdge(a, b, CallType.DIRECT))
    cg.add_edge(CallEdge(b, a, CallType.DIRECT))

    assert cg.get_depth(a) == 2


def test_find_call_path_deep_chain_no_recursion_error() -> None:
    cg, addresses = _build_linear_chain(CHAIN_LENGTH)

    path = cg.find_call_path(addresses[0], addresses[-1])

    assert path == addresses


def test_find_call_path_deep_chain_unreachable_returns_none() -> None:
    """Deep backtracking path must also survive: the recursive DFS
    descended the whole chain (RecursionError pre-fix) before reporting
    no path. Post-fix it returns None without raising."""
    cg, addresses = _build_linear_chain(CHAIN_LENGTH)
    isolated = addresses[-1] + 0x10
    cg.add_node(CallNode(address=isolated, name="isolated"))

    assert cg.find_call_path(addresses[0], isolated) is None


def test_find_call_path_src_equals_dst() -> None:
    """Behavior-preservation: src == dst yields the single-node path."""
    a = 0x1000
    cg = CallGraph()
    cg.add_node(CallNode(address=a, name="a"))

    assert cg.find_call_path(a, a) == [a]


def test_find_call_path_leftmost_dfs_order_preserved() -> None:
    """a -> b (dead end), a -> c -> d. The recursive DFS tries the
    leftmost callee first, backtracks out of b, then finds [a, c, d].
    The iterative rewrite must return the identical first-found path."""
    a, b, c, d = 0x1000, 0x1010, 0x1020, 0x1030
    cg = CallGraph()
    for addr, name in ((a, "a"), (b, "b"), (c, "c"), (d, "d")):
        cg.add_node(CallNode(address=addr, name=name))
    cg.add_edge(CallEdge(a, b, CallType.DIRECT))
    cg.add_edge(CallEdge(a, c, CallType.DIRECT))
    cg.add_edge(CallEdge(c, d, CallType.DIRECT))

    assert cg.find_call_path(a, d) == [a, c, d]


def test_find_call_path_no_path_small() -> None:
    """Behavior-preservation: same contract as the pre-existing
    test_find_call_path_no_path, mock-free."""
    a, b = 0x1000, 0x2000
    cg = CallGraph()
    cg.add_node(CallNode(address=a, name="a"))
    cg.add_node(CallNode(address=b, name="b"))

    assert cg.find_call_path(a, b) is None
