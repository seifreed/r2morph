"""
Call Graph construction for inter-procedural analysis.

Provides call graph construction and analysis capabilities:
- Direct call extraction
- Indirect call resolution
- Recursive call detection
- Caller/callee relationships
- Caching support for repeated analysis
"""

from __future__ import annotations

from typing import Any

from r2morph.analysis.call_graph_models import (
    CallEdge,
    CallNode,
    _DepthFrame,
    _PathFrame,
    _RecursionFrame,
    _SccFrame,
)
from r2morph.analysis.call_graph_models import (
    CallType as _CallType,
)
from r2morph.analysis.call_graph_models import (
    RecursionType as _RecursionType,
)
from r2morph.analysis.call_graph_serialization import (
    call_graph_from_dict,
    call_graph_from_json,
    call_graph_to_dict,
    call_graph_to_dot,
    call_graph_to_json,
)

RecursionType = _RecursionType
CallType = _CallType


class CallGraph:
    """
    Directed call graph for inter-procedural analysis.

    Stores relationships between functions:
    - Who calls each function (callers)
    - What each function calls (callees)
    - Recursive chains
    - Entry points

    Usage:
        cg = CallGraph()
        cg.build(binary)
        callers = cg.get_callers(func_addr)
        callees = cg.get_callees(func_addr)
    """

    def __init__(self) -> None:
        self.nodes: dict[int, CallNode] = {}
        self.edges: list[CallEdge] = []
        self.entry_points: list[int] = []
        self._call_sites: dict[int, list[int]] = {}
        self._indirect_targets: dict[int, list[int]] = {}
        self._recursive_chains: list[list[int]] = []
        self._strongly_connected: list[set[int]] = []

    def __repr__(self) -> str:
        return f"<CallGraph nodes={len(self.nodes)} edges={len(self.edges)}>"

    def add_node(self, node: CallNode) -> None:
        """Add a function node to the graph."""
        self.nodes[node.address] = node

    def add_edge(self, edge: CallEdge) -> None:
        """Add a call edge to the graph."""
        self.edges.append(edge)
        if edge.caller in self.nodes:
            caller = self.nodes[edge.caller]
            if edge.callee not in caller.callees:
                caller.callees.append(edge.callee)
        if edge.callee in self.nodes:
            callee = self.nodes[edge.callee]
            if edge.caller not in callee.callers:
                callee.callers.append(edge.caller)

    def get_node(self, address: int) -> CallNode | None:
        """Get a function node by address."""
        return self.nodes.get(address)

    def get_callers(self, address: int) -> list[int]:
        """
        Get addresses of functions that call the given function.

        Args:
            address: Function address

        Returns:
            List of caller function addresses
        """
        node = self.nodes.get(address)
        if node is None:
            return []
        return list(node.callers)

    def get_callees(self, address: int) -> list[int]:
        """
        Get addresses of functions called by the given function.

        Args:
            address: Function address

        Returns:
            List of callee function addresses
        """
        node = self.nodes.get(address)
        if node is None:
            return []
        return list(node.callees)

    def get_call_sites(self, caller: int, callee: int) -> list[int]:
        """
        Get addresses where caller calls callee.

        Args:
            caller: Caller function address
            callee: Callee function address

        Returns:
            List of call site addresses
        """
        sites = []
        for edge in self.edges:
            if edge.caller == caller and edge.callee == callee:
                sites.append(edge.call_site)
        return sites

    def get_entry_points(self) -> list[int]:
        """
        Get entry point functions (functions with no callers).

        Returns:
            List of entry point addresses
        """
        if self.entry_points:
            return self.entry_points
        self.entry_points = [addr for addr, node in self.nodes.items() if len(node.callers) == 0]
        return self.entry_points

    def get_leaf_functions(self) -> list[int]:
        """
        Get leaf functions (functions that don't call others).

        Returns:
            List of leaf function addresses
        """
        return [addr for addr, node in self.nodes.items() if len(node.callees) == 0]

    def find_recursive_functions(self) -> list[int]:
        """
        Find all recursive functions.

        Returns:
            List of recursive function addresses
        """
        self._detect_recursion()
        return [addr for addr, node in self.nodes.items() if node.is_recursive]

    def find_recursive_chains(self) -> list[list[int]]:
        """
        Find all recursive call chains.

        Returns:
            List of recursive chains (each chain is a list of function addresses)
        """
        self._detect_recursion()
        return self._recursive_chains

    def _detect_recursion(self) -> None:
        """Detect recursion in the call graph."""
        if self._recursive_chains:
            return

        visited: set[int] = set()
        rec_stack: set[int] = set()

        def enter(node_addr: int) -> CallNode | None:
            # Mirrors dfs() entry. When the node is missing, the recursive
            # version returns WITHOUT popping rec_stack, so the address
            # stays in both `visited` and `rec_stack` for the rest of the
            # traversal; that quirk is preserved by not removing it here.
            visited.add(node_addr)
            rec_stack.add(node_addr)
            return self.nodes.get(node_addr)

        def record_cycle(path: list[int], callee: int) -> None:
            cycle_start = path.index(callee) if callee in path else -1
            if cycle_start >= 0:
                cycle = path[cycle_start:] + [callee]
                self._recursive_chains.append(cycle)
                for addr in cycle:
                    if addr in self.nodes:
                        self.nodes[addr].is_recursive = True

        # An explicit stack replaces the interpreter call stack so deep
        # call graphs (routine in real binaries) no longer raise
        # RecursionError. `path` is kept in lockstep with the work stack,
        # so it is exactly the list the recursive dfs() carried; the
        # simulation is mechanically equivalent and produces identical
        # chains, is_recursive flags and recursion_depth for every input.
        for root in self.nodes:
            if root in visited:
                continue
            root_node = enter(root)
            if root_node is None:
                continue

            path: list[int] = [root]
            work: list[_RecursionFrame] = [_RecursionFrame(root, list(root_node.callees))]
            while work:
                frame = work[-1]
                if frame.idx < len(frame.callees):
                    callee = frame.callees[frame.idx]
                    frame.idx += 1
                    if callee not in visited:
                        callee_node = enter(callee)
                        if callee_node is not None:
                            path.append(callee)
                            work.append(_RecursionFrame(callee, list(callee_node.callees)))
                    elif callee in rec_stack:
                        record_cycle(path, callee)
                else:
                    rec_stack.remove(frame.node_addr)
                    work.pop()
                    path.pop()

        for chain in self._recursive_chains:
            for addr in chain:
                if addr in self.nodes:
                    self.nodes[addr].recursion_depth = max(self.nodes[addr].recursion_depth, len(chain) - 1)

    def find_strongly_connected_components(self) -> list[set[int]]:
        """
        Find strongly connected components (SCCs) in the call graph.

        SCCs represent groups of mutually recursive functions.

        Returns:
            List of SCCs (each SCC is a set of function addresses)
        """
        if self._strongly_connected:
            return self._strongly_connected

        index_counter = 0
        stack: list[int] = []
        lowlinks: dict[int, int] = {}
        index: dict[int, int] = {}
        on_stack: set[int] = set()

        def begin(node: int) -> None:
            nonlocal index_counter
            index[node] = index_counter
            lowlinks[node] = index_counter
            index_counter += 1
            stack.append(node)
            on_stack.add(node)

        def close_scc(root_node: int) -> None:
            scc: set[int] = set()
            while True:
                member = stack.pop()
                on_stack.remove(member)
                scc.add(member)
                if member == root_node:
                    break
            if len(scc) > 1:
                self._strongly_connected.append(scc)

        # Iterative Tarjan. An explicit work stack replaces the interpreter
        # call stack so deep call graphs (routine in real binaries) no
        # longer raise RecursionError. The simulation is mechanically
        # equivalent to the recursive strongconnect(): the post-recursion
        # `lowlink = min(lowlink, child lowlink)` is applied when each child
        # frame completes, so index/lowlink, SCC membership, the `len > 1`
        # filter and the append order are identical for every input.
        for root in self.nodes:
            if root in index:
                continue
            begin(root)
            root_obj = self.nodes.get(root)
            if root_obj is None:
                continue

            work: list[_SccFrame] = [_SccFrame(root, list(root_obj.callees))]
            while work:
                frame = work[-1]
                node = frame.node
                if frame.idx < len(frame.callees):
                    successor = frame.callees[frame.idx]
                    frame.idx += 1
                    if successor not in index:
                        begin(successor)
                        successor_obj = self.nodes.get(successor)
                        if successor_obj is None:
                            lowlinks[node] = min(lowlinks[node], lowlinks[successor])
                        else:
                            work.append(_SccFrame(successor, list(successor_obj.callees)))
                    elif successor in on_stack:
                        lowlinks[node] = min(lowlinks[node], index[successor])
                else:
                    if lowlinks[node] == index[node]:
                        close_scc(node)
                    work.pop()
                    if work:
                        parent = work[-1].node
                        lowlinks[parent] = min(lowlinks[parent], lowlinks[node])

        return self._strongly_connected

    def topological_sort(self) -> list[int]:
        """
        Topologically sort functions (callers before callees).

        Returns:
            List of function addresses in topological order
        """
        visited: set[int] = set()
        result: list[int] = []

        # Iterative post-order DFS. An explicit stack is used instead of
        # recursion because real (often malicious) binaries can produce call
        # chains far deeper than CPython's recursion limit; a recursive
        # walker would raise RecursionError on such input. Each node is
        # pushed once for expansion and once (post=True) for emission, so a
        # node is appended only after all its callees, preserving the exact
        # post-order the recursive implementation produced.
        for start in sorted(self.nodes.keys()):
            if start in visited or start not in self.nodes:
                continue
            stack: list[tuple[int, bool]] = [(start, False)]
            while stack:
                node, post = stack.pop()
                if post:
                    result.append(node)
                    continue
                if node in visited or node not in self.nodes:
                    continue
                visited.add(node)
                stack.append((node, True))
                for callee in reversed(self.nodes[node].callees):
                    if callee not in visited:
                        stack.append((callee, False))

        return result

    def find_call_path(self, src: int, dst: int) -> list[int] | None:
        """
        Find a call path between two functions.

        Args:
            src: Source function address
            dst: Destination function address

        Returns:
            List of function addresses forming the path, or None if no path exists
        """
        if src not in self.nodes or dst not in self.nodes:
            return None

        visited: set[int] = set()
        path: list[int] = []

        def descend(current: int) -> bool | None:
            # Mirrors the recursive dfs() early returns: True/False is the
            # value the recursive call would return immediately; None means
            # `current` passed the guards and needs its own frame (iterate
            # its callees). `visited`/`path` are mutated in exactly the same
            # order as the recursive implementation.
            if current == dst:
                path.append(current)
                return True
            if current in visited:
                return False
            visited.add(current)
            path.append(current)
            node = self.nodes.get(current)
            if node is None:
                path.pop()
                return False
            return None

        # An explicit stack replaces the interpreter call stack so deep
        # call graphs (routine in real binaries) no longer raise
        # RecursionError. The simulation is mechanically equivalent to the
        # recursive depth-first search, so it returns the identical
        # first-found path for every input.
        start = descend(src)
        if start is True:
            return path
        if start is False:
            return None

        stack: list[_PathFrame] = [_PathFrame(list(self.nodes[src].callees))]
        while stack:
            frame = stack[-1]
            if frame.idx < len(frame.callees):
                callee = frame.callees[frame.idx]
                frame.idx += 1
                result = descend(callee)
                if result is True:
                    return path
                if result is None:
                    stack.append(_PathFrame(list(self.nodes[callee].callees)))
            else:
                path.pop()
                stack.pop()

        return None

    def get_depth(self, address: int) -> int:
        """
        Get the maximum call depth from a function.

        Args:
            address: Function address

        Returns:
            Maximum depth of call chain from this function
        """
        visited: set[int] = set()

        def descend(node: int) -> int | None:
            # Mirrors the recursive base cases: returns the immediate
            # depth() value, or None when `node` needs its own frame
            # (passed the guards and has callees). `visited` is marked in
            # pre-order, exactly as the recursive implementation did.
            if node in visited:
                return 0
            if node not in self.nodes:
                return 0
            visited.add(node)
            if not self.nodes[node].callees:
                return 0
            return None

        # An explicit stack replaces the interpreter call stack so deep
        # call graphs (routine in real binaries) no longer raise
        # RecursionError. The simulation is mechanically equivalent to the
        # recursive descent — same shared `visited` set, same left-to-right
        # max over callees — so the returned depth is identical for every
        # input.
        root = descend(address)
        if root is not None:
            return root

        stack: list[_DepthFrame] = [_DepthFrame(list(self.nodes[address].callees))]
        returned = 0
        while stack:
            frame = stack[-1]
            if frame.idx < len(frame.callees):
                callee = frame.callees[frame.idx]
                frame.idx += 1
                child = descend(callee)
                if child is None:
                    stack.append(_DepthFrame(list(self.nodes[callee].callees)))
                elif child > frame.best:
                    frame.best = child
            else:
                returned = 1 + frame.best
                stack.pop()
                if stack and returned > stack[-1].best:
                    stack[-1].best = returned

        return returned

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return call_graph_to_dict(self)

    def to_dot(self) -> str:
        """
        Generate GraphViz DOT representation.

        Returns:
            DOT format string
        """
        return call_graph_to_dot(self)

    def to_json(self) -> str:
        """
        Serialize to JSON string for caching.

        Returns:
            JSON string representation
        """
        return call_graph_to_json(self)

    @classmethod
    def from_json(cls, json_str: str) -> CallGraph:
        """
        Deserialize from JSON string.

        Args:
            json_str: JSON string representation

        Returns:
            CallGraph instance
        """
        return call_graph_from_json(json_str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CallGraph:
        """
        Create from dictionary representation.

        Args:
            data: Dictionary from to_dict()

        Returns:
            CallGraph instance
        """
        return call_graph_from_dict(data)
