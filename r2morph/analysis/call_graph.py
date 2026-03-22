"""
Call Graph construction for inter-procedural analysis.

Provides call graph construction and analysis capabilities:
- Direct call extraction
- Indirect call resolution
- Recursive call detection
- Caller/callee relationships
- Caching support for repeated analysis
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

from r2morph.core.binary import Binary

if TYPE_CHECKING:
    from r2morph.core.analysis_cache import AnalysisCache

logger = logging.getLogger(__name__)


class CallType(Enum):
    """Type of call instruction."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    TAIL = "tail"
    PLT = "plt"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class RecursionType(Enum):
    """Type of recursion in call graph."""

    NONE = "none"
    DIRECT = "direct"
    MUTUAL = "mutual"


@dataclass
class CallNode:
    """
    Represents a function node in the call graph.

    Attributes:
        address: Function start address
        name: Function name (if available)
        size: Function size in bytes
        call_type: Type of function (user, library, plt)
        callers: Addresses of functions that call this function
        callees: Addresses of functions called by this function
        is_recursive: Whether this function is recursive
        recursion_depth: Maximum recursion depth if recursive
    """

    address: int
    name: str = ""
    size: int = 0
    call_type: CallType = CallType.DIRECT
    callers: list[int] = field(default_factory=list)
    callees: list[int] = field(default_factory=list)
    is_recursive: bool = False
    recursion_depth: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"<CallNode @ 0x{self.address:x} name={self.name} callers={len(self.callers)} callees={len(self.callees)}>"
        )

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallNode):
            return False
        return self.address == other.address

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": f"0x{self.address:x}",
            "name": self.name,
            "size": self.size,
            "call_type": self.call_type.value,
            "callers": [f"0x{a:x}" for a in self.callers],
            "callees": [f"0x{a:x}" for a in self.callees],
            "is_recursive": self.is_recursive,
            "recursion_depth": self.recursion_depth,
            "metadata": self.metadata,
        }


@dataclass
class CallEdge:
    """
    Represents an edge in the call graph.

    Attributes:
        caller: Address of calling function
        callee: Address of called function
        call_type: Type of call (direct, indirect, tail)
        call_site: Address where the call instruction occurs
        is_tail_call: Whether this is a tail call
    """

    caller: int
    callee: int
    call_type: CallType
    call_site: int = 0
    is_tail_call: bool = False

    def __repr__(self) -> str:
        return f"<CallEdge 0x{self.caller:x} -> 0x{self.callee:x} ({self.call_type.value})>"

    def __hash__(self) -> int:
        return hash((self.caller, self.callee, self.call_site))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "caller": f"0x{self.caller:x}",
            "callee": f"0x{self.callee:x}",
            "call_type": self.call_type.value,
            "call_site": f"0x{self.call_site:x}",
            "is_tail_call": self.is_tail_call,
        }


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

    def __init__(self):
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

        def dfs(node_addr: int, path: list[int]) -> None:
            visited.add(node_addr)
            rec_stack.add(node_addr)

            node = self.nodes.get(node_addr)
            if node is None:
                return

            for callee in node.callees:
                if callee not in visited:
                    dfs(callee, path + [callee])
                elif callee in rec_stack:
                    cycle_start = path.index(callee) if callee in path else -1
                    if cycle_start >= 0:
                        cycle = path[cycle_start:] + [callee]
                        self._recursive_chains.append(cycle)
                        for addr in cycle:
                            if addr in self.nodes:
                                self.nodes[addr].is_recursive = True

            rec_stack.remove(node_addr)

        for addr in self.nodes:
            if addr not in visited:
                dfs(addr, [addr])

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

        index_counter = [0]
        stack: list[int] = []
        lowlinks: dict[int, int] = {}
        index: dict[int, int] = {}
        on_stack: set[int] = set()

        def strongconnect(node: int) -> None:
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack.add(node)

            node_obj = self.nodes.get(node)
            if node_obj is None:
                return

            for successor in node_obj.callees:
                if successor not in index:
                    strongconnect(successor)
                    lowlinks[node] = min(lowlinks[node], lowlinks[successor])
                elif successor in on_stack:
                    lowlinks[node] = min(lowlinks[node], index[successor])

            if lowlinks[node] == index[node]:
                scc: set[int] = set()
                while True:
                    successor = stack.pop()
                    on_stack.remove(successor)
                    scc.add(successor)
                    if successor == node:
                        break
                if len(scc) > 1:
                    self._strongly_connected.append(scc)

        for node in self.nodes:
            if node not in index:
                strongconnect(node)

        return self._strongly_connected

    def topological_sort(self) -> list[int]:
        """
        Topologically sort functions (callers before callees).

        Returns:
            List of function addresses in topological order
        """
        visited: set[int] = set()
        result: list[int] = []

        def visit(node: int) -> None:
            if node in visited:
                return
            if node not in self.nodes:
                return

            visited.add(node)
            node_obj = self.nodes[node]

            for callee in node_obj.callees:
                visit(callee)

            result.append(node)

        for addr in sorted(self.nodes.keys()):
            visit(addr)

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

        def dfs(current: int) -> bool:
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

            for callee in node.callees:
                if dfs(callee):
                    return True

            path.pop()
            return False

        if dfs(src):
            return path
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

        def depth(node: int) -> int:
            if node in visited:
                return 0
            if node not in self.nodes:
                return 0

            visited.add(node)
            node_obj = self.nodes[node]

            if not node_obj.callees:
                return 0

            return 1 + max(depth(callee) for callee in node_obj.callees)

        return depth(address)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "nodes": {f"0x{addr:x}": node.to_dict() for addr, node in self.nodes.items()},
            "edges": [edge.to_dict() for edge in self.edges],
            "entry_points": [f"0x{addr:x}" for addr in self.get_entry_points()],
            "leaf_functions": [f"0x{addr:x}" for addr in self.get_leaf_functions()],
            "recursive_functions": [f"0x{addr:x}" for addr in self.find_recursive_functions()],
            "recursive_chains": [[f"0x{addr:x}" for addr in chain] for chain in self._recursive_chains],
            "strongly_connected_components": [
                [f"0x{addr:x}" for addr in scc] for scc in self.find_strongly_connected_components()
            ],
            "statistics": {
                "total_functions": len(self.nodes),
                "total_calls": len(self.edges),
                "entry_points": len(self.get_entry_points()),
                "leaf_functions": len(self.get_leaf_functions()),
                "recursive_functions": len(self.find_recursive_functions()),
                "strongly_connected_components": len(self._strongly_connected),
            },
        }

    def to_dot(self) -> str:
        """
        Generate GraphViz DOT representation.

        Returns:
            DOT format string
        """
        lines = [
            "digraph CallGraph {",
            "  node [shape=box];",
            "  rankdir=TB;",
            "",
        ]

        for addr, node in self.nodes.items():
            label = f"{node.name}\\n0x{addr:x}" if node.name else f"0x{addr:x}"
            color = "red" if node.is_recursive else "lightblue"
            if addr in self.get_entry_points():
                color = "green"
            elif addr in self.get_leaf_functions():
                color = "yellow"
            lines.append(f'  "0x{addr:x}" [label="{label}", style=filled, fillcolor={color}];')

        lines.append("")

        for edge in self.edges:
            style = "dashed" if edge.call_type == CallType.INDIRECT else "solid"
            label = edge.call_type.value
            lines.append(f'  "0x{edge.caller:x}" -> "0x{edge.callee:x}" [style={style}, label="{label}"];')

        lines.append("}")
        return "\n".join(lines)

    def to_json(self) -> str:
        """
        Serialize to JSON string for caching.

        Returns:
            JSON string representation
        """
        import json

        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "CallGraph":
        """
        Deserialize from JSON string.

        Args:
            json_str: JSON string representation

        Returns:
            CallGraph instance
        """
        import json

        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CallGraph":
        """
        Create from dictionary representation.

        Args:
            data: Dictionary from to_dict()

        Returns:
            CallGraph instance
        """
        cg = cls()
        cg.entry_points = [int(ep, 16) for ep in data.get("entry_points", [])]

        for addr_str, node_data in data.get("nodes", {}).items():
            addr = int(addr_str, 16)
            node = CallNode(
                address=addr,
                name=node_data.get("name", ""),
                size=node_data.get("size", 0),
                call_type=CallType(node_data.get("call_type", "direct")),
                callers=[int(c, 16) for c in node_data.get("callers", [])],
                callees=[int(c, 16) for c in node_data.get("callees", [])],
                is_recursive=node_data.get("is_recursive", False),
                recursion_depth=node_data.get("recursion_depth", 0),
                metadata=node_data.get("metadata", {}),
            )
            cg.add_node(node)

        for edge_data in data.get("edges", []):
            edge = CallEdge(
                caller=int(edge_data["caller"], 16),
                callee=int(edge_data["callee"], 16),
                call_type=CallType(edge_data.get("call_type", "direct")),
                call_site=int(edge_data.get("call_site", "0x0"), 16),
                is_tail_call=edge_data.get("is_tail_call", False),
            )
            cg.add_edge(edge)

        for chain in data.get("recursive_chains", []):
            cg._recursive_chains.append([int(addr, 16) for addr in chain])

        for scc in data.get("strongly_connected_components", []):
            cg._strongly_connected.append({int(addr, 16) for addr in scc})

        return cg


class CallGraphBuilder:
    """
    Builds call graphs from binary analysis.

    Extracts call relationships from disassembly and builds
    a directed graph representation.

    Usage:
        builder = CallGraphBuilder()
        cg = builder.build(binary)
    """

    def __init__(self, include_indirect: bool = True, include_plt: bool = True):
        """
        Initialize the call graph builder.

        Args:
            include_indirect: Whether to include indirect calls
            include_plt: Whether to include PLT stubs
        """
        self.include_indirect = include_indirect
        self.include_plt = include_plt
        self._known_indirect_targets: dict[int, list[int]] = {}

    def build(self, binary: Binary) -> CallGraph:
        """
        Build a call graph from a binary.

        Args:
            binary: The binary to analyze

        Returns:
            CallGraph instance
        """
        cg = CallGraph()

        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, run analysis first")

        functions = binary.get_functions()
        logger.info(f"Building call graph from {len(functions)} functions")

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            func_name = func.get("name", f"sub_{func_addr:x}")
            func_size = func.get("size", 0)

            call_type = self._determine_call_type(func_name, func)

            node = CallNode(
                address=func_addr,
                name=func_name,
                size=func_size,
                call_type=call_type,
            )
            cg.add_node(node)

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            self._extract_calls(binary, func_addr, cg)

        entry_points = self._find_entry_points(binary, cg)
        cg.entry_points = entry_points

        cg._detect_recursion()
        cg.find_strongly_connected_components()

        logger.info(f"Call graph built: {len(cg.nodes)} nodes, {len(cg.edges)} edges, {len(entry_points)} entry points")

        return cg

    def _determine_call_type(self, name: str, func: dict) -> CallType:
        """Determine the type of a function."""
        if name.startswith("sym.imp."):
            return CallType.PLT
        if name.startswith("sub."):
            return CallType.DIRECT
        if "." in name and not name.startswith("sub."):
            return CallType.LIBRARY
        return CallType.DIRECT

    def _extract_calls(self, binary: Binary, func_addr: int, cg: CallGraph) -> None:
        """Extract call instructions from a function."""
        try:
            disasm = binary.get_function_disasm(func_addr)
            if not disasm:
                return

            for insn in disasm:
                self._process_instruction(binary, func_addr, insn, cg)

        except Exception as e:
            logger.debug(f"Error extracting calls from 0x{func_addr:x}: {e}")

    def _process_instruction(self, binary: Binary, func_addr: int, insn: dict, cg: CallGraph) -> None:
        """Process a single instruction for call extraction."""
        disasm = insn.get("disasm", "").lower()
        offset = insn.get("offset", 0)

        if not disasm.startswith("call") and not self._is_tail_call(disasm):
            return

        call_target = self._extract_call_target(disasm)
        if call_target is None:
            return

        call_type = CallType.DIRECT
        is_tail = self._is_tail_call(disasm)

        if call_target in cg.nodes:
            target_node = cg.nodes[call_target]
            if target_node.call_type == CallType.PLT:
                call_type = CallType.PLT
        elif isinstance(call_target, str) and call_target.startswith("0x"):
            call_type = CallType.DIRECT
        else:
            call_type = CallType.INDIRECT
            if not self.include_indirect:
                return

        if call_type == CallType.PLT and not self.include_plt:
            return

        if isinstance(call_target, int):
            if call_target not in cg.nodes:
                target_node = CallNode(
                    address=call_target,
                    name=f"sub_{call_target:x}",
                    call_type=call_type,
                )
                cg.add_node(target_node)

            edge = CallEdge(
                caller=func_addr,
                callee=call_target,
                call_type=call_type,
                call_site=offset,
                is_tail_call=is_tail,
            )
            cg.add_edge(edge)

    def _extract_call_target(self, disasm: str) -> int | str | None:
        """Extract call target from disassembly."""
        parts = disasm.split(None, 1)
        if len(parts) < 2:
            return None

        operand = parts[1].strip()

        if operand.startswith("0x"):
            try:
                return int(operand, 16)
            except ValueError:
                pass

        if operand.startswith("[") and operand.endswith("]"):
            return f"indirect:{operand}"

        if operand.startswith("dword [") or operand.startswith("qword ["):
            return f"indirect:{operand}"

        if operand in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
            return f"indirect:{operand}"

        return operand

    def _is_tail_call(self, disasm: str) -> bool:
        """Check if instruction is a tail call (jmp to function)."""
        if not disasm.startswith("jmp"):
            return False
        parts = disasm.split(None, 1)
        if len(parts) < 2:
            return False
        operand = parts[1].strip()
        return operand.startswith("0x") or operand in ("rax", "rbx", "rcx", "rdx")

    def _find_entry_points(self, binary: Binary, cg: CallGraph) -> list[int]:
        """Find entry point functions."""
        entry_points: list[int] = []

        symbols = getattr(binary, "_symbols", {}) or {}
        entry = symbols.get("entry0")
        if entry:
            entry_addr = entry if isinstance(entry, int) else entry.get("offset", 0)
            if entry_addr in cg.nodes:
                entry_points.append(entry_addr)

        main_sym = symbols.get("main")
        if main_sym:
            main_addr = main_sym if isinstance(main_sym, int) else main_sym.get("offset", 0)
            if main_addr in cg.nodes and main_addr not in entry_points:
                entry_points.append(main_addr)

        init_syms = [symbols.get(f"__libc_csu_init"), symbols.get("_init")]
        for sym in init_syms:
            if sym:
                addr = sym if isinstance(sym, int) else sym.get("offset", 0)
                if addr in cg.nodes and addr not in entry_points:
                    entry_points.append(addr)

        if not entry_points:
            entry_points = cg.get_entry_points()

        return entry_points

    def resolve_indirect_call(self, binary: Binary, call_site: int, context: dict[str, Any] | None = None) -> list[int]:
        """
        Attempt to resolve an indirect call to possible targets.

        Args:
            binary: The binary being analyzed
            call_site: Address of the call instruction
            context: Additional context (register values, etc.)

        Returns:
            List of possible target addresses
        """
        targets: list[int] = []

        if call_site in self._known_indirect_targets:
            return self._known_indirect_targets[call_site]

        if context and "possible_targets" in context:
            targets = context["possible_targets"]

        functions = binary.get_functions()
        func_starts = {f.get("offset", f.get("addr", 0)) for f in functions}

        for addr in targets:
            if addr in func_starts:
                if call_site not in self._known_indirect_targets:
                    self._known_indirect_targets[call_site] = []
                self._known_indirect_targets[call_site].append(addr)

        return self._known_indirect_targets.get(call_site, targets)


def build_call_graph(binary: Binary, include_indirect: bool = True, include_plt: bool = True) -> CallGraph:
    """
    Convenience function to build a call graph.

    Args:
        binary: The binary to analyze
        include_indirect: Whether to include indirect calls
        include_plt: Whether to include PLT stubs

    Returns:
        CallGraph instance
    """
    builder = CallGraphBuilder(include_indirect=include_indirect, include_plt=include_plt)
    return builder.build(binary)


def build_call_graph_cached(
    binary: Binary,
    cache: "AnalysisCache | None" = None,
    include_indirect: bool = True,
    include_plt: bool = True,
) -> CallGraph:
    """
    Build a call graph with caching support.

    Uses the provided cache to avoid rebuilding the call graph for
    unchanged binaries. If no cache is provided, builds without caching.

    Args:
        binary: The binary to analyze
        cache: Optional AnalysisCache instance for caching
        include_indirect: Whether to include indirect calls
        include_plt: Whether to include PLT stubs

    Returns:
        CallGraph instance
    """
    options = {
        "include_indirect": include_indirect,
        "include_plt": include_plt,
    }

    if cache is not None:
        try:
            binary_data = binary.path.open("rb").read()
            cached = cache.get(binary_data, "call_graph", options)
            if cached is not None:
                logger.debug("Call graph cache hit")
                return CallGraph.from_json(cached)
        except Exception as e:
            logger.debug(f"Cache lookup failed: {e}")

    cg = build_call_graph(binary, include_indirect=include_indirect, include_plt=include_plt)

    if cache is not None:
        try:
            binary_data = binary.path.open("rb").read()
            cache.set(binary_data, "call_graph", cg.to_json(), options)
            logger.debug("Call graph cached")
        except Exception as e:
            logger.debug(f"Cache storage failed: {e}")

    return cg
