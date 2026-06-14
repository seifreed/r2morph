"""Pointer alias analysis helpers."""

from __future__ import annotations

from r2morph.analysis.pointer_analysis_helpers import compute_transitive_aliases, extract_lea_target
from r2morph.core.binary import Binary


class PointerAnalysis:
    """
    Pointer alias analysis.

    Tracks pointer aliases and points-to relationships.

    Usage:
        analysis = PointerAnalysis()
        analysis.compute_aliases(binary)
        aliases = analysis.get_aliases(address)
    """

    def __init__(self) -> None:
        self._points_to: dict[int, set[int]] = {}
        self._aliases: dict[int, set[int]] = {}

    def compute_aliases(self, binary: Binary) -> None:
        """Compute pointer alias information."""
        functions = binary.get_functions()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            self._analyze_function_pointers(binary, func_addr)

        self._compute_transitive_aliases()

    def _analyze_function_pointers(self, binary: Binary, func_addr: int) -> None:
        """Analyze pointers in a function."""
        disasm = binary.get_function_disasm(func_addr)
        if not disasm:
            return

        for insn in disasm:
            self._extract_pointer_use(binary, insn)

    def _extract_pointer_use(self, binary: Binary, insn: dict) -> None:
        """Extract pointer use from instruction."""
        disasm = insn.get("disasm", "").lower()
        addr = insn.get("offset", 0)

        if "lea" in disasm:
            target = extract_lea_target(disasm)
            if target:
                if addr not in self._points_to:
                    self._points_to[addr] = set()
                self._points_to[addr].add(target)

    def _compute_transitive_aliases(self) -> None:
        """Compute transitive alias closure."""
        self._aliases = compute_transitive_aliases(self._points_to)

    def get_points_to(self, address: int) -> set[int]:
        """
        Get addresses that a pointer may point to.

        Args:
            address: Address with pointer

        Returns:
            Set of possible target addresses
        """
        return self._points_to.get(address, set())

    def get_aliases(self, address: int) -> set[int]:
        """
        Get all aliases of a pointer.

        Args:
            address: Address with pointer

        Returns:
            Set of alias addresses
        """
        return self._aliases.get(address, set())

    def may_alias(self, addr1: int, addr2: int) -> bool:
        """
        Check if two pointers may alias.

        Args:
            addr1: First pointer address
            addr2: Second pointer address

        Returns:
            True if they may alias
        """
        if addr1 == addr2:
            return True

        aliases1 = self.get_aliases(addr1)
        aliases2 = self.get_aliases(addr2)

        return bool(aliases1 & aliases2)
