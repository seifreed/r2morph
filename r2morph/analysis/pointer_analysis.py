"""Pointer alias analysis helpers."""

from __future__ import annotations

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
            target = self._extract_lea_target(disasm)
            if target:
                if addr not in self._points_to:
                    self._points_to[addr] = set()
                self._points_to[addr].add(target)

    def _extract_lea_target(self, disasm: str) -> int | None:
        """Extract LEA target from disassembly."""
        parts = disasm.split("[")
        if len(parts) < 2:
            return None

        bracket_content = parts[1].split("]")[0]
        if bracket_content.startswith("0x"):
            try:
                return int(bracket_content, 16)
            except ValueError:
                # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
                pass

        return None

    def _compute_transitive_aliases(self) -> None:
        """Compute transitive alias closure."""
        for addr in self._points_to:
            self._aliases[addr] = set(self._points_to[addr])

        changed = True
        while changed:
            changed = False
            for addr, aliases in list(self._aliases.items()):
                new_aliases = set(aliases)
                for alias in aliases:
                    if alias in self._aliases:
                        new_aliases.update(self._aliases[alias])
                if new_aliases != aliases:
                    self._aliases[addr] = new_aliases
                    changed = True

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
