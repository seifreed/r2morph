"""
Def-use chain analysis for binary analysis.

Provides definition-use chain analysis including:
- Definition tracking
- Use site identification
- Chain construction
- Web analysis
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from r2morph.analysis.cfg import ControlFlowGraph
from r2morph.analysis.dataflow import DataFlowAnalyzer, Definition, Use, Register
from r2morph.analysis.liveness import LivenessAnalysis

logger = logging.getLogger(__name__)


@dataclass
class DefWeb:
    """
    Definition web - all uses connected by a single definition.

    A web connects a definition to all its uses, representing
    the flow of a value through the program.
    """

    definition: Definition
    uses: list[Use] = field(default_factory=list)
    register: Register | None = None

    def __repr__(self) -> str:
        return f"<DefWeb {self.register} def@0x{self.definition.address:x} uses={len(self.uses)}>"

    def get_live_range(self) -> tuple[int, int]:
        """Get the live range from definition to last use."""
        if not self.uses:
            return (self.definition.address, self.definition.address)

        all_addrs = [self.definition.address] + [u.address for u in self.uses]
        return (min(all_addrs), max(all_addrs))

    def contains_address(self, address: int) -> bool:
        """Check if address is within this web's range."""
        live_range = self.get_live_range()
        return live_range[0] <= address <= live_range[1]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        live_range = self.get_live_range()
        return {
            "definition": f"0x{self.definition.address:x}",
            "register": self.register.name if self.register else None,
            "uses": [f"0x{u.address:x}" for u in self.uses],
            "live_range": {
                "start": f"0x{live_range[0]:x}",
                "end": f"0x{live_range[1]:x}",
            },
        }


@dataclass
class UseWeb:
    """
    Use web - all definitions reaching a single use.

    A web connects a use to all definitions that might reach it,
    representing the set of possible values at a use site.
    """

    use: Use
    definitions: list[Definition] = field(default_factory=list)
    register: Register | None = None

    def __repr__(self) -> str:
        return f"<UseWeb {self.register} use@0x{self.use.address:x} defs={len(self.definitions)}>"

    def is_unique(self) -> bool:
        """Check if this use has a unique reaching definition."""
        return len(self.definitions) == 1

    def has_phi_needed(self) -> bool:
        """Check if phi node would be needed at this use site."""
        return len(self.definitions) > 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "use": f"0x{self.use.address:x}",
            "register": self.register.name if self.register else None,
            "definitions": [f"0x{d.address:x}" for d in self.definitions],
        }


class DefUseAnalyzer:
    """
    Definition-use chain analyzer.

    Builds complete def-use chains and webs from CFG.

    Usage:
        analyzer = DefUseAnalyzer(cfg)
        analyzer.analyze()
        webs = analyzer.get_def_webs()
    """

    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        self._dataflow = DataFlowAnalyzer(cfg)
        self._liveness = LivenessAnalysis(cfg)
        self._def_webs: dict[int, DefWeb] = {}
        self._use_webs: dict[int, UseWeb] = {}
        self._all_chains: list[DefWeb] = []

    def analyze(self) -> None:
        """Perform def-use analysis."""
        self._dataflow.analyze()
        self._liveness.compute()
        self._build_def_webs()
        self._build_use_webs()

    def _build_def_webs(self) -> None:
        """Build definition webs from data flow result."""
        for chain in self._dataflow.get_def_use_chains():
            web = DefWeb(
                definition=chain.definition,
                uses=chain.uses.copy(),
                register=chain.register,
            )
            self._def_webs[chain.definition.address] = web
            self._all_chains.append(web)

    def _build_use_webs(self) -> None:
        """Build use webs from reaching definitions."""
        for addr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)
                regs_used = self._extract_registers(insn)

                for reg in regs_used:
                    reaching_defs = self._get_reaching_definitions_for_use(reg, insn_addr)

                    use = Use(address=insn_addr, register=reg)
                    web = UseWeb(
                        use=use,
                        definitions=reaching_defs,
                        register=reg,
                    )
                    self._use_webs[insn_addr] = web

    def _extract_registers(self, insn: dict) -> set[Register]:
        """Extract registers mentioned in an instruction."""
        regs = set()
        disasm = insn.get("disasm", "").lower()

        x86_regs = [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "bp",
            "sp",
            "r8w",
            "r9w",
            "r10w",
            "r11w",
            "r12w",
            "r13w",
            "r14w",
            "r15w",
            "al",
            "bl",
            "cl",
            "dl",
            "sil",
            "dil",
            "bpl",
            "spl",
            "r8b",
            "r9b",
            "r10b",
            "r11b",
            "r12b",
            "r13b",
            "r14b",
            "r15b",
        ]

        for reg in x86_regs:
            if reg in disasm:
                if reg.endswith("d"):
                    size = 32
                elif reg.endswith("w"):
                    size = 16
                elif reg.endswith("b"):
                    size = 8
                else:
                    size = 64
                regs.add(Register(reg, size))

        return regs

    def _get_reaching_definitions_for_use(self, reg: Register, address: int) -> list[Definition]:
        """Get all definitions that reach a use."""
        block_addr = self._find_block_containing(address)
        if block_addr is None:
            return []

        definitions: list[Definition] = []
        reaching_defs = self._dataflow.get_reaching_in(block_addr)

        for defn in reaching_defs:
            if defn.register and defn.register.name == reg.name:
                definitions.append(defn)

        block = self.cfg.blocks.get(block_addr)
        if block:
            block.address + block.size
            max_search_distance = max(100, block.size * 2)

            for prev_addr in range(address - 1, max(block.address, address - max_search_distance), -1):
                for insn in block.instructions:
                    if insn.get("offset", 0) == prev_addr:
                        for defn in self._dataflow.get_block_definitions(block):
                            if defn.register and defn.register.name == reg.name:
                                if defn not in definitions:
                                    definitions.append(defn)
                        break

        return definitions

    def _find_block_containing(self, address: int) -> int | None:
        """Find the block containing an address."""
        for block_addr, block in self.cfg.blocks.items():
            if block.address <= address < block.address + block.size:
                return block_addr
        return None

    def get_def_web(self, address: int) -> DefWeb | None:
        """
        Get the definition web at an address.

        Args:
            address: Definition address

        Returns:
            DefWeb or None
        """
        return self._def_webs.get(address)

    def get_use_web(self, address: int) -> UseWeb | None:
        """
        Get the use web at an address.

        Args:
            address: Use address

        Returns:
            UseWeb or None
        """
        return self._use_webs.get(address)

    def get_all_def_webs(self) -> list[DefWeb]:
        """
        Get all definition webs.

        Returns:
            List of all DefWeb instances
        """
        return list(self._def_webs.values())

    def get_all_use_webs(self) -> list[UseWeb]:
        """
        Get all use webs.

        Returns:
            List of all UseWeb instances
        """
        return list(self._use_webs.values())

    def get_webs_for_register(self, register: Register) -> tuple[list[DefWeb], list[UseWeb]]:
        """
        Get all webs involving a specific register.

        Args:
            register: Register to filter by

        Returns:
            Tuple of (def_webs, use_webs)
        """
        def_webs = [web for web in self._def_webs.values() if web.register and web.register.name == register.name]

        use_webs = [web for web in self._use_webs.values() if web.register and web.register.name == register.name]

        return (def_webs, use_webs)

    def is_definition_reachable(self, definition_addr: int, use_addr: int) -> bool:
        """
        Check if a definition reaches a use.

        Args:
            definition_addr: Address of definition
            use_addr: Address of use

        Returns:
            True if definition reaches use
        """
        use_web = self._use_webs.get(use_addr)
        if use_web:
            for defn in use_web.definitions:
                if defn.address == definition_addr:
                    return True
        return False

    def find_uninitialized_uses(self) -> list[UseWeb]:
        """
        Find uses that may be uninitialized.

        Returns:
            List of UseWeb instances with no reaching definitions
        """
        uninitialized = []
        for web in self._use_webs.values():
            if not web.definitions:
                uninitialized.append(web)
        return uninitialized

    def find_unused_definitions(self) -> list[DefWeb]:
        """
        Find definitions that are never used.

        Returns:
            List of DefWeb instances with no uses
        """
        unused = []
        for web in self._def_webs.values():
            if not web.uses:
                unused.append(web)
        return unused

    def get_value_propagation_path(self, definition_addr: int) -> list[tuple[int, str]]:
        """
        Get the propagation path of a value from definition to all uses.

        Args:
            definition_addr: Address of the definition

        Returns:
            List of (address, type) tuples representing the path
        """
        path: list[tuple[int, str]] = []

        def_web = self._def_webs.get(definition_addr)
        if not def_web:
            return path

        path.append((definition_addr, "definition"))

        for use in sorted(def_web.uses, key=lambda u: u.address):
            path.append((use.address, "use"))

        return path

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis results to dictionary."""
        return {
            "def_webs": {f"0x{addr:x}": web.to_dict() for addr, web in self._def_webs.items()},
            "use_webs": {f"0x{addr:x}": web.to_dict() for addr, web in self._use_webs.items()},
            "unused_definitions": [f"0x{web.definition.address:x}" for web in self.find_unused_definitions()],
            "uninitialized_uses": [f"0x{web.use.address:x}" for web in self.find_uninitialized_uses()],
        }
