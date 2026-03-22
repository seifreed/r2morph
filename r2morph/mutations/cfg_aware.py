"""
CFG-aware mutation pass base class.

Provides mutation passes that are aware of control flow graphs
to avoid mutating critical control flow points.
"""

import logging
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any

from r2morph.mutations.base import MutationPass, MutationResult
from r2morph.core.binary import Binary
from r2morph.analysis.cfg import ControlFlowGraph, CFGBuilder
from r2morph.analysis.critical_nodes import (
    CriticalNodeDetector,
    AddressRange,
    CriticalNode,
    MutationSafetyScorer,
)

logger = logging.getLogger(__name__)


@dataclass
class CFGAwareMutationResult(MutationResult):
    """Result of a CFG-aware mutation."""

    safe_mutations: int = 0
    skipped_mutations: int = 0
    critical_nodes_avoided: int = 0
    exclusion_zones: list[AddressRange] = field(default_factory=list)
    safe_regions: list[AddressRange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "safe_mutations": self.safe_mutations,
                "skipped_mutations": self.skipped_mutations,
                "critical_nodes_avoided": self.critical_nodes_avoided,
                "exclusion_zones": [z.to_dict() for z in self.exclusion_zones],
                "safe_regions": [r.to_dict() for r in self.safe_regions],
            }
        )
        return base


class CFGAwareMutationPass(MutationPass):
    """
    Base class for CFG-aware mutation passes.

    Provides infrastructure for mutations that respect control flow
    by avoiding critical nodes and exclusion zones.

    Subclasses should implement apply_cfg_aware() instead of apply().

    Usage:
        class MyCFGAwarePass(CFGAwareMutationPass):
            def apply_cfg_aware(self, binary, cfg, safe_regions):
                # Implement mutation logic
                pass
    """

    def __init__(
        self,
        name: str = "cfg_aware",
        enabled: bool = True,
        exclusion_radius: int = 3,
        min_safety_score: float = 0.5,
    ):
        """
        Initialize CFG-aware mutation pass.

        Args:
            name: Pass name
            enabled: Whether pass is enabled
            exclusion_radius: Radius around critical nodes to exclude
            min_safety_score: Minimum safety score for mutation sites
        """
        super().__init__(name=name, enabled=enabled)
        self.exclusion_radius = exclusion_radius
        self.min_safety_score = min_safety_score
        self._detector: CriticalNodeDetector | None = None
        self._scorer: MutationSafetyScorer | None = None
        self._cfg: ControlFlowGraph | None = None

    def apply(self, binary: Binary) -> MutationResult:
        """
        Apply the mutation (CFG-aware wrapper).

        This method builds the CFG and calls apply_cfg_aware().

        Args:
            binary: Binary to mutate

        Returns:
            MutationResult instance
        """
        builder = CFGBuilder(binary)
        functions = binary.get_functions()

        if not functions:
            logger.warning("No functions found in binary")
            return CFGAwareMutationResult(
                success=False,
                message="No functions found in binary",
            )

        result = CFGAwareMutationResult(
            success=True,
            message="CFG-aware mutation completed",
        )

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            func_name = func.get("name", f"func_{func_addr:x}")

            try:
                self._cfg = builder.build_cfg(func_addr, func_name)
                self._detector = CriticalNodeDetector(
                    self._cfg,
                    default_exclusion_radius=self.exclusion_radius,
                )
                self._detector.find_all_critical_nodes()

                result.exclusion_zones.extend(self._detector.get_exclusion_zones())
                result.safe_regions.extend(self._detector.get_safe_regions())

                safe_regions = self._detector.get_safe_regions()
                func_result = self.apply_cfg_aware(binary, self._cfg, safe_regions)

                if isinstance(func_result, dict):
                    result.mutations.extend(func_result.get("mutations", []))
                    result.safe_mutations += func_result.get("safe_mutations", 0)
                    result.skipped_mutations += func_result.get("skipped_mutations", 0)
                    result.critical_nodes_avoided += func_result.get("critical_nodes_avoided", 0)

            except Exception as e:
                logger.error(f"Failed to apply CFG-aware mutation to {func_name}: {e}")

        return result

    @abstractmethod
    def apply_cfg_aware(
        self,
        binary: Binary,
        cfg: ControlFlowGraph,
        safe_regions: list[AddressRange],
    ) -> dict[str, Any]:
        """
        Apply the mutation with CFG awareness.

        Subclasses must implement this method.

        Args:
            binary: Binary to mutate
            cfg: Control flow graph for current function
            safe_regions: List of safe regions for mutations

        Returns:
            Dictionary with mutation results
        """
        pass

    def get_critical_nodes(self) -> dict[int, CriticalNode]:
        """
        Get critical nodes from the current CFG.

        Returns:
            Dictionary mapping addresses to CriticalNode instances
        """
        if self._detector is None:
            return {}
        return self._detector.find_all_critical_nodes()

    def score_mutation_site(self, address: int) -> float:
        """
        Score a potential mutation site for safety.

        Args:
            address: Address to score

        Returns:
            Safety score from 0.0 (unsafe) to 1.0 (safe)
        """
        if self._scorer is None:
            self._scorer = MutationSafetyScorer()

        if self._cfg is None:
            return 0.5

        critical_nodes = self.get_critical_nodes()
        return self._scorer.score_address(address, self._cfg, critical_nodes)

    def should_skip(self, address: int) -> bool:
        """
        Check if an address should be skipped for mutation.

        Args:
            address: Address to check

        Returns:
            True if address should be skipped
        """
        if self._detector is None:
            return False

        if self._detector.is_critical(address):
            return True

        if self._detector.is_in_exclusion_zone(address):
            return True

        score = self.score_mutation_site(address)
        return score < self.min_safety_score

    def get_safe_regions(self) -> list[AddressRange]:
        """
        Get safe regions from the current CFG.

        Returns:
            List of AddressRange instances safe for mutation
        """
        if self._detector is None:
            return []
        return self._detector.get_safe_regions()

    def filter_safe_addresses(self, addresses: list[int]) -> list[int]:
        """
        Filter addresses to only include safe ones.

        Args:
            addresses: List of addresses to filter

        Returns:
            List of safe addresses
        """
        return [addr for addr in addresses if not self.should_skip(addr)]

    def get_exclusion_zones(self) -> list[AddressRange]:
        """
        Get exclusion zones from the current CFG.

        Returns:
            List of AddressRange instances to avoid
        """
        if self._detector is None:
            return []
        return self._detector.get_exclusion_zones()


class CFGAwareNOPInsertion(CFGAwareMutationPass):
    """
    CFG-aware NOP insertion mutation pass.

    Only inserts NOPs at safe locations, avoiding critical control flow points.
    """

    def __init__(
        self,
        name: str = "cfg_aware_nop",
        enabled: bool = True,
        max_nops: int = 3,
        exclusion_radius: int = 3,
        min_safety_score: float = 0.6,
    ):
        """
        Initialize CFG-aware NOP insertion pass.

        Args:
            name: Pass name
            enabled: Whether pass is enabled
            max_nops: Maximum number of NOPs to insert per function
            exclusion_radius: Radius around critical nodes to exclude
            min_safety_score: Minimum safety score for mutation sites
        """
        super().__init__(
            name=name,
            enabled=enabled,
            exclusion_radius=exclusion_radius,
            min_safety_score=min_safety_score,
        )
        self.max_nops = max_nops

    def apply_cfg_aware(
        self,
        binary: Binary,
        cfg: ControlFlowGraph,
        safe_regions: list[AddressRange],
    ) -> dict[str, Any]:
        """
        Apply CFG-aware NOP insertion.

        Args:
            binary: Binary to mutate
            cfg: Control flow graph
            safe_regions: Safe regions for mutations

        Returns:
            Dictionary with mutation results
        """
        result = {
            "mutations": [],
            "safe_mutations": 0,
            "skipped_mutations": 0,
            "critical_nodes_avoided": 0,
        }

        if not safe_regions:
            logger.debug(f"No safe regions in function {cfg.function_name}")
            return result

        safe_addresses = []
        for addr, block in cfg.blocks.items():
            if not self.should_skip(addr):
                score = self.score_mutation_site(addr)
                if score >= self.min_safety_score:
                    safe_addresses.append((addr, score))

        safe_addresses.sort(key=lambda x: x[1], reverse=True)

        nops_inserted = 0
        for addr, score in safe_addresses[: self.max_nops]:
            try:
                mutation_result = self._insert_nop(binary, addr)
                if mutation_result:
                    result["mutations"].append(
                        {
                            "type": "nop_insertion",
                            "address": f"0x{addr:x}",
                            "safety_score": score,
                        }
                    )
                    result["safe_mutations"] += 1
                    nops_inserted += 1
            except Exception as e:
                logger.debug(f"Failed to insert NOP at 0x{addr:x}: {e}")
                result["skipped_mutations"] += 1

        result["critical_nodes_avoided"] = len(self.get_critical_nodes())

        return result

    def _insert_nop(self, binary: Binary, address: int) -> bool:
        """
        Insert a NOP at the specified address.

        Args:
            binary: Binary to modify
            address: Address to insert NOP

        Returns:
            True if successful
        """
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "").lower()

        if arch in ("x86", "x86_64", "amd64"):
            nop_bytes = b"\x90"
        elif arch in ("arm64", "aarch64"):
            nop_bytes = b"\x1f\x20\x03\xd5"
        elif arch in ("arm",):
            nop_bytes = b"\x00\xf0\x20\xe3"
        else:
            nop_bytes = b"\x90"

        return binary.write_bytes(address, nop_bytes)


class CFGAwareSubstitution(CFGAwareMutationPass):
    """
    CFG-aware instruction substitution mutation pass.

    Only substitutes instructions at safe locations.
    """

    def __init__(
        self,
        name: str = "cfg_aware_substitution",
        enabled: bool = True,
        exclusion_radius: int = 3,
        min_safety_score: float = 0.6,
    ):
        """
        Initialize CFG-aware substitution pass.

        Args:
            name: Pass name
            enabled: Whether pass is enabled
            exclusion_radius: Radius around critical nodes to exclude
            min_safety_score: Minimum safety score for mutation sites
        """
        super().__init__(
            name=name,
            enabled=enabled,
            exclusion_radius=exclusion_radius,
            min_safety_score=min_safety_score,
        )

    def apply_cfg_aware(
        self,
        binary: Binary,
        cfg: ControlFlowGraph,
        safe_regions: list[AddressRange],
    ) -> dict[str, Any]:
        """
        Apply CFG-aware instruction substitution.

        Args:
            binary: Binary to mutate
            cfg: Control flow graph
            safe_regions: Safe regions for mutations

        Returns:
            Dictionary with mutation results
        """
        result = {
            "mutations": [],
            "safe_mutations": 0,
            "skipped_mutations": 0,
            "critical_nodes_avoided": 0,
        }

        if not safe_regions:
            logger.debug(f"No safe regions in function {cfg.function_name}")
            return result

        for addr, block in cfg.blocks.items():
            if self.should_skip(addr):
                continue

            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)
                if self.should_skip(insn_addr):
                    continue

                disasm = insn.get("disasm", "").lower()
                substitution = self._get_substitution(disasm, insn_addr, binary)

                if substitution:
                    result["mutations"].append(
                        {
                            "type": "substitution",
                            "address": f"0x{insn_addr:x}",
                            "original": disasm,
                            "substitution": substitution,
                        }
                    )
                    result["safe_mutations"] += 1

        result["critical_nodes_avoided"] = len(self.get_critical_nodes())

        return result

    def _get_substitution(self, disasm: str, address: int, binary: Binary) -> str | None:
        """
        Get a safe substitution for an instruction.

        Args:
            disasm: Disassembled instruction
            address: Instruction address
            binary: Binary being mutated

        Returns:
            Substitution or None if not applicable
        """
        if not disasm:
            return None

        parts = disasm.split(None, 1)
        mnemonic = parts[0].lower() if parts else ""

        if mnemonic == "nop":
            return None

        if mnemonic in ("jmp", "call", "ret", "syscall"):
            return None

        if mnemonic in ("add", "sub", "imul", "xor", "or", "and", "shl", "shr"):
            score = self.score_mutation_site(address)
            if score < self.min_safety_score:
                return None
            return f"[cfg_aware_substitution] {disasm}"

        return None


def create_cfg_aware_nop_pass(**kwargs) -> CFGAwareNOPInsertion:
    """
    Create a CFG-aware NOP insertion pass.

    Args:
        **kwargs: Pass arguments

    Returns:
        CFGAwareNOPInsertion instance
    """
    return CFGAwareNOPInsertion(**kwargs)


def create_cfg_aware_substitution_pass(**kwargs) -> CFGAwareSubstitution:
    """
    Create a CFG-aware substitution pass.

    Args:
        **kwargs: Pass arguments

    Returns:
        CFGAwareSubstitution instance
    """
    return CFGAwareSubstitution(**kwargs)
