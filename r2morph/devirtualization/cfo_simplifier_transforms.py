"""
Transformation helpers for the CFO simplifier.
"""

from __future__ import annotations

import logging
from typing import Any

from .cfo_simplifier_models import DispatcherInfo

nx: Any
try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

logger = logging.getLogger(__name__)


def simplify_dispatcher_flattening(simplifier: Any) -> bool:
    """Simplify dispatcher-based control flow flattening."""
    try:
        changes_made = False

        for dispatcher in simplifier.dispatchers:
            dispatcher_block = simplifier.blocks.get(dispatcher.dispatcher_address)
            if not dispatcher_block:
                continue

            reconstructed_edges = reconstruct_control_flow(simplifier, dispatcher)

            if reconstructed_edges:
                for source, target in reconstructed_edges:
                    if source in simplifier.blocks and target in simplifier.blocks:
                        simplifier.blocks[source].successors.add(target)
                        simplifier.blocks[target].predecessors.add(source)
                        changes_made = True

                dispatcher_block.is_dispatcher = False
                logger.debug(f"Simplified dispatcher at 0x{dispatcher.dispatcher_address:x}")

        return changes_made

    except Exception as e:
        logger.error(f"Dispatcher simplification failed: {e}")
        return False


def eliminate_opaque_predicates(simplifier: Any) -> bool:
    """Eliminate opaque predicates from control flow."""
    try:
        changes_made = False

        for address, block in simplifier.blocks.items():
            for i, instr in enumerate(block.instructions):
                opcode = instr.get("opcode", "").lower()

                if any(jmp in opcode for jmp in ["je", "jne", "jz", "jnz", "jg", "jl"]):
                    if i > 0:
                        prev_instr = block.instructions[i - 1]
                        if simplifier._is_opaque_comparison(prev_instr):
                            block.instructions[i - 1] = {"opcode": "nop", "comment": "removed_opaque_cmp"}
                            block.instructions[i] = {"opcode": "jmp", "comment": "simplified_jump"}
                            changes_made = True

        return changes_made

    except Exception as e:
        logger.error(f"Opaque predicate elimination failed: {e}")
        return False


def resolve_indirect_jumps(simplifier: Any) -> bool:
    """Resolve indirect jumps to direct jumps where possible."""
    try:
        changes_made = False

        for address, block in simplifier.blocks.items():
            for i, instr in enumerate(block.instructions):
                opcode = instr.get("opcode", "").lower()

                if "jmp" in opcode and "[" in opcode:
                    target = simplifier._resolve_jump_target(instr)
                    if target:
                        block.instructions[i] = {
                            "opcode": f"jmp 0x{target:x}",
                            "comment": "resolved_indirect_jump",
                        }
                        changes_made = True

        return changes_made

    except Exception as e:
        logger.error(f"Indirect jump resolution failed: {e}")
        return False


def remove_fake_control_flow(simplifier: Any) -> bool:
    """Remove fake control flow edges."""
    try:
        if not NETWORKX_AVAILABLE or not simplifier.cfg:
            return False

        changes_made = False
        entry_node = min(simplifier.blocks.keys()) if simplifier.blocks else 0
        reachable = set(nx.descendants(simplifier.cfg, entry_node))
        reachable.add(entry_node)

        unreachable_blocks = set(simplifier.blocks.keys()) - reachable
        for block_addr in unreachable_blocks:
            if block_addr in simplifier.blocks:
                del simplifier.blocks[block_addr]
                changes_made = True

        return changes_made

    except Exception as e:
        logger.error(f"Fake control flow removal failed: {e}")
        return False


def analyze_dispatch_targets(simplifier: Any, dispatcher_info: DispatcherInfo) -> None:
    """Analyze dispatch targets for a dispatcher."""
    try:
        dispatcher_block = simplifier.blocks.get(dispatcher_info.dispatcher_address)
        if not dispatcher_block:
            return

        for successor in dispatcher_block.successors:
            successor_block = simplifier.blocks.get(successor)
            if successor_block:
                state_value = simplifier._extract_state_value(successor_block)
                if state_value is not None:
                    dispatcher_info.dispatch_table[state_value] = successor

        if len(dispatcher_info.dispatch_table) >= 2:
            dispatcher_info.pattern_confidence = min(1.0, 0.5 + (len(dispatcher_info.dispatch_table) * 0.1))

    except Exception as e:
        logger.error(f"Dispatch target analysis failed: {e}")


def reconstruct_control_flow(simplifier: Any, dispatcher: DispatcherInfo) -> list[tuple[int, int]]:
    """Reconstruct original control flow from dispatcher pattern."""
    try:
        reconstructed_edges = []

        for state_value, target in dispatcher.dispatch_table.items():
            source_blocks = simplifier._find_state_setters(state_value, dispatcher.state_variable)

            for source in source_blocks:
                if source != dispatcher.dispatcher_address:
                    reconstructed_edges.append((source, target))

        return reconstructed_edges

    except Exception as e:
        logger.error(f"Control flow reconstruction failed: {e}")
        return []


def calculate_complexity(simplifier: Any) -> int:
    """Calculate control flow complexity metric."""
    try:
        if not NETWORKX_AVAILABLE or not simplifier.cfg:
            return sum(len(block.successors) for block in simplifier.blocks.values())

        num_edges = simplifier.cfg.number_of_edges()
        num_nodes = simplifier.cfg.number_of_nodes()
        num_components = nx.number_weakly_connected_components(simplifier.cfg)
        complexity = num_edges - num_nodes + (2 * num_components)
        return int(max(1, complexity))

    except Exception as e:
        logger.error(f"Complexity calculation failed: {e}")
        return len(simplifier.blocks)
