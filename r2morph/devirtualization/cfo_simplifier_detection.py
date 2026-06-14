"""
Detection helpers for the CFO simplifier.
"""

from __future__ import annotations

import logging
from typing import Any

from .cfo_simplifier_models import CFOPattern, DispatcherInfo

nx: Any
try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

logger = logging.getLogger(__name__)


def detect_obfuscation_patterns(simplifier: Any) -> list[CFOPattern]:
    """Detect various control flow obfuscation patterns."""
    patterns = []

    try:
        if detect_dispatcher_flattening(simplifier):
            patterns.append(CFOPattern.DISPATCHER_FLATTENING)

        if detect_opaque_predicates(simplifier):
            patterns.append(CFOPattern.OPAQUE_PREDICATES)

        if detect_indirect_jumps(simplifier):
            patterns.append(CFOPattern.INDIRECT_JUMPS)

        if detect_fake_control_flow(simplifier):
            patterns.append(CFOPattern.FAKE_CONTROL_FLOW)

        if detect_switch_case_obfuscation(simplifier):
            patterns.append(CFOPattern.SWITCH_CASE_OBFUSCATION)

        logger.info(f"Detected {len(patterns)} obfuscation patterns: {[p.value for p in patterns]}")

    except Exception as e:
        logger.error(f"Pattern detection failed: {e}")

    return patterns


def detect_dispatcher_flattening(simplifier: Any) -> bool:
    """Detect dispatcher-based control flow flattening."""
    try:
        dispatcher_candidates = []

        for address, block in simplifier.blocks.items():
            if len(block.predecessors) >= 3:
                has_switch_pattern = False
                state_variable = None

                for instr in block.instructions:
                    opcode = instr.get("opcode", "").lower()

                    if any(op in opcode for op in ["cmp", "test", "je", "jne", "jmp"]):
                        has_switch_pattern = True

                    if "cmp" in opcode and "operands" in instr:
                        operands = instr.get("operands", [])
                        if operands and len(operands) >= 2:
                            state_variable = operands[0].get("value", "")

                if has_switch_pattern:
                    dispatcher_info = DispatcherInfo(
                        dispatcher_address=address,
                        state_variable=state_variable or f"var_{address:x}",
                        pattern_confidence=0.7,
                    )

                    simplifier._analyze_dispatch_targets(dispatcher_info)

                    if dispatcher_info.pattern_confidence >= simplifier.dispatcher_threshold:
                        dispatcher_candidates.append(dispatcher_info)
                        block.is_dispatcher = True

        simplifier.dispatchers.extend(dispatcher_candidates)
        return len(dispatcher_candidates) > 0

    except Exception as e:
        logger.error(f"Dispatcher detection failed: {e}")
        return False


def detect_opaque_predicates(simplifier: Any) -> bool:
    """Detect opaque predicates (always true/false conditions)."""
    try:
        opaque_count = 0

        for address, block in simplifier.blocks.items():
            for instr in block.instructions:
                opcode = instr.get("opcode", "").lower()

                if "cmp" in opcode or "test" in opcode:
                    operands = instr.get("operands", [])
                    if len(operands) >= 2:
                        op1 = operands[0].get("value", "")
                        op2 = operands[1].get("value", "")

                        if op1 == op2:
                            opaque_count += 1
                        elif simplifier._is_constant_expression(op1, op2):
                            opaque_count += 1

        return opaque_count > 0

    except Exception as e:
        logger.error(f"Opaque predicate detection failed: {e}")
        return False


def detect_indirect_jumps(simplifier: Any) -> bool:
    """Detect indirect jumps that may hide control flow."""
    try:
        indirect_count = 0

        for address, block in simplifier.blocks.items():
            for instr in block.instructions:
                opcode = instr.get("opcode", "").lower()

                if "jmp" in opcode and "[" in opcode:
                    indirect_count += 1
                elif "call" in opcode and "[" in opcode:
                    indirect_count += 1

        return indirect_count > 0

    except Exception as e:
        logger.error(f"Indirect jump detection failed: {e}")
        return False


def detect_fake_control_flow(simplifier: Any) -> bool:
    """Detect fake control flow (unreachable code paths)."""
    try:
        if not NETWORKX_AVAILABLE or not simplifier.cfg:
            return False

        entry_node = min(simplifier.blocks.keys()) if simplifier.blocks else 0
        reachable = set(nx.descendants(simplifier.cfg, entry_node))
        reachable.add(entry_node)

        unreachable_count = len(simplifier.blocks) - len(reachable)
        return unreachable_count > 0

    except Exception as e:
        logger.error(f"Fake control flow detection failed: {e}")
        return False


def detect_switch_case_obfuscation(simplifier: Any) -> bool:
    """Detect obfuscated switch-case statements."""
    try:
        for address, block in simplifier.blocks.items():
            if len(block.successors) > 3:
                for instr in block.instructions:
                    opcode = instr.get("opcode", "").lower()
                    if "jmp" in opcode and any(reg in opcode for reg in ["eax", "rax", "ebx", "rbx"]):
                        return True

        return False

    except Exception as e:
        logger.error(f"Switch-case detection failed: {e}")
        return False
