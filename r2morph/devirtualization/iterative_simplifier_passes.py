"""Concrete simplification passes used by the iterative simplifier."""

from __future__ import annotations

import logging
from typing import Any

from .cfo_simplifier import CFOSimplifier
from .iterative_simplifier_models import SimplificationPass
from .mba_solver import MBASolver
from .vm_handler_analyzer import VMHandlerAnalyzer

logger = logging.getLogger(__name__)


class CFOSimplificationPass(SimplificationPass):
    """Control Flow Obfuscation simplification pass."""

    def __init__(self) -> None:
        self.cfo_simplifier = CFOSimplifier()

    def apply(self, binary: Any, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Apply CFO simplification."""
        try:
            changes_made = False
            functions = context.get("functions", [])

            for func_addr in functions:
                self.cfo_simplifier.binary = binary
                result = self.cfo_simplifier.simplify_control_flow(func_addr)

                if result.success and result.simplified_complexity < result.original_complexity:
                    changes_made = True
                    context.setdefault("cfo_results", []).append(result)

            return changes_made, context

        except Exception as e:
            logger.error(f"CFO simplification failed: {e}")
            return False, context

    def get_name(self) -> str:
        return "CFO_Simplification"


class MBASimplificationPass(SimplificationPass):
    """Mixed Boolean Arithmetic simplification pass."""

    def __init__(self) -> None:
        self.mba_solver = MBASolver()

    def apply(self, binary: Any, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Apply MBA simplification."""
        try:
            changes_made = False
            mba_expressions = context.get("mba_expressions", [])

            for expr in mba_expressions:
                result = self.mba_solver.simplify_mba(expr)

                if result.success and result.complexity_reduction > 0.1:
                    changes_made = True
                    context.setdefault("mba_results", []).append(result)

            return changes_made, context

        except Exception as e:
            logger.error(f"MBA simplification failed: {e}")
            return False, context

    def get_name(self) -> str:
        return "MBA_Simplification"


class VMDevirtualizationPass(SimplificationPass):
    """Virtual machine devirtualization pass."""

    def __init__(self) -> None:
        self.vm_analyzer = VMHandlerAnalyzer(None)

    def apply(self, binary: Any, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Apply VM devirtualization."""
        try:
            changes_made = False
            self.vm_analyzer.binary = binary

            vm_dispatchers = context.get("vm_dispatchers", [])

            for dispatcher_addr in vm_dispatchers:
                vm_arch = self.vm_analyzer.analyze_vm_architecture(dispatcher_addr)

                if vm_arch and vm_arch.handlers:
                    changes_made = True
                    context.setdefault("vm_results", []).append(vm_arch)

            return changes_made, context

        except Exception as e:
            logger.error(f"VM devirtualization failed: {e}")
            return False, context

    def get_name(self) -> str:
        return "VM_Devirtualization"
