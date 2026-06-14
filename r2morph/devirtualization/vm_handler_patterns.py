"""Static handler pattern catalog for VM handler analysis."""

from __future__ import annotations

from typing import Any

from .vm_handler_models import VMHandlerType


def load_vm_handler_patterns() -> dict[VMHandlerType, list[dict[str, Any]]]:
    """Return the canonical handler pattern catalog."""
    return {
        VMHandlerType.ARITHMETIC: [
            {
                "pattern": ["add", "sub", "mul", "div", "inc", "dec"],
                "description": "Basic arithmetic operations",
                "confidence": 0.8,
            },
            {
                "pattern": ["add.*eax.*ebx", "mov.*eax"],
                "description": "Register arithmetic pattern",
                "confidence": 0.7,
            },
        ],
        VMHandlerType.LOGICAL: [
            {
                "pattern": ["and", "or", "xor", "not", "shl", "shr"],
                "description": "Logical and bitwise operations",
                "confidence": 0.8,
            }
        ],
        VMHandlerType.MEMORY: [
            {"pattern": ["mov.*\\[.*\\]", "lea"], "description": "Memory access patterns", "confidence": 0.7}
        ],
        VMHandlerType.STACK: [{"pattern": ["push", "pop"], "description": "Stack operations", "confidence": 0.9}],
        VMHandlerType.BRANCH: [
            {
                "pattern": ["jmp", "je", "jne", "jz", "jnz", "jc", "jnc"],
                "description": "Conditional and unconditional jumps",
                "confidence": 0.8,
            }
        ],
        VMHandlerType.COMPARE: [
            {"pattern": ["cmp", "test"], "description": "Comparison operations", "confidence": 0.9}
        ],
    }
