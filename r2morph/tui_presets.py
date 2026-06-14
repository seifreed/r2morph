"""Pure preset data for the TUI."""

from __future__ import annotations

from typing import Any

DEFAULT_PASS_CONFIGS: dict[str, dict[str, Any]] = {
    "nop": {"max_nops": 3, "use_equiv": True, "avoid_critical": True},
    "substitute": {"x86_equiv": True, "arm_equiv": True, "preserve_semantics": True},
    "register": {"preserve_calling_conv": True, "preserve_callee_saved": True, "max_substitutions": 2},
    "block": {"max_blocks": 10, "preserve_entry": True},
    "dead-code": {"max_instructions": 5, "use_opaque": True},
    "opaque": {"predicate_type": "true", "complexity": "medium"},
    "expand": {"max_expansion": 3, "preserve_flags": True},
    "cff": {"dispatcher_style": "switch", "max_depth": 3},
}


PASS_DESCRIPTIONS: dict[str, tuple[str, bool]] = {
    "nop": ("Insert benign NOP instructions", True),
    "substitute": ("Replace instructions with equivalents", True),
    "register": ("Substitute registers safely", True),
    "block": ("Reorder basic blocks", False),
    "dead-code": ("Inject dead code sequences", False),
    "opaque": ("Insert opaque predicates", False),
    "expand": ("Expand instructions to longer forms", False),
    "cff": ("Flatten control flow", False),
}


CONFIG_TYPES: dict[str, dict[str, type]] = {
    "nop": {"max_nops": int, "use_equiv": bool, "avoid_critical": bool},
    "substitute": {"x86_equiv": bool, "arm_equiv": bool, "preserve_semantics": bool},
    "register": {"preserve_calling_conv": bool, "preserve_callee_saved": bool, "max_substitutions": int},
    "block": {"max_blocks": int, "preserve_entry": bool},
    "dead-code": {"max_instructions": int, "use_opaque": bool},
    "opaque": {"predicate_type": str, "complexity": str},
    "expand": {"max_expansion": int, "preserve_flags": bool},
    "cff": {"dispatcher_style": str, "max_depth": int},
}


CONFIG_OPTIONS: dict[str, dict[str, list[str]]] = {
    "opaque": {"predicate_type": ["true", "false", "mixed"], "complexity": ["low", "medium", "high"]},
    "cff": {"dispatcher_style": ["switch", "jump_table", "nested"]},
}
