"""Model and constraint conversion helpers for symbolic solving."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def convert_angr_to_z3(constraints: list[Any], z3: Any | None) -> list[Any]:
    """Convert angr/claripy constraints to Z3 format."""
    z3_constraints: list[Any] = []

    if z3 is None:
        return z3_constraints

    try:
        for constraint in constraints:
            if isinstance(constraint, z3.ExprRef):
                z3_constraints.append(constraint)
            elif hasattr(constraint, "to_z3"):
                z3_constraints.append(constraint.to_z3())
            else:
                logger.debug("Could not convert constraint: %s", constraint)
    except Exception as exc:
        logger.debug("Error converting constraints: %s", exc)

    return z3_constraints


def extract_model(z3_model: Any, z3: Any | None) -> dict[str, Any]:
    """Extract model values from a Z3 solution."""
    model: dict[str, Any] = {}

    if z3 is None or z3_model is None:
        return model

    try:
        for decl in z3_model:
            var_name = str(decl)
            value = z3_model[decl]

            if z3.is_int_value(value) or z3.is_bv_value(value):
                model[var_name] = value.as_long()
            elif z3.is_bool(value):
                model[var_name] = z3.is_true(value)
            else:
                model[var_name] = str(value)
    except Exception as exc:
        logger.debug("Error extracting model: %s", exc)

    return model


def convert_single_constraint(constraint: Any, z3: Any | None) -> Any | None:
    """Convert a single constraint to Z3 format."""
    if z3 is None:
        return None

    try:
        if isinstance(constraint, bool):
            return z3.BoolVal(constraint)
        if isinstance(constraint, z3.ExprRef):
            return constraint
        if hasattr(constraint, "to_z3"):
            return constraint.to_z3()
    except Exception as exc:
        logger.debug("Error converting single constraint: %s", exc)

    return None
