"""Pure metrics helpers for VM handler analysis."""

from __future__ import annotations

from typing import Any

from .vm_handler_models import VMArchitecture, VMHandler, VMHandlerType


def calculate_handler_confidence(handler: VMHandler) -> float:
    """Calculate confidence score for handler classification."""
    confidence = 0.5

    if handler.handler_type != VMHandlerType.UNKNOWN:
        confidence += 0.3

    if handler.equivalent_x86:
        confidence += 0.2

    if len(handler.instructions) < 3:
        confidence -= 0.2
    elif len(handler.instructions) > 50:
        confidence -= 0.1

    return max(0.0, min(1.0, confidence))


def build_handler_statistics(vm_architecture: VMArchitecture | None) -> dict[str, Any]:
    """Summarize a VM architecture's analyzed handler set."""
    if not vm_architecture:
        return {}

    type_counts: dict[str, int] = {}
    total_handlers = len(vm_architecture.handlers)

    for handler in vm_architecture.handlers.values():
        handler_type = handler.handler_type.value
        type_counts[handler_type] = type_counts.get(handler_type, 0) + 1

    avg_confidence = 0.0
    if total_handlers > 0:
        avg_confidence = sum(h.confidence for h in vm_architecture.handlers.values()) / total_handlers

    return {
        "total_handlers": total_handlers,
        "handler_types": type_counts,
        "average_confidence": avg_confidence,
        "dispatcher_address": vm_architecture.dispatcher_address,
        "handler_table_address": vm_architecture.handler_table_address,
    }
