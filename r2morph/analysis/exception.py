"""Exception edge analysis for complex CFG handling."""

from __future__ import annotations

from typing import Any

from r2morph.analysis.exception_models import (  # noqa: F401
    ExceptionAction,
    ExceptionFrame,
    ExceptionTableEntry,
    LandingPad,
)
from r2morph.analysis.exception_reader import ExceptionInfoReader
from r2morph.core.binary import Binary


class ExceptionAwareCFGBuilder:
    """
    CFG builder that includes exception handling edges.

    This extends the basic CFG builder to handle:
    - Exception dispatch edges
    - Landing pad blocks
    - Cleanup/final handler blocks
    """

    def __init__(self, binary: Binary):
        """Initialize exception-aware CFG builder."""
        self.binary = binary
        self.exception_reader = ExceptionInfoReader(binary)

    def analyze_function_exceptions(self, function_address: int) -> dict[str, Any]:
        """Analyze exception handling for a function."""
        frames = self.exception_reader.read_exception_frames()

        frame = frames.get(function_address)
        if not frame:
            return {
                "has_exceptions": False,
                "landing_pads": [],
                "exception_edges": [],
            }

        return {
            "has_exceptions": True,
            "landing_pads": [
                {
                    "address": pad.address,
                    "size": pad.size,
                    "action": pad.action.value,
                }
                for pad in frame.landing_pads
            ],
            "exception_edges": [(frame.function_start, pad.address, pad.action.value) for pad in frame.landing_pads],
        }

    def is_protected_region(self, address: int) -> bool:
        """Check if an address is within a protected region (try block)."""
        frames = self.exception_reader.read_exception_frames()

        for frame in frames.values():
            if frame.function_start <= address < frame.function_end:
                if frame.landing_pads:
                    return True

        return False

    def get_landing_pad_for_address(self, address: int) -> LandingPad | None:
        """Get the landing pad that handles exceptions from an address."""
        frames = self.exception_reader.read_exception_frames()

        for frame in frames.values():
            if frame.function_start <= address < frame.function_end:
                for pad in frame.landing_pads:
                    return pad

        return None

    def get_exception_aware_functions(self) -> list[int]:
        """Get list of functions with exception handling."""
        frames = self.exception_reader.read_exception_frames()
        return [addr for addr, frame in frames.items() if frame.landing_pads]
