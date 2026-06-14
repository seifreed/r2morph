"""Shared def-use model types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from r2morph.analysis.dataflow_models import Definition, Register, Use


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
