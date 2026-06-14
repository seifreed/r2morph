"""Shared data flow model types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DataFlowDirection(Enum):
    """Direction of data flow analysis."""

    FORWARD = "forward"
    BACKWARD = "backward"


@dataclass(frozen=True)
class Register:
    """Represents a CPU register."""

    name: str
    size: int = 64
    is_float: bool = False

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash((self.name, self.size, self.is_float))

    def aliases(self) -> set[Register]:
        """Get all aliases of this register."""
        aliases: set[Register] = {self}
        name = self.name.lower()

        for alias_set in _X86_ALIAS_FAMILIES:
            if name in alias_set:
                return {Register(a, self._x86_alias_size(a)) for a in alias_set}

        for alias_set in _ARM64_ALIAS_FAMILIES:
            if name in alias_set:
                return {Register(a, 64 if a.startswith("x") or a in ("sp", "lr") else 32) for a in alias_set}

        for alias_set in _ARM32_ALIAS_FAMILIES:
            if name in alias_set:
                return {Register(a, 32) for a in alias_set}

        return aliases

    @staticmethod
    def _x86_alias_size(alias: str) -> int:
        """Bit width of an x86 sub-register name within its alias family."""
        if alias.startswith("r") and "d" not in alias and "w" not in alias and "b" not in alias:
            return 64
        if "d" in alias or alias.startswith("e"):
            return 32
        if "w" in alias or alias.endswith("w"):
            return 16
        if "b" in alias:
            return 8
        return 64


@dataclass
class Definition:
    """Represents a definition of a register or memory location."""

    address: int
    register: Register | None = None
    memory_address: int | None = None
    instruction: str = ""
    value: Any | None = None

    def __repr__(self) -> str:
        if self.register:
            return f"<Def 0x{self.address:x} {self.register}>"
        return f"<Def 0x{self.address:x} mem>"

    def __hash__(self) -> int:
        return hash((self.address, self.register, self.memory_address))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Definition):
            return False
        return (
            self.address == other.address
            and self.register == other.register
            and self.memory_address == other.memory_address
        )


@dataclass
class Use:
    """Represents a use of a register or memory location."""

    address: int
    register: Register | None = None
    memory_address: int | None = None
    instruction: str = ""

    def __repr__(self) -> str:
        if self.register:
            return f"<Use 0x{self.address:x} {self.register}>"
        return f"<Use 0x{self.address:x} mem>"

    def __hash__(self) -> int:
        return hash((self.address, self.register, self.memory_address))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Use):
            return False
        return (
            self.address == other.address
            and self.register == other.register
            and self.memory_address == other.memory_address
        )


@dataclass
class DefUseChain:
    """Represents a definition-use chain."""

    definition: Definition
    register: Register
    uses: list[Use] = field(default_factory=list)
    live_range: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        """Initialize live range from definition and uses."""
        if self.live_range is None:
            self._update_live_range()

    def __repr__(self) -> str:
        return f"<DefUseChain {self.register} {len(self.uses)} uses>"

    def add_use(self, use: Use) -> None:
        """Add a use to this chain."""
        if use not in self.uses:
            self.uses.append(use)
            self._update_live_range()

    def _update_live_range(self) -> None:
        """Update live range based on definition and uses."""
        addresses = [self.definition.address] + [u.address for u in self.uses]
        if addresses:
            self.live_range = (min(addresses), max(addresses))

    def is_live_at(self, address: int) -> bool:
        """Check if this def-use chain is live at an address."""
        if self.live_range is None:
            return False
        return self.live_range[0] <= address <= self.live_range[1]


class DataFlowResult:
    """Result of data flow analysis."""

    def __init__(self) -> None:
        self.live_in: dict[int, set[Register]] = {}
        self.live_out: dict[int, set[Register]] = {}
        self.reaching_in: dict[int, set[Definition]] = {}
        self.reaching_out: dict[int, set[Definition]] = {}
        self.def_use_chains: list[DefUseChain] = []
        self.register_values: dict[int, dict[str, Any]] = {}
        self.defined_at: dict[int, set[Register]] = {}
        self.used_at: dict[int, set[Register]] = {}

    def get_live_registers(self, address: int) -> set[Register]:
        """Get live registers at an address."""
        return self.live_in.get(address, set())

    def is_register_live(self, address: int, register: Register) -> bool:
        """Check if a register is live at an address."""
        live = self.live_in.get(address, set())
        return any(r.name == register.name for r in live)

    def get_reaching_definitions(self, address: int) -> set[Definition]:
        """Get definitions reaching an address."""
        return self.reaching_in.get(address, set())

    def get_def_use_chain(self, register: Register) -> DefUseChain | None:
        """Get def-use chain for a register."""
        for chain in self.def_use_chains:
            if chain.register.name == register.name:
                return chain
        return None


_X86_ALIAS_FAMILIES = (
    {"rax", "eax", "ax", "al"},
    {"rbx", "ebx", "bx", "bl"},
    {"rcx", "ecx", "cx", "cl"},
    {"rdx", "edx", "dx", "dl"},
    {"rsi", "esi", "si", "sil"},
    {"rdi", "edi", "di", "dil"},
    {"rbp", "ebp", "bp", "bpl"},
    {"rsp", "esp", "sp", "spl"},
    {"r8", "r8d", "r8w", "r8b"},
    {"r9", "r9d", "r9w", "r9b"},
    {"r10", "r10d", "r10w", "r10b"},
    {"r11", "r11d", "r11w", "r11b"},
    {"r12", "r12d", "r12w", "r12b"},
    {"r13", "r13d", "r13w", "r13b"},
    {"r14", "r14d", "r14w", "r14b"},
    {"r15", "r15d", "r15w", "r15b"},
)

_ARM64_ALIAS_FAMILIES = tuple({f"x{n}", f"w{n}"} for n in range(31)) + (
    {"sp", "wsp"},
    {"lr", "x30"},
)

_ARM32_ALIAS_FAMILIES = (
    {"r0"},
    {"r1"},
    {"r2"},
    {"r3"},
    {"r4"},
    {"r5"},
    {"r6"},
    {"r7"},
    {"r8"},
    {"r9", "sb"},
    {"r10", "sl"},
    {"r11", "fp"},
    {"r12", "ip"},
    {"r13", "sp"},
    {"r14", "lr"},
    {"r15", "pc"},
)
