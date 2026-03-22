"""
Data flow analysis engine for binary analysis.

Provides forward and backward data flow analysis including:
- Reaching definitions
- Liveness analysis
- Def-use chains
- Value set analysis
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph

logger = logging.getLogger(__name__)


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

        x86_alias_map = {
            "rax": {"rax", "eax", "ax", "al"},
            "rbx": {"rbx", "ebx", "bx", "bl"},
            "rcx": {"rcx", "ecx", "cx", "cl"},
            "rdx": {"rdx", "edx", "dx", "dl"},
            "rsi": {"rsi", "esi", "si", "sil"},
            "rdi": {"rdi", "edi", "di", "dil"},
            "rbp": {"rbp", "ebp", "bp", "bpl"},
            "rsp": {"rsp", "esp", "sp", "spl"},
            "r8": {"r8", "r8d", "r8w", "r8b"},
            "r9": {"r9", "r9d", "r9w", "r9b"},
            "r10": {"r10", "r10d", "r10w", "r10b"},
            "r11": {"r11", "r11d", "r11w", "r11b"},
            "r12": {"r12", "r12d", "r12w", "r12b"},
            "r13": {"r13", "r13d", "r13w", "r13b"},
            "r14": {"r14", "r14d", "r14w", "r14b"},
            "r15": {"r15", "r15d", "r15w", "r15b"},
        }

        arm64_alias_map = {
            "x0": {"x0", "w0"},
            "x1": {"x1", "w1"},
            "x2": {"x2", "w2"},
            "x3": {"x3", "w3"},
            "x4": {"x4", "w4"},
            "x5": {"x5", "w5"},
            "x6": {"x6", "w6"},
            "x7": {"x7", "w7"},
            "x8": {"x8", "w8"},
            "x9": {"x9", "w9"},
            "x10": {"x10", "w10"},
            "x11": {"x11", "w11"},
            "x12": {"x12", "w12"},
            "x13": {"x13", "w13"},
            "x14": {"x14", "w14"},
            "x15": {"x15", "w15"},
            "x16": {"x16", "w16"},
            "x17": {"x17", "w17"},
            "x18": {"x18", "w18"},
            "x19": {"x19", "w19"},
            "x20": {"x20", "w20"},
            "x21": {"x21", "w21"},
            "x22": {"x22", "w22"},
            "x23": {"x23", "w23"},
            "x24": {"x24", "w24"},
            "x25": {"x25", "w25"},
            "x26": {"x26", "w26"},
            "x27": {"x27", "w27"},
            "x28": {"x28", "w28"},
            "x29": {"x29", "w29"},
            "x30": {"x30", "w30"},
            "sp": {"sp", "wsp"},
            "lr": {"lr", "x30"},
        }

        arm32_alias_map = {
            "r0": {"r0"},
            "r1": {"r1"},
            "r2": {"r2"},
            "r3": {"r3"},
            "r4": {"r4"},
            "r5": {"r5"},
            "r6": {"r6"},
            "r7": {"r7"},
            "r8": {"r8"},
            "r9": {"r9", "sb"},
            "r10": {"r10", "sl"},
            "r11": {"r11", "fp"},
            "r12": {"r12", "ip"},
            "r13": {"r13", "sp"},
            "r14": {"r14", "lr"},
            "r15": {"r15", "pc"},
        }

        for base, alias_set in x86_alias_map.items():
            if name in alias_set:
                result: set[Register] = set()
                for a in alias_set:
                    if a.startswith("r") and "d" not in a and "w" not in a and "b" not in a:
                        size = 64
                    elif "d" in a or a.startswith("e"):
                        size = 32
                    elif "w" in a or a.endswith("w"):
                        size = 16
                    elif "b" in a:
                        size = 8
                    else:
                        size = 64
                    result.add(Register(a, size))
                return result

        for base, alias_set in arm64_alias_map.items():
            if name in alias_set:
                result: set[Register] = set()
                for a in alias_set:
                    size = 64 if a.startswith("x") or a == "sp" or a == "lr" else 32
                    result.add(Register(a, size))
                return result

        for base, alias_set in arm32_alias_map.items():
            if name in alias_set:
                result: set[Register] = set()
                for a in alias_set:
                    result.add(Register(a, 32))
                return result

        return aliases


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

    def __post_init__(self):
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

    def __init__(self):
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


class DataFlowAnalyzer:
    """
    Core data flow analyzer.

    Performs forward and backward data flow analysis on CFG basic blocks.

    Usage:
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()
        live_regs = result.get_live_registers(address)
    """

    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        self._result = DataFlowResult()

    def analyze(self) -> DataFlowResult:
        """
        Perform complete data flow analysis.

        Returns:
            DataFlowResult with liveness, reaching definitions, and def-use chains
        """
        self._compute_liveness()
        self._compute_reaching_definitions()
        self._build_def_use_chains()

        return self._result

    def _compute_liveness(self) -> None:
        """Compute liveness analysis (backward data flow)."""
        self._result.live_in.clear()
        self._result.live_out.clear()

        for addr in self.cfg.blocks:
            self._result.live_in[addr] = set()
            self._result.live_out[addr] = set()

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr in sorted(self.cfg.blocks.keys(), reverse=True):
                block = self.cfg.blocks[addr]

                old_out = self._result.live_out[addr].copy()

                for succ_addr in block.successors:
                    if succ_addr in self._result.live_in:
                        self._result.live_out[addr].update(self._result.live_in[succ_addr])

                old_in = self._result.live_in[addr].copy()

                use = self._get_block_use(block)
                defn = self._get_block_def(block)

                self._result.live_in[addr] = use | (self._result.live_out[addr] - defn)

                if self._result.live_in[addr] != old_in or self._result.live_out[addr] != old_out:
                    changed = True

    def _get_block_use(self, block: BasicBlock) -> set[Register]:
        """Get registers used before being defined in a block."""
        used = set()
        defined = set()

        for insn in block.instructions:
            regs_used = self._extract_used_registers(insn)
            for reg in regs_used:
                if reg not in defined and not any(r.name == reg.name for r in defined):
                    used.add(reg)

            regs_defined = self._extract_defined_registers(insn)
            defined.update(regs_defined)

        return used

    def _get_block_def(self, block: BasicBlock) -> set[Register]:
        """Get registers defined in a block."""
        defined = set()

        for insn in block.instructions:
            regs_def = self._extract_defined_registers(insn)
            defined.update(regs_def)

        return defined

    def _extract_used_registers(self, insn: dict) -> set[Register]:
        """Extract registers used by an instruction."""
        used = set()
        disasm = insn.get("disasm", "").lower()

        if not disasm:
            return used

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) < 2:
            return used

        operands = operand_parts[1]
        if "," in operands:
            src_parts = operands.split(",")
            if len(src_parts) >= 2:
                src = src_parts[1].strip()
                for reg in self._extract_registers_from_operand(src):
                    used.add(reg)

        for reg in self._extract_registers_from_operand(operands):
            if "(" in operands and ")" in operands:
                used.add(reg)

        return used

    def _extract_defined_registers(self, insn: dict) -> set[Register]:
        """Extract registers defined by an instruction."""
        defined = set()
        disasm = insn.get("disasm", "").lower()
        mnemonic = insn.get("type", "").lower()

        if not disasm:
            return defined

        if mnemonic in ("jmp", "ret", "call", "nop"):
            return defined

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) < 2:
            return defined

        operands = operand_parts[1]
        if "," in operands:
            dest = operands.split(",")[0].strip()

            if "[" in dest:
                return defined

            for reg in self._extract_registers_from_operand(dest):
                defined.add(reg)

        return defined

    def _extract_registers_from_operand(self, operand: str) -> set[Register]:
        """Extract register names from an operand string."""
        registers = set()
        operand = operand.lower()

        x86_regs = [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "r8d",
            "r9d",
            "r10d",
            "r11d",
            "r12d",
            "r13d",
            "r14d",
            "r15d",
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "bp",
            "sp",
            "r8w",
            "r9w",
            "r10w",
            "r11w",
            "r12w",
            "r13w",
            "r14w",
            "r15w",
            "al",
            "bl",
            "cl",
            "dl",
            "sil",
            "dil",
            "bpl",
            "spl",
            "r8b",
            "r9b",
            "r10b",
            "r11b",
            "r12b",
            "r13b",
            "r14b",
            "r15b",
        ]

        for reg in x86_regs:
            if reg in operand:
                size = 64 if reg.startswith("r") and "d" not in reg and "w" not in reg and "b" not in reg else 32
                if reg.endswith("d"):
                    size = 32
                elif reg.endswith("w"):
                    size = 16
                elif reg.endswith("b"):
                    size = 8
                registers.add(Register(reg, size))

        return registers

    def _compute_reaching_definitions(self) -> None:
        """Compute reaching definitions (forward data flow)."""
        self._result.reaching_in.clear()
        self._result.reaching_out.clear()

        for addr in self.cfg.blocks:
            self._result.reaching_in[addr] = set()
            self._result.reaching_out[addr] = set()

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr in sorted(self.cfg.blocks.keys()):
                block = self.cfg.blocks[addr]

                old_in = self._result.reaching_in[addr].copy()

                for pred_addr in block.predecessors:
                    if pred_addr in self._result.reaching_out:
                        self._result.reaching_in[addr].update(self._result.reaching_out[pred_addr])

                gen = self._get_block_gen(block)
                kill = self._get_block_kill(block, gen)

                new_out = gen | (self._result.reaching_in[addr] - kill)

                if self._result.reaching_out[addr] != new_out:
                    self._result.reaching_out[addr] = new_out
                    changed = True
                elif self._result.reaching_in[addr] != old_in:
                    changed = True

    def _get_block_gen(self, block: BasicBlock) -> set[Definition]:
        """Get definitions generated by a block."""
        gen = set()

        for insn in block.instructions:
            addr = insn.get("offset", 0)
            regs_defined = self._extract_defined_registers(insn)

            for reg in regs_defined:
                defn = Definition(address=addr, register=reg, instruction=insn.get("disasm", ""))
                gen.add(defn)

        return gen

    def get_block_definitions(self, block: BasicBlock) -> set[Definition]:
        """Public API to get definitions generated by a block."""
        return self._get_block_gen(block)

    def get_reaching_in(self, block_addr: int) -> set[Definition]:
        """Public API to get reaching definitions for a block."""
        return self._result.reaching_in.get(block_addr, set())

    def get_def_use_chains(self) -> list[DefUseChain]:
        """Public API to get all def-use chains."""
        return self._result.def_use_chains

    def _get_block_kill(self, block: BasicBlock, gen: set[Definition]) -> set[Definition]:
        """Get definitions killed by a block."""
        kill = set()

        defined_regs = set()
        for defn in gen:
            if defn.register:
                defined_regs.add(defn.register)

        for reg in defined_regs:
            for definitions in self._result.reaching_in.values():
                for defn in definitions:
                    if defn.register and defn.register.name == reg.name:
                        kill.add(defn)

        return kill

    def _build_def_use_chains(self) -> None:
        """Build definition-use chains."""
        chains_by_def: dict[tuple[int, str], DefUseChain] = {}

        for addr, block in sorted(self.cfg.blocks.items()):
            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)

                regs_defined = self._extract_defined_registers(insn)
                for reg in regs_defined:
                    key = (insn_addr, reg.name)
                    defn = Definition(address=insn_addr, register=reg)
                    chains_by_def[key] = DefUseChain(
                        definition=defn,
                        register=reg,
                        live_range=(insn_addr, insn_addr),
                    )

        for addr, block in sorted(self.cfg.blocks.items()):
            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)

                regs_used = self._extract_used_registers(insn)
                for reg in regs_used:
                    reaching = self._get_reaching_definition_for(reg, insn_addr)

                    if reaching:
                        key = (reaching.address, reg.name)
                        if key in chains_by_def:
                            use = Use(address=insn_addr, register=reg)
                            chains_by_def[key].add_use(use)

        self._result.def_use_chains = list(chains_by_def.values())

    def _get_reaching_definition_for(self, reg: Register, address: int) -> Definition | None:
        """Get the reaching definition for a register at an address."""
        block_addr = None
        for baddr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                if insn.get("offset", 0) == address:
                    block_addr = baddr
                    break
            if block_addr:
                break

        if block_addr is None:
            return None

        reaching = self._result.reaching_in.get(block_addr, set())

        latest_def: Definition | None = None
        latest_addr = -1

        for defn in reaching:
            if defn.register and defn.register.name == reg.name:
                if defn.address > latest_addr and defn.address < address:
                    latest_def = defn
                    latest_addr = defn.address

        return latest_def

    def get_value_at(self, address: int, register: Register) -> set[Any]:
        """
        Get possible values for a register at an address.

        Args:
            address: Instruction address
            register: Register to analyze

        Returns:
            Set of possible values
        """
        values: set[Any] = set()
        block_addr = None

        for baddr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                if insn.get("offset", 0) == address:
                    block_addr = baddr
                    break
            if block_addr is not None:
                break

        if block_addr is None:
            return values

        reaching = self._result.reaching_in.get(block_addr, set())

        for defn in reaching:
            if defn.register and defn.register.name == register.name:
                if defn.value is not None:
                    values.add(defn.value)

        return values

    def is_safe_to_mutate(self, address: int, mutation_type: str) -> tuple[bool, str]:
        """
        Check if it's safe to apply a mutation at an address.

        Args:
            address: Address to check
            mutation_type: Type of mutation

        Returns:
            Tuple of (is_safe, reason)
        """
        block_addr = None
        for baddr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                if insn.get("offset", 0) == address:
                    block_addr = baddr
                    break
            if block_addr is not None:
                break

        if block_addr is None:
            return (False, "Address not found in CFG")

        live_regs = self._result.live_in.get(block_addr, set())

        if mutation_type in ("register_swap", "register_substitution"):
            critical_regs = {"rsp", "rbp", "esp", "ebp"}
            for reg in live_regs:
                if reg.name.lower() in critical_regs:
                    aliases = reg.aliases()
                    for alias in aliases:
                        if alias.name.lower() in critical_regs:
                            return (False, f"Critical register {reg.name} is live")

        reaching = self._result.reaching_in.get(block_addr, set())

        if mutation_type == "instruction_expansion":
            for defn in reaching:
                if defn.register:
                    if self._is_address_calculation(defn):
                        return (False, "Address calculation nearby - expansion may break pointer references")

        return (True, "Safe to mutate")

    def _is_address_calculation(self, defn: Definition) -> bool:
        """Check if a definition is part of address calculation."""
        if not defn.instruction:
            return False

        insn = defn.instruction.lower()

        if "lea" in insn:
            return True

        if "add" in insn and any(r in insn for r in ["rbp", "rsp", "ebp", "esp"]):
            return True

        if "sub" in insn and any(r in insn for r in ["rbp", "rsp", "ebp", "esp"]):
            return True

        return False
