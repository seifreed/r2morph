"""
Register substitution mutation pass.

Replaces registers with equivalent unused registers in code sequences.
"""

import logging
import random
from typing import Any, List, Tuple

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class RegisterSubstitutionPass(MutationPass):
    """
    Mutation pass that substitutes registers with equivalent ones.

    This mutation replaces registers throughout a code sequence with
    different but equivalent registers, preserving program semantics.

    Example (x86):
        mov eax, 5     ->    mov ecx, 5
        add eax, 3     ->    add ecx, 3
        ret            ->    mov eax, ecx
                             ret

    The key is to ensure the substitution is valid within the scope
    and restore original values when needed (e.g., for calling conventions).

    Config options:
        - probability: Probability of substituting in a function (default: 0.2)
        - max_substitutions_per_function: Max substitutions per function (default: 3)
        - respect_calling_convention: Respect ABI calling conventions (default: True)
    """

    REGISTER_CLASSES = {
        "x86": {
            "gp32": ["eax", "ebx", "ecx", "edx", "esi", "edi"],
            "caller_saved": ["eax", "ecx", "edx"],
            "callee_saved": ["ebx", "esi", "edi"],
        },
        "x64": {
            "gp64": [
                "rax",
                "rbx",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
            ],
            "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
            "callee_saved": ["rbx", "r12", "r13", "r14", "r15"],
        },
        "arm": {
            "gp": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
            "caller_saved": ["r0", "r1", "r2", "r3"],
            "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        },
    }

    # Register sizes in bits (for x86/x64)
    REGISTER_SIZES = {
        # 8-bit registers
        "al": 8,
        "bl": 8,
        "cl": 8,
        "dl": 8,
        "ah": 8,
        "bh": 8,
        "ch": 8,
        "dh": 8,
        "spl": 8,
        "bpl": 8,
        "sil": 8,
        "dil": 8,
        "r8b": 8,
        "r9b": 8,
        "r10b": 8,
        "r11b": 8,
        "r12b": 8,
        "r13b": 8,
        "r14b": 8,
        "r15b": 8,
        # 16-bit registers
        "ax": 16,
        "bx": 16,
        "cx": 16,
        "dx": 16,
        "sp": 16,
        "bp": 16,
        "si": 16,
        "di": 16,
        "r8w": 16,
        "r9w": 16,
        "r10w": 16,
        "r11w": 16,
        "r12w": 16,
        "r13w": 16,
        "r14w": 16,
        "r15w": 16,
        # 32-bit registers
        "eax": 32,
        "ebx": 32,
        "ecx": 32,
        "edx": 32,
        "esp": 32,
        "ebp": 32,
        "esi": 32,
        "edi": 32,
        "r8d": 32,
        "r9d": 32,
        "r10d": 32,
        "r11d": 32,
        "r12d": 32,
        "r13d": 32,
        "r14d": 32,
        "r15d": 32,
        # 64-bit registers
        "rax": 64,
        "rbx": 64,
        "rcx": 64,
        "rdx": 64,
        "rsp": 64,
        "rbp": 64,
        "rsi": 64,
        "rdi": 64,
        "r8": 64,
        "r9": 64,
        "r10": 64,
        "r11": 64,
        "r12": 64,
        "r13": 64,
        "r14": 64,
        "r15": 64,
    }

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize register substitution pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="RegisterSubstitution", config=config)
        self.probability = self.config.get("probability", 0.2)
        self.max_substitutions = self.config.get("max_substitutions_per_function", 3)
        self.respect_calling_convention = self.config.get("respect_calling_convention", True)

    def _get_register_class(self, arch: str) -> dict[str, list[str]]:
        """
        Get register classes for architecture.

        Args:
            arch: Architecture name

        Returns:
            Dictionary of register classes
        """
        if arch in ["x86", "x64"]:
            arch_family = arch
        elif arch in ["arm", "arm64"]:
            arch_family = "arm"
        else:
            return {}

        return self.REGISTER_CLASSES.get(arch_family, {})

    def _find_substitution_candidates(
        self, instructions: list[dict[str, Any]], arch: str
    ) -> list[Tuple[str, str]]:
        """
        Find valid register substitution opportunities.

        Args:
            instructions: List of instructions
            arch: Architecture

        Returns:
            List of (original_reg, substitute_reg) tuples
        """
        register_classes = self._get_register_class(arch)
        if not register_classes:
            return []

        candidates = []

        used_registers = set()
        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            for reg_class in register_classes.values():
                for reg in reg_class:
                    if reg in disasm:
                        used_registers.add(reg)

        caller_saved = set(register_classes.get("caller_saved", []))
        unused = caller_saved - used_registers

        if unused:
            for used_reg in used_registers & caller_saved:
                if unused:
                    substitute = random.choice(list(unused))
                    candidates.append((used_reg, substitute))
                    unused.discard(substitute)

        return candidates

    def _count_register_uses(self, instructions: list[dict[str, Any]], register: str) -> int:
        """
        Count how many times a register is used.

        Args:
            instructions: List of instructions
            register: Register name

        Returns:
            Number of uses
        """
        count = 0
        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            if register in disasm:
                count += 1
        return count

    def _is_safe_size_extension_substitution(
        self, disasm: str, orig_reg: str, subst_reg: str
    ) -> bool:
        """
        Check if register substitution is safe for size-extension instructions (movzx, movsx).

        These instructions have size constraints:
        - movzx eax, al (32-bit dest, 8-bit source) - INVALID: source is part of dest
        - movzx edx, al (valid - different register families) ✅
        - movzx al, eax (INVALID - dest smaller than source) ❌

        Args:
            disasm: Instruction disassembly
            orig_reg: Original register being replaced
            subst_reg: Substitute register

        Returns:
            True if substitution is safe, False otherwise
        """
        # Parse the instruction to extract source and destination
        parts = disasm.split(",")
        if len(parts) < 2:
            return False

        # Get destination and source operands
        dest = parts[0].split()[-1].strip()  # Last word before comma
        source = parts[1].strip()

        # Get sizes
        orig_size = self.REGISTER_SIZES.get(orig_reg, 0)
        subst_size = self.REGISTER_SIZES.get(subst_reg, 0)

        if orig_size == 0 or subst_size == 0:
            # Unknown register size, be conservative
            return False

        # For movzx/movsx: both registers must have same size if being substituted
        # This ensures the instruction semantics remain valid
        if orig_size != subst_size:
            logger.debug(
                f"Skipping {disasm}: {orig_reg}({orig_size}b) -> {subst_reg}({subst_size}b) "
                f"size mismatch for movzx/movsx"
            )
            return False

        # Check if source and dest are from the same register family
        # e.g., movzx eax, al is problematic (al is part of eax)
        # This creates register aliasing issues that radare2 cannot assemble
        register_families = {
            "a": ["al", "ah", "ax", "eax", "rax"],
            "b": ["bl", "bh", "bx", "ebx", "rbx"],
            "c": ["cl", "ch", "cx", "ecx", "rcx"],
            "d": ["dl", "dh", "dx", "edx", "rdx"],
        }

        dest_family = None
        source_family = None

        for family, regs in register_families.items():
            if dest in regs:
                dest_family = family
            if source in regs:
                source_family = family

        if dest_family and source_family and dest_family == source_family:
            # Source and dest from same register family - problematic
            logger.debug(f"Skipping {disasm}: {dest} and {source} from same register family")
            return False

        # Additionally verify the constraint: destination must be larger than source
        dest_size = self.REGISTER_SIZES.get(dest, 0)
        source_size = self.REGISTER_SIZES.get(source, 0)

        if dest_size > 0 and source_size > 0 and dest_size <= source_size:
            # This would be invalid even without substitution
            return False

        return True

    def _is_safe_lea_substitution(self, disasm: str, orig_reg: str, subst_reg: str) -> bool:
        """
        Check if register substitution is safe for LEA (Load Effective Address).

        LEA calculates an address without dereferencing:
        - lea rax, [rbx + rcx*4] - rax is destination, rbx/rcx are in calculation
        - Substituting rax (dest) is SAFE ✅
        - Substituting rbx or rcx (in calculation) is UNSAFE ❌ (changes address)

        Args:
            disasm: Instruction disassembly
            orig_reg: Original register being replaced
            subst_reg: Substitute register

        Returns:
            True if substitution is safe, False otherwise
        """
        # Parse: "lea dest, [calculation]"
        parts = disasm.split(",", 1)
        if len(parts) < 2:
            return False

        dest = parts[0].split()[-1].strip()
        calculation_part = parts[1].strip()

        # Check if orig_reg is the destination
        if orig_reg == dest:
            # Safe to substitute destination register
            return True

        # Check if orig_reg is in the calculation (inside brackets)
        if "[" in calculation_part and "]" in calculation_part:
            calc_inner = calculation_part.split("[")[1].split("]")[0]
            if orig_reg in calc_inner:
                # Unsafe: register is part of address calculation
                logger.debug(
                    f"Skipping LEA substitution: {orig_reg} in address calculation of '{disasm}'"
                )
                return False

        return True

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply register substitution mutations to the binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")

        register_classes = self._get_register_class(arch)
        if not register_classes:
            logger.warning(f"No register classes defined for architecture: {arch}")
            return {
                "mutations_applied": 0,
                "error": f"Unsupported architecture: {arch}",
            }

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        total_registers_substituted = 0

        logger.info(f"Register substitution: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < 20:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            candidates = self._find_substitution_candidates(instructions, arch)

            if not candidates:
                continue

            if random.random() > self.probability:
                continue

            num_substitutions = min(self.max_substitutions, len(candidates))
            selected = random.sample(candidates, num_substitutions)

            func_mutations = 0
            for orig_reg, subst_reg in selected:
                substituted_count = 0

                for insn in instructions:
                    disasm = insn.get("disasm", "").lower()

                    if orig_reg not in disasm:
                        continue

                    mnemonic = disasm.split()[0] if disasm else ""

                    # Category 1: ALWAYS SKIP - Hardware/semantic restrictions
                    # These cannot be safely substituted due to hardware constraints
                    always_skip_mnemonics = [
                        "xlat",  # Table lookup with implicit AL register
                        "movabs",  # 64-bit immediate/address - complex syntax issues
                        "cmovz",
                        "cmovnz",
                        "cmove",
                        "cmovne",  # Conditional moves
                        "setne",
                        "sete",
                        "setz",
                        "setnz",  # Set byte on condition
                        "lock",  # Atomic operations prefix
                        "xadd",  # Atomic exchange-and-add
                        "cmpxchg",  # Atomic compare-and-exchange
                    ]
                    if mnemonic in always_skip_mnemonics:
                        continue

                    # Category 2: VALIDATE FIRST - Can be resolved with proper checks
                    # movzx/movsx: Size-extension instructions with manual encoding fallback
                    if mnemonic in ["movzx", "movsx"]:
                        if not self._is_safe_size_extension_substitution(
                            disasm, orig_reg, subst_reg
                        ):
                            continue

                    # LEA: Address calculation - only safe if substituting destination
                    if mnemonic == "lea":
                        if not self._is_safe_lea_substitution(disasm, orig_reg, subst_reg):
                            continue

                    # Skip instructions with memory addresses to avoid corrupting them
                    if "[" in disasm and "]" in disasm:
                        # Check if register is only in memory operand (skip these)
                        parts = disasm.split("[")
                        if len(parts) > 1:
                            mem_part = parts[1].split("]")[0]
                            # If register only appears in memory operand, skip
                            non_mem_part = parts[0] + (
                                parts[1].split("]")[1] if "]" in parts[1] else ""
                            )
                            if orig_reg not in non_mem_part and orig_reg in mem_part:
                                continue

                    new_disasm = disasm.replace(orig_reg, subst_reg)

                    addr = insn.get("addr", 0)
                    orig_size = insn.get("size", 0)

                    if addr == 0 or orig_size == 0:
                        continue

                    try:
                        new_bytes = binary.assemble(new_disasm, func["addr"])

                        if new_bytes:
                            new_size = len(new_bytes)

                            if new_size <= orig_size:
                                binary.write_bytes(addr, new_bytes)

                                if new_size < orig_size:
                                    binary.nop_fill(addr + new_size, orig_size - new_size)

                                logger.debug(
                                    f"Substituted {orig_reg} -> {subst_reg} at 0x{addr:x}: "
                                    f"'{disasm}' -> '{new_disasm}'"
                                )
                                substituted_count += 1
                                func_mutations += 1
                            else:
                                logger.debug(
                                    f"Skipping substitution at 0x{addr:x}: new instruction too large"
                                )
                    except Exception as e:
                        logger.debug(f"Failed to substitute at 0x{addr:x}: {e}")

                if substituted_count > 0:
                    logger.info(
                        f"Substituted {orig_reg} -> {subst_reg} in {func.get('name')}: "
                        f"{substituted_count} instructions"
                    )
                    total_registers_substituted += 1

            if func_mutations > 0:
                mutations_applied += func_mutations
                functions_mutated += 1

        logger.info(
            f"Register substitution complete: {total_registers_substituted} registers "
            f"substituted in {functions_mutated} functions "
            f"({mutations_applied} total instruction changes)"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "registers_substituted": total_registers_substituted,
            "total_functions": len(functions),
        }
