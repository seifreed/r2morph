"""
Instruction substitution mutation pass.

Replaces instructions with semantically equivalent alternatives.
Implements r2morph-style bidirectional equivalences and advanced patterns.

Features:
- Bidirectional equivalence groups
- Flag preservation with pushfd/popfd
- Force different mode
- Strict size validation
- jmp + dead code patterns (dynamically generated)
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.equivalences import load_equivalence_rules

logger = logging.getLogger(__name__)


class InstructionSubstitutionPass(MutationPass):
    """
    Mutation pass that substitutes instructions with equivalent ones.

    Replaces instructions with semantically equivalent alternatives to
    change the binary signature while preserving behavior.

    Implements r2morph-style features:
    - Bidirectional equivalences (any pattern can match and be replaced by any other)
    - Jump-based dead code patterns
    - Flag preservation with pushfd/popfd
    - Strict size validation mode
    - Force different mode

    Config options:
        - max_substitutions_per_function: Maximum substitutions per function
        - probability: Probability of substituting a candidate instruction
        - force_different: Force mutations to be different from original (r2morph-style)
        - strict_size: Only apply mutations if size matches exactly (no NOP padding)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize instruction substitution pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="InstructionSubstitution", config=config)
        self.max_substitutions = self.config.get("max_substitutions_per_function", 10)
        self.probability = self.config.get("probability", 0.7)
        self.force_different = self.config.get("force_different", False)
        self.strict_size = self.config.get("strict_size", False)

        self._init_substitution_rules()

    def _init_substitution_rules(self):
        """
        Initialize substitution rules with r2morph-style equivalence groups.

        Each equivalence group is a list of patterns that are all equivalent to each other.
        Any pattern in the group can match, and can be replaced by any other pattern.

        This method shuffles each equivalence group for randomness (r2morph-style re-seeding).
        Called after each successful mutation to ensure different patterns are used.

        Rules are loaded from YAML files in the equivalences/ directory.
        """
        # Load rules from YAML files for each supported architecture
        self.equivalence_groups = {
            "x86": load_equivalence_rules("x86"),
            "arm": load_equivalence_rules("arm"),
        }

        # Shuffle each group for randomness (r2morph-style re-seeding)
        for arch in self.equivalence_groups:
            for group in self.equivalence_groups[arch]:
                random.shuffle(group)

        # Build pattern-to-group lookup table
        self.pattern_to_group = {}
        for arch, groups in self.equivalence_groups.items():
            if arch not in self.pattern_to_group:
                self.pattern_to_group[arch] = {}

            for group_idx, group in enumerate(groups):
                for pattern in group:
                    normalized = self._normalize_instruction(pattern)
                    self.pattern_to_group[arch][normalized] = group_idx

    def _normalize_instruction(self, disasm: str) -> str:
        """
        Normalize instruction for pattern matching.

        Args:
            disasm: Disassembly string

        Returns:
            Normalized instruction
        """
        normalized = " ".join(disasm.lower().split())

        normalized = normalized.replace("0x0", "0")
        normalized = normalized.replace("0x1", "1")

        return normalized

    def _get_equivalents(self, instruction: dict[str, Any], arch: str) -> tuple[str, list[str]]:
        """
        Get all equivalent patterns for an instruction.

        Args:
            instruction: Instruction dictionary from r2
            arch: Architecture (x86, arm, etc.)

        Returns:
            Tuple of (original_pattern, list of equivalent patterns)
        """
        if arch not in self.pattern_to_group:
            return ("", [])

        disasm = instruction.get("disasm", "")
        normalized = self._normalize_instruction(disasm)

        if normalized in self.pattern_to_group[arch]:
            group_idx = self.pattern_to_group[arch][normalized]
            equivalents = self.equivalence_groups[arch][group_idx]
            return (normalized, equivalents)

        return ("", [])

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply instruction substitution mutations to the binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        arch_family, bits = binary.get_arch_family()

        if arch_family == "arm" and bits == 64:
            return self._apply_arm64_mov_substitution(binary)

        if arch_family not in self.equivalence_groups:
            logger.warning(f"No substitution rules for architecture: {arch_family}")
            return {
                "mutations_applied": 0,
                "error": f"Unsupported architecture: {arch_family}",
            }

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        candidates_found = 0

        logger.info(f"Instruction substitution: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            func_mutations = 0
            for insn in instructions:
                original_pattern, equivalents = self._get_equivalents(insn, arch_family)

                if equivalents and len(equivalents) > 1:
                    candidates_found += 1

                    if (
                        random.random() < self.probability
                        and func_mutations < self.max_substitutions
                    ):
                        if self.force_different:
                            available = [e for e in equivalents if e != original_pattern]
                            if not available:
                                continue
                            chosen = random.choice(available)
                        else:
                            chosen = random.choice(equivalents)
                            if chosen == original_pattern:
                                continue

                        addr = insn.get("addr", 0)
                        orig_size = insn.get("size", 0)

                        if addr == 0 or orig_size == 0:
                            continue

                        try:
                            if ";" in chosen:
                                instruction_list = [i.strip() for i in chosen.split(";")]
                                all_bytes = b""

                                for inst in instruction_list:
                                    inst_bytes = binary.assemble(inst, func["addr"])
                                    if not inst_bytes:
                                        logger.debug(f"Failed to assemble part: {inst}")
                                        all_bytes = None
                                        break
                                    all_bytes += inst_bytes

                                new_bytes = all_bytes
                            else:
                                new_bytes = binary.assemble(chosen, func["addr"])

                            if new_bytes:
                                new_size = len(new_bytes)

                                if new_size == orig_size:
                                    binary.write_bytes(addr, new_bytes)
                                    logger.info(
                                        f"Substituted '{insn.get('disasm')}' with "
                                        f"'{chosen}' at 0x{addr:x}"
                                    )
                                    func_mutations += 1
                                    mutations_applied += 1

                                    self._init_substitution_rules()
                                elif new_size < orig_size and not self.strict_size:
                                    binary.write_bytes(addr, new_bytes)
                                    binary.nop_fill(addr + new_size, orig_size - new_size)
                                    logger.info(
                                        f"Substituted '{insn.get('disasm')}' with "
                                        f"'{chosen}' (+ NOPs) at 0x{addr:x}"
                                    )
                                    func_mutations += 1
                                    mutations_applied += 1

                                    self._init_substitution_rules()
                                else:
                                    logger.debug(
                                        f"Skipping substitution: size mismatch "
                                        f"({new_size} vs {orig_size}, strict={self.strict_size})"
                                    )
                        except Exception as e:
                            logger.error(f"Failed to substitute at 0x{addr:x}: {e}")

            if func_mutations > 0:
                functions_mutated += 1

        logger.info(
            f"Instruction substitution complete: {mutations_applied} substitutions "
            f"in {functions_mutated} functions ({candidates_found} candidates found)"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "candidates_found": candidates_found,
            "total_functions": len(functions),
            "force_different": self.force_different,
            "strict_size": self.strict_size,
        }

    def _apply_arm64_mov_substitution(self, binary: Binary) -> dict[str, Any]:
        """Apply safe ARM64 mov-immediate substitutions."""
        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            func_mutations = 0
            for insn in instructions:
                disasm = insn.get("disasm", "").lower().replace("#", "")
                addr = insn.get("addr", 0)
                size = insn.get("size", 0)

                if not disasm.startswith("mov "):
                    continue

                parts = [p.strip() for p in disasm.split(",")]
                if len(parts) != 2:
                    continue

                dst = parts[0].split()[-1]
                imm = parts[1]

                if not (dst.startswith("w") or dst.startswith("x")):
                    continue

                if not imm.startswith("0x") and not imm.isdigit():
                    continue

                try:
                    imm_val = int(imm, 16) if imm.startswith("0x") else int(imm)
                except ValueError:
                    continue

                if imm_val < 0 or imm_val > 0xFFFF:
                    continue

                new_insn = f"movz {dst}, {hex(imm_val)}"
                new_bytes = binary.assemble(new_insn, func["addr"])

                if not new_bytes or len(new_bytes) != size:
                    continue

                if binary.write_bytes(addr, new_bytes):
                    func_mutations += 1
                    mutations_applied += 1

                    if func_mutations >= self.max_substitutions:
                        break

            if func_mutations > 0:
                functions_mutated += 1

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_functions": len(functions),
        }
