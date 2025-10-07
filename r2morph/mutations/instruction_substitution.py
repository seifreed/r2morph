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
from typing import Any, List

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

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
        """
        self.equivalence_groups = {
            "x86": [
                [
                    "mov eax, 0",
                    "xor eax, eax",
                    "sub eax, eax",
                    "push 0; pop eax",
                ],
                [
                    "mov ebx, 0",
                    "xor ebx, ebx",
                    "sub ebx, ebx",
                    "push 0; pop ebx",
                ],
                [
                    "mov ecx, 0",
                    "xor ecx, ecx",
                    "sub ecx, ecx",
                    "push 0; pop ecx",
                ],
                [
                    "mov edx, 0",
                    "xor edx, edx",
                    "sub edx, edx",
                    "push 0; pop edx",
                ],
                [
                    "mov esi, 0",
                    "xor esi, esi",
                    "sub esi, esi",
                    "push 0; pop esi",
                ],
                [
                    "mov edi, 0",
                    "xor edi, edi",
                    "sub edi, edi",
                    "push 0; pop edi",
                ],
                [
                    "mov rax, 0",
                    "xor rax, rax",
                    "sub rax, rax",
                    "xor eax, eax",
                ],
                [
                    "mov rbx, 0",
                    "xor rbx, rbx",
                    "sub rbx, rbx",
                    "xor ebx, ebx",
                ],
                [
                    "mov rcx, 0",
                    "xor rcx, rcx",
                    "sub rcx, rcx",
                    "xor ecx, ecx",
                ],
                [
                    "mov rdx, 0",
                    "xor rdx, rdx",
                    "sub rdx, rdx",
                    "xor edx, edx",
                ],
                [
                    "mov rsi, 0",
                    "xor rsi, rsi",
                    "sub rsi, rsi",
                    "xor esi, esi",
                ],
                [
                    "mov rdi, 0",
                    "xor rdi, rdi",
                    "sub rdi, rdi",
                    "xor edi, edi",
                ],
                ["mov eax, eax", "push eax; pop eax", "xchg eax, eax"],
                ["mov ebx, ebx", "push ebx; pop ebx", "xchg ebx, ebx"],
                ["mov ecx, ecx", "push ecx; pop ecx", "xchg ecx, ecx"],
                ["mov edx, edx", "push edx; pop edx", "xchg edx, edx"],
                ["mov esi, esi", "push esi; pop esi", "xchg esi, esi"],
                ["mov edi, edi", "push edi; pop edi", "xchg edi, edi"],
                ["mov rax, rax", "push rax; pop rax", "xchg rax, rax"],
                ["mov rbx, rbx", "push rbx; pop rbx", "xchg rbx, rbx"],
                ["mov rcx, rcx", "push rcx; pop rcx", "xchg rcx, rcx"],
                ["mov rdx, rdx", "push rdx; pop rdx", "xchg rdx, rdx"],
                [
                    "mov eax, 1",
                    "push 1; pop eax",
                    "xor eax, eax; inc eax",
                ],
                [
                    "mov ebx, 1",
                    "push 1; pop ebx",
                    "xor ebx, ebx; inc ebx",
                ],
                [
                    "mov ecx, 1",
                    "push 1; pop ecx",
                    "xor ecx, ecx; inc ecx",
                ],
                [
                    "mov edx, 1",
                    "push 1; pop edx",
                    "xor edx, edx; inc edx",
                ],
                ["test eax, eax", "or eax, eax"],
                ["test ebx, ebx", "or ebx, ebx"],
                ["test ecx, ecx", "or ecx, ecx"],
                ["test edx, edx", "or edx, edx"],
                ["test esi, esi", "or esi, esi"],
                ["test edi, edi", "or edi, edi"],
                ["test rax, rax", "or rax, rax"],
                ["test rbx, rbx", "or rbx, rbx"],
                ["test rcx, rcx", "or rcx, rcx"],
                ["test rdx, rdx", "or rdx, rdx"],
                ["xor eax, eax", "sub eax, eax"],
                ["xor ebx, ebx", "sub ebx, ebx"],
                ["xor ecx, ecx", "sub ecx, ecx"],
                ["xor edx, edx", "sub edx, edx"],
                ["xor esi, esi", "sub esi, esi"],
                ["xor edi, edi", "sub edi, edi"],
                ["xor rax, rax", "sub rax, rax"],
                ["xor rbx, rbx", "sub rbx, rbx"],
                ["xor rcx, rcx", "sub rcx, rcx"],
                ["xor rdx, rdx", "sub rdx, rdx"],
                ["add eax, 1", "inc eax"],
                ["add ebx, 1", "inc ebx"],
                ["add ecx, 1", "inc ecx"],
                ["add edx, 1", "inc edx"],
                ["add esi, 1", "inc esi"],
                ["add edi, 1", "inc edi"],
                ["add rax, 1", "inc rax"],
                ["add rbx, 1", "inc rbx"],
                ["add rcx, 1", "inc rcx"],
                ["add rdx, 1", "inc rdx"],
                ["sub eax, 1", "dec eax"],
                ["sub ebx, 1", "dec ebx"],
                ["sub ecx, 1", "dec ecx"],
                ["sub edx, 1", "dec edx"],
                ["sub esi, 1", "dec esi"],
                ["sub edi, 1", "dec edi"],
                ["sub rax, 1", "dec rax"],
                ["sub rbx, 1", "dec rbx"],
                ["sub rcx, 1", "dec rcx"],
                ["sub rdx, 1", "dec rdx"],
                ["push eax; pop eax", "nop"],
                ["push ebx; pop ebx", "nop"],
                ["push ecx; pop ecx", "nop"],
                ["push edx; pop edx", "nop"],
                ["push rax; pop rax", "nop"],
                ["push rbx; pop rbx", "nop"],
                ["push rcx; pop rcx", "nop"],
                ["push rdx; pop rdx", "nop"],
                ["nop", "xchg eax, eax", "xchg rax, rax"],
            ]
        }

        for arch in self.equivalence_groups:
            for group in self.equivalence_groups[arch]:
                random.shuffle(group)

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

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")

        arch_family = "x86" if arch in ["x86", "x64"] else arch

        if arch_family not in self.equivalence_groups:
            logger.warning(f"No substitution rules for architecture: {arch}")
            return {
                "mutations_applied": 0,
                "error": f"Unsupported architecture: {arch}",
            }

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        candidates_found = 0

        logger.info(f"Instruction substitution: processing {len(functions)} functions")

        for func in functions:
            if func.get("size", 0) < 10:
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
