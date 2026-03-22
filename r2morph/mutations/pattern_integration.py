"""
Integration module connecting pattern_pool and junk_generator
with existing mutation passes.

Provides unified interface for:
- Pattern-based instruction substitution
- Junk code injection integration
- Semantic preservation validation
"""

from typing import Any
from dataclasses import dataclass

from r2morph.mutations.pattern_pool import (
    get_pattern_pools,
)
from r2morph.mutations.junk_generator import JunkGenerator, create_junk_generator


@dataclass
class PatternMatchConfig:
    """Configuration for pattern matching integration."""

    use_pattern_pools: bool = True
    use_junk_generator: bool = True
    pattern_probability: float = 0.7
    junk_probability: float = 0.3
    junk_min_size: int = 16
    junk_max_size: int = 64
    os_type: str = "linux"


class PatternMatchIntegration:
    """
    Integrates pattern_pool and junk_generator with mutation passes.

    Usage:
        integration = PatternMatchIntegration()
        integration.apply_patterns(basic_blocks, os_type="linux")
    """

    def __init__(self, config: PatternMatchConfig | None = None):
        self.config = config or PatternMatchConfig()
        self._junk_generator: JunkGenerator | None = None

    def get_junk_generator(self, os_type: str = "linux") -> JunkGenerator:
        """Get or create junk generator."""
        if self._junk_generator is None or self._junk_generator.os_type != os_type:
            self._junk_generator = create_junk_generator(os_type)
        return self._junk_generator

    def apply_patterns_to_block(
        self,
        block_instructions: list[Any],
        os_type: str = "linux",
        verbose: bool = False,
    ) -> tuple[list[Any], list[dict[str, Any]]]:
        """
        Apply all registered pattern pools to a block of instructions.

        Args:
            block_instructions: List of instruction dicts or objects
            os_type: Operating system type for constants
            verbose: Print mutation details

        Returns:
            Tuple of (mutated_instructions, mutation_log)
        """
        from r2morph.mutations.pattern_pool import Instruction

        converted = []
        for ins in block_instructions:
            if isinstance(ins, dict):
                converted_ins = Instruction(
                    address=ins.get("addr", 0) if isinstance(ins.get("addr"), int) else 0,
                    mnemonic=ins.get("mnemonic", ""),
                    operand_1=self._extract_operand(ins, 0),
                    operand_2=self._extract_operand(ins, 1),
                    operand_3=self._extract_operand(ins, 2),
                    operand_str=ins.get("disasm", "").split(maxsplit=1)[1] if " " in ins.get("disasm", "") else "",
                    bytes=ins.get("bytes", ""),
                    type=ins.get("type", ""),
                    opcode=str(ins.get("opcode", ins.get("disasm", ""))),
                    mutated=getattr(ins, "mutated", False),
                )
            else:
                converted_ins = ins
            converted.append(converted_ins)

        pools = get_pattern_pools()
        mutation_log = []

        for pool in pools:
            for rule in pool.match_rules:
                matches = rule(converted)

                for match in reversed(matches):
                    import random

                    if random.randint(0, 100) <= pool.mutation_probability:
                        old_insns = converted[match.index : match.index + match.length]

                        import random as rand

                        gen_list, weights = zip(*pool.generators)
                        chosen_gen = rand.choices(gen_list, weights=weights, k=1)[0]

                        new_insns = chosen_gen(match.operands, os_type)

                        mutation_log.append(
                            {
                                "pool": pool.name,
                                "address": old_insns[0].address if old_insns else 0,
                                "old": [ins.mnemonic for ins in old_insns],
                                "new": [ins.mnemonic for ins in new_insns],
                            }
                        )

                        if verbose:
                            print(f"[{pool.name}] Mutation at 0x{old_insns[0].address:x if old_insns else 0:x}")
                            print(f"  old: {' -> '.join([ins.mnemonic for ins in old_insns])}")
                            print(f"  new: {' -> '.join([ins.mnemonic for ins in new_insns])}")

                        converted[match.index : match.index + match.length] = new_insns

        return converted, mutation_log

    def _extract_operand(self, ins: dict[str, Any], idx: int) -> str:
        """Extract operand at index from instruction dict."""
        disasm = str(ins.get("disasm", ""))
        parts = disasm.split(maxsplit=1)
        if len(parts) < 2:
            return ""
        operands = parts[1].split(",")
        if idx < len(operands):
            return str(operands[idx].strip())
        return ""

    def generate_junk_code(
        self,
        size: int | None = None,
        os_type: str = "linux",
    ) -> bytes:
        """
        Generate semantically neutral junk code.

        Args:
            size: Target size in bytes (randomized if None)
            os_type: Operating system for constants

        Returns:
            Bytes of assembled junk code
        """
        generator = self.get_junk_generator(os_type)

        if size is None:
            import random

            size = random.randint(self.config.junk_min_size, self.config.junk_max_size)

        return generator.generate_junk_code(size)

    def generate_junk_before_mutation(
        self,
        reg: str,
        size: int | None = None,
        os_type: str = "linux",
    ) -> tuple[bytes, bytes, bytes]:
        """
        Generate junk code with register preservation.

        Args:
            reg: Register to preserve
            size: Target size in bytes
            os_type: Operating system type

        Returns:
            Tuple of (store_code, junk_code, restore_code)
        """
        generator = self.get_junk_generator(os_type)

        if size is None:
            import random

            size = random.randint(self.config.junk_min_size, self.config.junk_max_size)

        store_code, store_size = generator.store_register(reg)
        junk_code = generator.generate_junk_code(size - store_size)
        restore_code = generator.restore_register()

        return store_code, junk_code, restore_code


def create_pattern_integration(
    use_patterns: bool = True,
    use_junk: bool = True,
    os_type: str = "linux",
    **kwargs: Any,
) -> PatternMatchIntegration:
    """
    Factory function to create a configured PatternMatchIntegration.

    Args:
        use_patterns: Enable pattern pool mutations
        use_junk: Enable junk code generation
        os_type: Default OS type
        **kwargs: Additional config options

    Returns:
        Configured PatternMatchIntegration instance
    """
    config = PatternMatchConfig(
        use_pattern_pools=use_patterns,
        use_junk_generator=use_junk,
        os_type=os_type,
        **kwargs,
    )
    return PatternMatchIntegration(config)


__all__ = [
    "PatternMatchIntegration",
    "PatternMatchConfig",
    "create_pattern_integration",
]
