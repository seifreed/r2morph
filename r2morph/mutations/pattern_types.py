"""
Core data types for instruction pattern matching and mutation.

Defines the value objects (``Instruction``, ``BasicBlock``, ``MatchResult``)
and the matcher/generator callable aliases shared by the pattern rules,
generators and the pattern pool registry. This module is a leaf: it depends
only on the standard library so rules and generators can import it without a
cycle through the pool registry.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Instruction:
    """Pattern-style Instruction class for pattern matching."""

    address: int = 0
    mnemonic: str = ""
    operand_1: str = ""
    operand_2: str = ""
    operand_3: str = ""
    operand_str: str = ""
    bytes: str = ""
    type: str = ""
    opcode: str = ""
    mutated: bool = False


@dataclass
class BasicBlock:
    """Pattern-style BasicBlock for pattern matching."""

    address: int = 0
    label: str = ""
    instructions: list[Instruction] = field(default_factory=list)
    jump: int | None = None
    fail: int | None = None


@dataclass
class MatchResult:
    index: int
    length: int
    operands: list[Any] = field(default_factory=list)


MatchRule = Callable[[list[Instruction]], list[MatchResult]]
Generator = Callable[[list[Any], str], list[Instruction]]
