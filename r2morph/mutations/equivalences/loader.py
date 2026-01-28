"""
Loader for equivalence rule YAML files.

Loads architecture-specific equivalence rules and expands register templates
into concrete instruction patterns.
"""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def load_equivalence_rules(arch: str = "x86") -> list[list[str]]:
    """
    Load equivalence rules for the specified architecture.

    Args:
        arch: Architecture name (x86, arm, etc.)

    Returns:
        List of equivalence groups, where each group is a list of
        equivalent instruction patterns.
    """
    rules_dir = Path(__file__).parent
    rules_file = rules_dir / f"{arch}_rules.yaml"

    if not rules_file.exists():
        logger.warning(f"No equivalence rules file found for architecture: {arch}")
        return []

    try:
        with open(rules_file) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML file {rules_file}: {e}")
        return []

    if not data:
        logger.warning(f"Empty or invalid rules file: {rules_file}")
        return []

    groups = []
    for group in data.get("equivalence_groups", []):
        expanded_groups = _expand_group(group)
        groups.extend(expanded_groups)

    logger.debug(
        f"Loaded {len(groups)} equivalence groups for {arch} "
        f"from {rules_file.name}"
    )

    return groups


def _expand_group(group: dict) -> list[list[str]]:
    """
    Expand a group definition into concrete equivalence groups.

    If the group has registers defined, it expands the {reg} template
    for each register. Otherwise, returns the instructions as-is.

    Args:
        group: Group definition dictionary from YAML

    Returns:
        List of expanded equivalence groups
    """
    instructions = group.get("instructions", [])
    registers = group.get("registers", [])
    register_mappings = group.get("register_mappings", {})

    if not instructions:
        return []

    # If no registers defined, return as a single group
    if not registers:
        return [instructions]

    # Expand templates for each register
    expanded_groups = []
    for reg in registers:
        expanded_instructions = []
        for inst in instructions:
            expanded = _expand_template(inst, reg, register_mappings.get(reg, {}))
            expanded_instructions.append(expanded)
        expanded_groups.append(expanded_instructions)

    return expanded_groups


def _expand_template(instruction: str, register: str, mappings: dict) -> str:
    """
    Expand a single instruction template with register values.

    Args:
        instruction: Instruction template with {reg} placeholders
        register: Register name to substitute for {reg}
        mappings: Additional register mappings (e.g., {reg32: "eax"})

    Returns:
        Expanded instruction string
    """
    # Replace the main register placeholder
    result = instruction.replace("{reg}", register)

    # Replace any additional mapped placeholders
    for placeholder, value in mappings.items():
        result = result.replace("{" + placeholder + "}", value)

    return result


def get_available_architectures() -> list[str]:
    """
    Get list of available architecture rule files.

    Returns:
        List of architecture names that have rule files.
    """
    rules_dir = Path(__file__).parent
    architectures = []

    for rules_file in rules_dir.glob("*_rules.yaml"):
        arch_name = rules_file.stem.replace("_rules", "")
        architectures.append(arch_name)

    return sorted(architectures)
