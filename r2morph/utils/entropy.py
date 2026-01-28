"""
Entropy calculation utilities.
"""

import math
from collections import Counter
from pathlib import Path


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.

    Args:
        data: Byte data to analyze

    Returns:
        Entropy value (0-8 for byte data)
    """
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counter.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)

    return entropy


def calculate_file_entropy(path: Path) -> float:
    """
    Calculate Shannon entropy of entire file.

    Args:
        path: File path

    Returns:
        Entropy value (0-8)
    """
    with open(path, "rb") as f:
        data = f.read()

    return calculate_entropy(data)
