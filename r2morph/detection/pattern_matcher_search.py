"""Reusable binary search helpers for pattern matching."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def find_patterns(binary: Any, patterns: list[bytes]) -> dict[bytes, list[int]]:
    """
    Search for arbitrary byte patterns in the binary.

    Args:
        binary: Binary object with an attached r2 handle.
        patterns: List of byte patterns to search for.

    Returns:
        Dictionary mapping patterns to list of addresses found.
    """
    results: dict[bytes, list[int]] = {}

    assert binary.r2 is not None
    try:
        for pattern in patterns:
            cmd = f"/x {pattern.hex()}"
            matches = binary.r2.cmd(cmd)

            if matches and matches.strip():
                addresses: list[int] = []
                for line in matches.strip().split("\n"):
                    parts = line.split()
                    if parts:
                        try:
                            addr = int(parts[0], 16)
                            addresses.append(addr)
                        except (ValueError, IndexError):
                            continue

                if addresses:
                    results[pattern] = addresses

    except Exception as e:
        logger.error(f"Pattern search failed: {e}")

    return results


def search_strings(binary: Any, search_terms: list[str], case_sensitive: bool = False) -> dict[str, bool]:
    """
    Search for specific strings in the binary.

    Args:
        binary: Binary object with an attached r2 handle.
        search_terms: List of strings to search for.
        case_sensitive: Whether search should be case-sensitive.

    Returns:
        Dictionary mapping search terms to whether they were found.
    """
    results: dict[str, bool] = {}

    assert binary.r2 is not None
    try:
        strings_output = binary.r2.cmd("izz")

        if not case_sensitive:
            strings_output = strings_output.lower()

        for term in search_terms:
            search_term = term if case_sensitive else term.lower()
            results[term] = search_term in strings_output

    except Exception as e:
        logger.error(f"String search failed: {e}")
        for term in search_terms:
            results[term] = False

    return results
