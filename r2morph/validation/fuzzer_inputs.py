"""Input generation helpers for the legacy validation fuzzer."""

from __future__ import annotations

import random
import string


def generate_fuzz_input(input_type: str) -> str:
    """Generate fuzz input based on a requested input type."""
    length = random.randint(0, 1000)

    if input_type == "random":
        return "".join(chr(random.randint(0, 255)) for _ in range(length))

    if input_type == "ascii":
        return "".join(random.choice(string.printable) for _ in range(length))

    if input_type == "binary":
        return bytes(random.randint(0, 255) for _ in range(length)).decode(errors="replace")

    if input_type == "structured":
        templates = [
            lambda: str(random.randint(-1000000, 1000000)),
            lambda: str(random.random()),
            lambda: "".join(random.choices(string.ascii_letters, k=random.randint(1, 100))),
            lambda: " ".join(str(random.randint(0, 100)) for _ in range(random.randint(1, 10))),
        ]
        return random.choice(templates)()

    return ""
