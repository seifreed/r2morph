"""Input generation helpers for the mutation fuzzer."""

from __future__ import annotations

import json
import random
import tempfile

from r2morph.validation.mutation_fuzzer_types import FuzzConfig, FuzzTestCase


def generate_random_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate random binary input."""
    size = size_hint or random.randint(config.min_input_size, config.max_input_size)
    return bytes(random.randint(0, 255) for _ in range(size))


def generate_ascii_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate printable ASCII input."""
    import string

    size = size_hint or random.randint(config.min_input_size, min(config.max_input_size, 1024))
    chars = string.printable
    return "".join(random.choice(chars) for _ in range(size)).encode()


def generate_binary_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate structured binary input."""
    size = size_hint or random.randint(config.min_input_size, min(config.max_input_size, 512))

    result = bytearray()

    while len(result) < size:
        pattern_type = random.choice(["zeros", "ones", "random", "sequence"])

        if pattern_type == "zeros":
            chunk_size = random.randint(1, min(64, size - len(result)))
            result.extend(b"\x00" * chunk_size)
        elif pattern_type == "ones":
            chunk_size = random.randint(1, min(64, size - len(result)))
            result.extend(b"\xff" * chunk_size)
        elif pattern_type == "sequence":
            chunk_size = random.randint(1, min(64, size - len(result)))
            result.extend(bytes(range(chunk_size)))
        else:
            chunk_size = min(64, size - len(result))
            result.extend(bytes(random.randint(0, 255) for _ in range(chunk_size)))

    return bytes(result[:size])


def generate_structured_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate structured input (JSON-like)."""
    structures = [
        lambda: json.dumps({"value": random.randint(0, 1000000)}),
        lambda: json.dumps({"values": [random.randint(0, 100) for _ in range(random.randint(1, 10))]}),
        lambda: json.dumps({"nested": {"a": random.randint(0, 10), "b": random.choice(["x", "y", "z"])}}),
        lambda: json.dumps([random.choice(["a", "b", "c"]) for _ in range(random.randint(1, 5))]),
        lambda: str(random.randint(-1000000, 1000000)),
        lambda: " ".join(str(random.randint(0, 100)) for _ in range(random.randint(1, 10))),
        lambda: ",".join(str(random.random()) for _ in range(random.randint(1, 5))),
    ]

    return random.choice(structures)().encode()


def generate_edge_case_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate edge case inputs."""
    edge_cases = [
        b"",
        b"\x00",
        b"\xff",
        b"\x00" * 1000,
        b"\xff" * 1000,
        b"a" * 10000,
        b"\n" * 100,
        b"\r\n" * 50,
        b"\x00\xff" * 500,
        bytes(range(256)),
        bytes(range(255, -1, -1)),
    ]

    return random.choice(edge_cases)


def generate_format_string_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate format string inputs."""
    format_patterns = [
        "%s" * random.randint(1, 10),
        "%d" * random.randint(1, 10),
        "%x" * random.randint(1, 10),
        "%n" * random.randint(1, 5),
        f"%{random.randint(1, 1000)}" + "s",
        "AAAA%08x.%08x.%08x.%08x",
        "%p" * random.randint(1, 5),
    ]

    return random.choice(format_patterns).encode()


def generate_path_like_input(config: FuzzConfig, size_hint: int) -> bytes:
    """Generate path-like inputs."""
    import string

    path_chars = string.ascii_letters + string.digits + "/\\._-"

    paths = [
        "/".join(
            "".join(random.choice(path_chars) for _ in range(random.randint(1, 10)))
            for _ in range(random.randint(1, 5))
        ),
        "\\".join(
            "".join(random.choice(path_chars) for _ in range(random.randint(1, 10)))
            for _ in range(random.randint(1, 5))
        ),
        "C:\\" + "".join(random.choice(path_chars) for _ in range(random.randint(5, 50))),
        tempfile.gettempdir() + "/" + "".join(random.choice(path_chars) for _ in range(random.randint(5, 30))),
        "." * random.randint(1, 10)
        + "/"
        + "".join(random.choice(path_chars) for _ in range(random.randint(5, 20))),
        ".." * random.randint(1, 20),
    ]

    return random.choice(paths).encode()


def generate_test_case(config: FuzzConfig, index: int) -> FuzzTestCase:
    """Generate a fuzz test case."""
    generators = {
        "random": generate_random_input,
        "ascii": generate_ascii_input,
        "binary": generate_binary_input,
        "structured": generate_structured_input,
        "edge_case": generate_edge_case_input,
        "format_string": generate_format_string_input,
        "path_like": generate_path_like_input,
    }

    input_type = random.choice(list(generators.keys()))
    size_hint = random.randint(config.min_input_size, config.max_input_size)
    input_data = generators[input_type](config, size_hint)

    num_args = random.randint(0, 5)
    args = [
        "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(1, 20)))
        for _ in range(num_args)
    ]

    env = {}
    if random.random() < 0.3:
        env["FUZZ_ENV"] = "test"

    return FuzzTestCase(
        test_id=f"fuzz_{index:04d}",
        input_data=input_data,
        input_type=input_type,
        args=args,
        env=env,
        description=f"Fuzz test case {index} ({input_type})",
    )
