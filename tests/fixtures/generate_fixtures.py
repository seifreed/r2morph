#!/usr/bin/env python3
"""
Generate test fixtures for real binary tests.

Creates simple ELF binaries for testing mutations.
"""

import os
import subprocess
import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent

# Simple C programs for test fixtures
SIMPLE_PROGRAM = """
#include <stdio.h>
int main() {
    printf("Hello, World!\\n");
    return 0;
}
"""

CONDITIONAL_PROGRAM = """
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) {
        printf("Arg: %s\\n", argv[1]);
    } else {
        printf("No args\\n");
    }
    return 0;
}
"""

LOOP_PROGRAM = """
#include <stdio.h>
int main() {
    for (int i = 0; i < 10; i++) {
        printf("%d\\n", i);
    }
    return 0;
}
"""

CALCULATOR_PROGRAM = """
#include <stdio.h>
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }
int main() {
    printf("1 + 2 = %d\\n", add(1, 2));
    printf("3 - 1 = %d\\n", sub(3, 1));
    printf("2 * 3 = %d\\n", mul(2, 3));
    return 0;
}
"""

STRING_PROGRAM = """
#include <stdio.h>
#include <string.h>
int main() {
    char msg[] = "Test string for obfuscation";
    printf("%s\\n", msg);
    printf("Length: %zu\\n", strlen(msg));
    return 0;
}
"""

RECURSIVE_PROGRAM = """
#include <stdio.h>
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
int main() {
    for (int i = 0; i < 10; i++) {
        printf("factorial(%d) = %d\\n", i, factorial(i));
    }
    return 0;
}
"""


def compile_program(source: str, output: Path, extra_flags: list = None):
    """Compile a C program to an executable."""
    extra_flags = extra_flags or []

    # Write source to temp file
    source_file = output.with_suffix(".c")
    source_file.write_text(source)

    # Compile
    cmd = [
        "gcc",
        "-o",
        str(output),
        str(source_file),
        "-no-pie",  # For predictable addresses
        *extra_flags,
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        # Make executable
        output.chmod(0o755)
        # Remove source
        source_file.unlink(missing_ok=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile {output}: {e.stderr.decode()}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("gcc not found, skipping compilation", file=sys.stderr)
        return False


def generate_fixtures():
    """Generate all test fixtures."""
    programs = {
        "simple": SIMPLE_PROGRAM,
        "conditional": CONDITIONAL_PROGRAM,
        "loop": LOOP_PROGRAM,
        "calculator": CALCULATOR_PROGRAM,
        "string": STRING_PROGRAM,
        "recursive": RECURSIVE_PROGRAM,
    }

    elf_dir = FIXTURES_DIR / "elf_x86_64"
    elf_dir.mkdir(parents=True, exist_ok=True)

    generated = []

    for name, source in programs.items():
        output = elf_dir / name
        if compile_program(source, output, ["-O0"]):
            generated.append(output)
            print(f"Generated: {output}")

    # Generate with different optimization levels
    for opt_level in ["O0", "O1", "O2", "O3"]:
        optimized_simple = elf_dir / f"simple_{opt_level.lower()}"
        if compile_program(SIMPLE_PROGRAM, optimized_simple, [f"-{opt_level}"]):
            generated.append(optimized_simple)
            print(f"Generated: {optimized_simple}")

    return generated


if __name__ == "__main__":
    print("Generating test fixtures...")
    fixtures = generate_fixtures()
    print(f"\nGenerated {len(fixtures)} fixtures")

    # List what we have
    print("\nAvailable fixtures:")
    for f in sorted(FIXTURES_DIR.rglob("*")):
        if f.is_file() and not f.suffix in [".c", ".o", ".obj", ".S"]:
            print(f"  - {f.relative_to(FIXTURES_DIR)}")
