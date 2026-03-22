"""
Cross-validation tests between different tools.

Validates that r2morph mutations produce results consistent with
other binary analysis tools (radare2, objdump, readelf, etc.).
"""

import os
import platform
import subprocess
import tempfile
from pathlib import Path

import pytest

from r2morph.core.engine import MorphEngine
from r2morph.core.config import EngineConfig


pytestmark = pytest.mark.skipif(
    os.environ.get("SKIP_CROSS_VALIDATION_TESTS") == "1", reason="Cross-validation tests disabled"
)


def has_tool(tool_name: str) -> bool:
    """Check if a tool is available."""
    return shutil.which(tool_name) is not None


def run_tool(tool_name: str, args: list, timeout: int = 10) -> tuple:
    """Run a tool and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            [tool_name] + args,
            capture_output=True,
            timeout=timeout,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, b"", b""


import shutil


class TestRadare2CrossValidation:
    """Cross-validation with radare2."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def test_binary(self, temp_dir):
        """Create test binary."""
        source = """
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main() {
    printf("%d\\n", add(2, 3));
    return 0;
}
"""
        source_file = temp_dir / "test.c"
        source_file.write_text(source)

        binary_file = temp_dir / "test"

        try:
            subprocess.run(
                ["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True
            )
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    @pytest.mark.skipif(not has_tool("r2"), reason="radare2 not available")
    def test_r2_function_count(self, test_binary, temp_dir):
        """Verify function count consistency with radare2."""
        output = temp_dir / "test_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(test_binary).analyze()
            original_functions = len(list(engine.binary.functions))

            engine.add_mutation("nop")
            result = engine.run(validation_mode="structural")

            if result.successful:
                engine.save(output)

        # Use radare2 to count functions in original
        success, stdout, _ = run_tool("r2", ["-q", "-c", "afl", str(test_binary)])
        if success and stdout:
            r2_func_count = len([l for l in stdout.decode().strip().split("\n") if l])

            # Use radare2 to count functions in mutated
            if output.exists():
                success2, stdout2, _ = run_tool("r2", ["-q", "-c", "afl", str(output)])
                if success2 and stdout2:
                    r2_mutated_count = len([l for l in stdout2.decode().strip().split("\n") if l])

                    # Function count should be preserved
                    assert r2_func_count == r2_mutated_count, (
                        f"Function count mismatch: original={r2_func_count}, mutated={r2_mutated_count}"
                    )

    @pytest.mark.skipif(not has_tool("r2"), reason="radare2 not available")
    def test_r2_section_preservation(self, test_binary, temp_dir):
        """Verify sections are preserved after mutation."""
        output = temp_dir / "test_mutated"
        config = EngineConfig.create_default()

        # Get sections with radare2
        success, stdout, _ = run_tool("r2", ["-q", "-c", "iS", str(test_binary)])

        if success and stdout:
            original_sections = [l for l in stdout.decode().strip().split("\n") if l.strip()]

            with MorphEngine(config=config) as engine:
                engine.load_binary(test_binary).analyze()
                engine.add_mutation("nop")
                result = engine.run(validation_mode="structural")

                if result.successful:
                    engine.save(output)

            if output.exists():
                success2, stdout2, _ = run_tool("r2", ["-q", "-c", "iS", str(output)])
                if success2 and stdout2:
                    mutated_sections = [l for l in stdout2.decode().strip().split("\n") if l.strip()]

                    # Section count should be preserved
                    assert len(original_sections) == len(mutated_sections), (
                        f"Section count mismatch: {len(original_sections)} vs {len(mutated_sections)}"
                    )


class TestObjdumpCrossValidation:
    """Cross-validation with objdump."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def test_binary(self, temp_dir):
        source = """
#include <stdio.h>
int main() { printf("test"); return 0; }
"""
        source_file = temp_dir / "test.c"
        source_file.write_text(source)
        binary_file = temp_dir / "test"

        try:
            subprocess.run(
                ["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True
            )
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    @pytest.mark.skipif(not has_tool("objdump"), reason="objdump not available")
    def test_objdump_disassembly_count(self, test_binary, temp_dir):
        """Verify instruction count consistency with objdump."""
        output = temp_dir / "test_mutated"

        # Count instructions with objdump in original
        success, stdout, _ = run_tool("objdump", ["-d", str(test_binary)])

        if success and stdout:
            original_lines = len([l for l in stdout.decode().split("\n") if l.strip()])

            config = EngineConfig.create_default()
            with MorphEngine(config=config) as engine:
                engine.load_binary(test_binary).analyze()
                engine.add_mutation("nop")
                result = engine.run(validation_mode="structural")

                if result.successful:
                    engine.save(output)

            if output.exists():
                success2, stdout2, _ = run_tool("objdump", ["-d", str(output)])
                if success2 and stdout2:
                    mutated_lines = len([l for l in stdout2.decode().split("\n") if l.strip()])

                    # Mutation should not destroy instructions
                    # (may have more due to NOP insertion)
                    assert mutated_lines >= original_lines * 0.9, (
                        f"Too many instructions lost: {original_lines} -> {mutated_lines}"
                    )


class TestReadelfCrossValidation:
    """Cross-validation with readelf."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def test_binary(self, temp_dir):
        source = """
#include <stdio.h>
int main() { return 42; }
"""
        source_file = temp_dir / "test.c"
        source_file.write_text(source)
        binary_file = temp_dir / "test"

        try:
            subprocess.run(
                ["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True
            )
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    @pytest.mark.skipif(not has_tool("readelf"), reason="readelf not available")
    def test_readelf_headers_preserved(self, test_binary, temp_dir):
        """Verify ELF headers are preserved after mutation."""
        output = temp_dir / "test_mutated"

        # Get headers with readelf
        success, stdout, _ = run_tool("readelf", ["-h", str(test_binary)])

        if success and stdout:
            # Extract key values
            header_lines = stdout.decode().strip().split("\n")
            entry_point = None
            for line in header_lines:
                if "Entry point" in line:
                    entry_point = line
                    break

            config = EngineConfig.create_default()
            with MorphEngine(config=config) as engine:
                engine.load_binary(test_binary).analyze()
                engine.add_mutation("nop")
                result = engine.run(validation_mode="structural")

                if result.successful:
                    engine.save(output)

            if output.exists() and entry_point:
                success2, stdout2, _ = run_tool("readelf", ["-h", str(output)])
                if success2 and stdout2:
                    mutated_headers = stdout2.decode().strip()

                    # Entry point should be the same
                    for line in mutated_headers.split("\n"):
                        if "Entry point" in line:
                            mutated_entry = line
                            assert entry_point == mutated_entry, (
                                f"Entry point changed: {entry_point} vs {mutated_entry}"
                            )
                            break

    @pytest.mark.skipif(not has_tool("readelf"), reason="readelf not available")
    def test_readelf_symbols_preserved(self, test_binary, temp_dir):
        """Verify symbols are preserved after mutation."""
        output = temp_dir / "test_mutated"

        # Get symbols with readelf
        success, stdout, _ = run_tool("readelf", ["-s", str(test_binary)])

        if success and stdout:
            original_symbols = set()
            for line in stdout.decode().strip().split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 8:
                        original_symbols.add(parts[-1])  # Symbol name

            config = EngineConfig.create_default()
            with MorphEngine(config=config) as engine:
                engine.load_binary(test_binary).analyze()
                engine.add_mutation("nop")
                result = engine.run(validation_mode="structural")

                if result.successful:
                    engine.save(output)

            if output.exists():
                success2, stdout2, _ = run_tool("readelf", ["-s", str(output)])
                if success2 and stdout2:
                    mutated_symbols = set()
                    for line in stdout2.decode().strip().split("\n"):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 8:
                                mutated_symbols.add(parts[-1])

                    # All original symbols should still exist
                    for sym in original_symbols:
                        if sym and not sym.startswith("_"):  # Skip internal symbols
                            assert sym in mutated_symbols, f"Symbol {sym} lost after mutation"


class TestFileCrossValidation:
    """Cross-validation using file command."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def test_binary(self, temp_dir):
        source = "int main() { return 0; }"
        source_file = temp_dir / "test.c"
        source_file.write_text(source)
        binary_file = temp_dir / "test"

        try:
            subprocess.run(
                ["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True
            )
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    @pytest.mark.skipif(not has_tool("file"), reason="file command not available")
    def test_file_type_preserved(self, test_binary, temp_dir):
        """Verify file type is preserved after mutation."""
        output = temp_dir / "test_mutated"

        # Get file type
        success, stdout, _ = run_tool("file", [str(test_binary)])

        if success and stdout:
            original_type = stdout.decode().strip()

            config = EngineConfig.create_default()
            with MorphEngine(config=config) as engine:
                engine.load_binary(test_binary).analyze()
                engine.add_mutation("nop")
                result = engine.run(validation_mode="structural")

                if result.successful:
                    engine.save(output)

            if output.exists():
                success2, stdout2, _ = run_tool("file", [str(output)])
                if success2 and stdout2:
                    mutated_type = stdout2.decode().strip()

                    # Key file type components should be preserved
                    if "ELF" in original_type:
                        assert "ELF" in mutated_type, "Lost ELF type"
                    if platform.system() != "Windows":
                        if "executable" in original_type.lower():
                            assert "executable" in mutated_type.lower(), "Lost executable type"
                        if "64-bit" in original_type:
                            assert "64-bit" in mutated_type, "Changed architecture"


class TestStringsCrossValidation:
    """Cross-validation using strings command."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def string_binary(self, temp_dir):
        source = """
#include <stdio.h>
const char *message = "Hello, World!";
int main() {
    printf("%s\\n", message);
    return 0;
}
"""
        source_file = temp_dir / "strings.c"
        source_file.write_text(source)
        binary_file = temp_dir / "strings_test"

        try:
            subprocess.run(
                ["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True
            )
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    @pytest.mark.skipif(not has_tool("strings"), reason="strings command not available")
    def test_strings_preserved(self, string_binary, temp_dir):
        """Verify string constants are preserved after mutation."""
        output = temp_dir / "strings_mutated"

        # Get strings
        success, stdout, _ = run_tool("strings", [str(string_binary)])

        if success and stdout:
            original_strings = set(stdout.decode().strip().split("\n"))

            # Filter for meaningful strings (> 4 chars, printable)
            meaningful = {s for s in original_strings if len(s) > 4 and s.isprintable()}

            config = EngineConfig.create_default()
            with MorphEngine(config=config) as engine:
                engine.load_binary(string_binary).analyze()
                engine.add_mutation("nop")
                result = engine.run(validation_mode="structural")

                if result.successful:
                    engine.save(output)

            if output.exists():
                success2, stdout2, _ = run_tool("strings", [str(output)])
                if success2 and stdout2:
                    mutated_strings = set(stdout2.decode().strip().split("\n"))

                    # Key strings should be preserved
                    for s in meaningful:
                        if s and len(s) > 4:
                            assert s in mutated_strings, f"String '{s}' lost after mutation"
