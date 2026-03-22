"""
Conftest for real binary tests.

Provides fixtures for testing with real system binaries.
"""

import os
import platform
import shutil
import subprocess

import pytest


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "real_binary: tests that require real system binaries")
    config.addinivalue_line("markers", "self_mutation: tests that mutate r2morph itself")


@pytest.fixture(scope="session")
def system_binaries_available():
    """Check if system binaries are available for testing."""
    binaries = []

    if platform.system() == "Linux":
        candidates = [
            "/bin/ls",
            "/bin/cat",
            "/bin/echo",
            "/usr/bin/whoami",
            "/usr/bin/id",
            "/bin/true",
            "/bin/false",
        ]
    elif platform.system() == "Darwin":
        candidates = [
            "/bin/ls",
            "/bin/cat",
            "/usr/bin/whoami",
            "/usr/bin/id",
            "/usr/bin/true",
            "/usr/bin/false",
        ]
    elif platform.system() == "Windows":
        candidates = [
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\find.exe",
        ]
    else:
        candidates = []

    for path in candidates:
        if os.path.exists(path):
            binaries.append(path)

    return binaries


@pytest.fixture(scope="session")
def has_gcc():
    """Check if gcc is available."""
    try:
        result = subprocess.run(["gcc", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def has_r2():
    """Check if radare2 is available."""
    try:
        result = subprocess.run(["r2", "-v"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def has_objdump():
    """Check if objdump is available."""
    return shutil.which("objdump") is not None


@pytest.fixture(scope="session")
def has_readelf():
    """Check if readelf is available."""
    return shutil.which("readelf") is not None


@pytest.fixture
def temp_binary(tmp_path):
    """Create a simple test binary."""
    source = """
#include <stdio.h>
int main() {
    printf("Hello\\n");
    return 0;
}
"""
    source_file = tmp_path / "test.c"
    source_file.write_text(source)
    binary_file = tmp_path / "test"

    try:
        subprocess.run(["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True)
        return binary_file
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("gcc not available")


@pytest.fixture
def temp_binary_with_functions(tmp_path):
    """Create a test binary with multiple functions."""
    source = """
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main() {
    printf("add: %d\\n", add(1, 2));
    printf("multiply: %d\\n", multiply(3, 4));
    printf("factorial: %d\\n", factorial(5));
    return 0;
}
"""
    source_file = tmp_path / "functions.c"
    source_file.write_text(source)
    binary_file = tmp_path / "functions"

    try:
        subprocess.run(
            ["gcc", "-o", str(binary_file), str(source_file), "-no-pie", "-O0"], check=True, capture_output=True
        )
        return binary_file
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("gcc not available")


@pytest.fixture
def temp_binary_with_loops(tmp_path):
    """Create a test binary with loops."""
    source = """
#include <stdio.h>

int main() {
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        sum += i;
    }
    printf("Sum: %d\\n", sum);
    return 0;
}
"""
    source_file = tmp_path / "loops.c"
    source_file.write_text(source)
    binary_file = tmp_path / "loops"

    try:
        subprocess.run(["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True)
        return binary_file
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("gcc not available")


def _check_gcc_available():
    """Check if gcc is available."""
    try:
        result = subprocess.run(["gcc", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _check_r2_available():
    """Check if radare2 is available."""
    try:
        result = subprocess.run(["r2", "-v"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def pytest_collection_modifyitems(config, items):
    """Skip tests based on available tools."""
    skip_no_gcc = pytest.mark.skip(reason="gcc not available")
    skip_no_r2 = pytest.mark.skip(reason="radare2 not available")

    has_gcc_available = _check_gcc_available()
    has_r2_available = _check_r2_available()

    for item in items:
        if "temp_binary" in str(item.fixturenames) or "temp_binary_with_functions" in str(item.fixturenames):
            if not has_gcc_available:
                item.add_marker(skip_no_gcc)

        if "has_r2" in str(item.fixturenames) and not has_r2_available:
            item.add_marker(skip_no_r2)
