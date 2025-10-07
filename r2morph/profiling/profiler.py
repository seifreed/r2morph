"""
Binary profiling for guided mutations.
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class BinaryProfiler:
    """
    Profiles binary execution to guide mutations.

    Uses dynamic analysis to identify:
    - Hot paths (frequently executed)
    - Cold code (rarely executed)
    - Critical sections (performance-sensitive)
    """

    def __init__(self, binary_path: Path):
        """
        Initialize profiler.

        Args:
            binary_path: Binary to profile
        """
        self.binary_path = binary_path
        self.profile_data: dict = {}

    def profile(self, test_inputs: list[str] = None, duration: int = 10) -> dict:
        """
        Profile binary execution.

        Args:
            test_inputs: Inputs for profiling
            duration: Profile duration (seconds)

        Returns:
            Profile data dict
        """
        logger.info(f"Profiling {self.binary_path.name}")

        self.profile_data = self._profile_with_sampling(duration)

        return self.profile_data

    def _profile_with_sampling(self, duration: int) -> dict:
        """
        Profile using sampling (perf, dtrace, etc).

        Args:
            duration: Duration in seconds

        Returns:
            Profile data
        """
        import platform

        system = platform.system()

        if system == "Linux":
            return self._profile_linux_perf(duration)
        elif system == "Darwin":
            return self._profile_macos_dtrace(duration)
        else:
            logger.warning("Profiling not available on this platform")
            return {}

    def _profile_linux_perf(self, duration: int) -> dict:
        """Profile on Linux using perf."""
        try:
            cmd = ["perf", "record", "-F", "99", "-g", "--", str(self.binary_path)]

            subprocess.run(cmd, timeout=duration)

            report = subprocess.run(["perf", "report", "--stdio"], capture_output=True, text=True)

            hot_functions = self._parse_perf_output(report.stdout)

            return {"hot_functions": hot_functions}

        except Exception as e:
            logger.error(f"perf profiling failed: {e}")
            return {}

    def _profile_macos_dtrace(self, duration: int) -> dict:
        """Profile on macOS using dtrace/Instruments."""
        logger.info("Would use dtrace/Instruments for profiling")
        return {}

    def _parse_perf_output(self, output: str) -> list[str]:
        """Parse perf report output."""
        hot_functions = []

        for line in output.split("\n"):
            if "%" in line and "sym." in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("sym."):
                        hot_functions.append(part)
                        break

        return hot_functions[:20]

    def get_hot_functions(self) -> set[str]:
        """
        Get frequently executed functions.

        Returns:
            Set of function names
        """
        return set(self.profile_data.get("hot_functions", []))

    def get_cold_functions(self, all_functions: list[str]) -> set[str]:
        """
        Get rarely executed functions.

        Args:
            all_functions: All function names

        Returns:
            Set of cold function names
        """
        hot = self.get_hot_functions()
        return set(all_functions) - hot

    def should_mutate_aggressively(self, func_name: str) -> bool:
        """
        Determine if function should be aggressively mutated.

        Cold functions can be mutated more aggressively.

        Args:
            func_name: Function name

        Returns:
            True if aggressive mutation is recommended
        """
        hot_functions = self.get_hot_functions()

        return func_name not in hot_functions
