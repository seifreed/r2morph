"""Continuous fuzzing regression helpers."""

from __future__ import annotations

import logging
import statistics
from pathlib import Path

from r2morph.validation.mutation_fuzzer_types import FuzzCampaignResult, FuzzConfig

logger = logging.getLogger(__name__)


class ContinuousFuzzer:
    """Continuous fuzzing framework for regression testing."""

    def __init__(self, config: FuzzConfig | None = None) -> None:
        from r2morph.validation.mutation_fuzzer import MutationPassFuzzer

        self.config = config or FuzzConfig()
        self.fuzzer = MutationPassFuzzer(self.config)
        self.campaign_history: list[FuzzCampaignResult] = []
        self.regression_threshold = 0.95

    def run_regression_check(
        self,
        original_path: Path,
        mutated_path: Path,
        mutation_names: list[str],
        baseline_result: FuzzCampaignResult | None = None,
    ) -> tuple[bool, FuzzCampaignResult]:
        current_result = self.fuzzer.fuzz_mutations(original_path, mutated_path, mutation_names)

        self.campaign_history.append(current_result)

        if baseline_result is None:
            return True, current_result

        current_rate = current_result.success_rate
        baseline_rate = baseline_result.success_rate

        if current_rate < baseline_rate * self.regression_threshold:
            logger.warning(
                f"Regression detected: success rate dropped from {baseline_rate:.2f}% to {current_rate:.2f}%"
            )
            return False, current_result

        if current_result.crashes > baseline_result.crashes:
            logger.warning(f"More crashes detected: {current_result.crashes} vs baseline {baseline_result.crashes}")
            return False, current_result

        return True, current_result

    def get_statistics(self) -> dict[str, float | int | list[int | None]]:
        if not self.campaign_history:
            return {"campaigns": 0}

        success_rates = [c.success_rate for c in self.campaign_history]
        crash_counts = [c.crashes for c in self.campaign_history]
        timeout_counts = [c.timeouts for c in self.campaign_history]

        return {
            "campaigns": len(self.campaign_history),
            "avg_success_rate": statistics.mean(success_rates),
            "min_success_rate": min(success_rates),
            "max_success_rate": max(success_rates),
            "total_crashes": sum(crash_counts),
            "total_timeouts": sum(timeout_counts),
            "avg_crashes_per_campaign": statistics.mean(crash_counts),
            "avg_timeouts_per_campaign": statistics.mean(timeout_counts),
            "seeds_used": [c.seed for c in self.campaign_history],
        }


def create_continuous_fuzzer(
    num_tests: int = 100,
    timeout: int = 5,
) -> ContinuousFuzzer:
    config = FuzzConfig(num_tests=num_tests, timeout=timeout)
    return ContinuousFuzzer(config)


__all__ = ["ContinuousFuzzer", "create_continuous_fuzzer"]
