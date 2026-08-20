from __future__ import annotations

from r2morph.validation import (
    BenchmarkConfig as PublicBenchmarkConfig,
)
from r2morph.validation import (
    PerformanceMetric as PublicPerformanceMetric,
)
from r2morph.validation import (
    PerformanceRegression as PublicPerformanceRegression,
)
from r2morph.validation import (
    PerformanceSnapshot as PublicPerformanceSnapshot,
)
from r2morph.validation.performance_regression_models import (
    BenchmarkConfig as ModelsBenchmarkConfig,
)
from r2morph.validation.performance_regression_models import (
    PerformanceMetric as ModelsPerformanceMetric,
)
from r2morph.validation.performance_regression_models import (
    PerformanceRegression as ModelsPerformanceRegression,
)
from r2morph.validation.performance_regression_models import (
    PerformanceSnapshot as ModelsPerformanceSnapshot,
)
from tests.utils.assertions import expect


def test_performance_regression_models_are_reexported_from_validation_package() -> None:
    expect(not (PublicPerformanceMetric is not ModelsPerformanceMetric))
    expect(not (PublicPerformanceSnapshot is not ModelsPerformanceSnapshot))
    expect(not (PublicPerformanceRegression is not ModelsPerformanceRegression))
    expect(not (PublicBenchmarkConfig is not ModelsBenchmarkConfig))
