"""Cache-backed call graph construction helpers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from r2morph.analysis.call_graph import CallGraph
from r2morph.analysis.call_graph_builder import build_call_graph
from r2morph.core.binary import Binary

if TYPE_CHECKING:
    from r2morph.core.analysis_cache import AnalysisCache

logger = logging.getLogger(__name__)


def build_call_graph_cached(
    binary: Binary,
    cache: AnalysisCache | None = None,
    include_indirect: bool = True,
    include_plt: bool = True,
) -> CallGraph:
    """Build a call graph with optional cache lookup/persistence."""
    options = {
        "include_indirect": include_indirect,
        "include_plt": include_plt,
    }

    if cache is not None:
        try:
            binary_data = binary.path.read_bytes()
            cached = cache.get(binary_data, "call_graph", options)
            if cached is not None:
                logger.debug("Call graph cache hit")
                return CallGraph.from_json(cached)
        except Exception as exc:
            logger.debug("Cache lookup failed: %s", exc)

    cg = build_call_graph(binary, include_indirect=include_indirect, include_plt=include_plt)

    if cache is not None:
        try:
            binary_data = binary.path.read_bytes()
            cache.set(binary_data, "call_graph", cg.to_json(), options)
            logger.debug("Call graph cached")
        except Exception as exc:
            logger.debug("Cache storage failed: %s", exc)

    return cg
