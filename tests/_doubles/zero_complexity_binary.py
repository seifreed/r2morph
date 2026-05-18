"""Real in-memory Binary double with zero detectable complexity.

Not unittest.mock: a concrete object whose ``get_functions`` returns an
empty list, modelling a clean/trivial binary with no functions,
obfuscation patterns, MBA expressions or VM dispatchers. Driving
``IterativeSimplifier.simplify`` with it makes ``_calculate_complexity``
return ``0.0``, exercising the zero-``prev_complexity`` convergence path.

It deliberately implements nothing else: ``IterativeSimplifier``'s
preprocessing calls ``ObfuscationDetector().analyze_binary(self.binary)``,
which accesses ``binary.is_analyzed()`` first; the resulting
``AttributeError`` is caught by the preprocessing guard, leaving the
context's complexity-contributing lists empty without spawning radare2.
"""

from __future__ import annotations

from typing import Any


class ZeroComplexityBinary:
    def get_functions(self) -> list[dict[str, Any]]:
        return []
