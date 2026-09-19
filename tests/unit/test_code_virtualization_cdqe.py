"""Regression coverage for virtualizing the implicit ``cdqe`` extension."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_region_classification import _classify
from tests.utils.assertions import expect


def test_classify_cdqe_as_movxreg_sign_extend_eax_to_rax() -> None:
    instruction: dict[str, Any] = {
        "addr": 0x1000,
        "size": 2,
        "type": "mov",
        "opcode": "cdqe",
    }

    expect(_classify(instruction) == ["movxreg", "s", 32, 64, 0, 0])
