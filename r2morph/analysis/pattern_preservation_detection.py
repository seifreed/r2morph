"""Pattern detection helpers for preservation analysis."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.exception import ExceptionInfoReader
from r2morph.analysis.pattern_preservation_models import Criticality, PatternType, PreservedPattern
from r2morph.analysis.switch_table import SwitchTableAnalyzer

logger = logging.getLogger(__name__)


def detect_exception_patterns(manager: Any) -> None:
    """Detect exception handling patterns (landing pads, handlers)."""
    try:
        if manager._exception_reader is None:
            manager._exception_reader = ExceptionInfoReader(manager.binary)
        frames = manager._exception_reader.read_exception_frames()

        for func_addr, frame in frames.items():
            if frame.landing_pads:
                pattern = PreservedPattern(
                    type=PatternType.EXCEPTION_HANDLER,
                    start_address=frame.function_start,
                    end_address=frame.function_end,
                    criticality=Criticality.PRESERVE,
                    source="exception_analysis",
                    metadata={"function_address": func_addr},
                )
                manager._patterns.append(pattern)

                for pad in frame.landing_pads:
                    landing_pattern = PreservedPattern(
                        type=PatternType.LANDING_PAD,
                        start_address=pad.address,
                        end_address=pad.address + max(pad.size, 16),
                        criticality=Criticality.PRESERVE,
                        source="exception_analysis",
                        metadata={"action": pad.action.value},
                    )
                    manager._patterns.append(landing_pattern)
    except Exception as e:
        logger.debug("Exception pattern detection failed: %s", e)


def detect_jump_table_patterns(manager: Any) -> None:
    """Detect jump tables and switch dispatch patterns."""
    try:
        if manager._switch_analyzer is None:
            manager._switch_analyzer = SwitchTableAnalyzer(manager.binary)
        functions = manager.binary.get_functions()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            if func_addr == 0:
                continue

            try:
                jump_tables, other_jumps = manager._switch_analyzer.detect_switch_pattern(func_addr)

                for table in jump_tables:
                    table_pattern = PreservedPattern(
                        type=PatternType.JUMP_TABLE,
                        start_address=table.table_address,
                        end_address=table.table_address + (len(table.entries) * 8),
                        criticality=Criticality.PRESERVE,
                        source="switch_analysis",
                        metadata={
                            "case_count": table.case_count,
                            "is_dense": table.is_dense,
                            "bounds_register": table.bounds_check_register,
                        },
                    )
                    manager._patterns.append(table_pattern)

                    for target in table.unique_targets:
                        target_pattern = PreservedPattern(
                            type=PatternType.JUMP_TABLE_ENTRY,
                            start_address=target,
                            end_address=target + 16,
                            criticality=Criticality.CAUTION,
                            source="switch_analysis",
                            metadata={"table_address": table.table_address},
                        )
                        manager._patterns.append(target_pattern)

                for jump in other_jumps:
                    if jump.jump_type in ("jumptable", "indirect"):
                        jump_pattern = PreservedPattern(
                            type=PatternType.INDIRECT_JUMP,
                            start_address=jump.address,
                            end_address=jump.address + 16,
                            criticality=Criticality.AVOID,
                            source="switch_analysis",
                            metadata={"jump_type": jump.jump_type},
                        )
                        manager._patterns.append(jump_pattern)
            except Exception as e:
                logger.debug("Jump table detection failed for 0x%x: %s", func_addr, e)
    except Exception as e:
        logger.debug("Jump table pattern detection failed: %s", e)


def detect_plt_got_patterns(manager: Any) -> None:
    """Detect PLT thunks and GOT entries."""
    try:
        if manager._switch_analyzer is None:
            manager._switch_analyzer = SwitchTableAnalyzer(manager.binary)

        plt_entries = manager._switch_analyzer.detect_plt_got_thunks()

        for addr, info in plt_entries.items():
            pattern = PreservedPattern(
                type=PatternType.PLT_THUNK,
                start_address=addr,
                end_address=addr + 16,
                criticality=Criticality.PRESERVE,
                source="plt_got_analysis",
                metadata=info,
            )
            manager._patterns.append(pattern)
    except Exception as e:
        logger.debug("PLT/GOT pattern detection failed: %s", e)


def detect_tail_call_patterns(manager: Any) -> None:
    """Detect tail call patterns."""
    try:
        if manager._switch_analyzer is None:
            manager._switch_analyzer = SwitchTableAnalyzer(manager.binary)

        functions = manager.binary.get_functions()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            if func_addr == 0:
                continue

            try:
                tail_calls = manager._switch_analyzer.detect_tail_calls(func_addr)

                for jump_addr, target_addr in tail_calls:
                    pattern = PreservedPattern(
                        type=PatternType.TAIL_CALL,
                        start_address=jump_addr,
                        end_address=jump_addr + 5,
                        criticality=Criticality.AVOID,
                        source="tail_call_analysis",
                        metadata={"target_address": target_addr},
                    )
                    manager._patterns.append(pattern)
            except Exception as e:
                logger.debug("Tail call detection failed for 0x%x: %s", func_addr, e)
    except Exception as e:
        logger.debug("Tail call pattern detection failed: %s", e)
