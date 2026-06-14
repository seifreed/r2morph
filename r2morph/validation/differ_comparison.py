"""Comparison helpers for validation diffing."""

from __future__ import annotations

from r2morph.core.binary import Binary
from r2morph.validation.differ_helpers import compare_section_bytes
from r2morph.validation.differ_models import (
    BinaryDiff,
    ChangeSeverity,
    DiffReport,
    DiffType,
    FunctionDiff,
    SectionDiff,
)


def _binary_path(binary: Binary) -> str:
    return str(binary.path) if binary.path else ""


def compare_sections(original: Binary, mutated: Binary, context_bytes: int) -> list[BinaryDiff]:
    diffs: list[BinaryDiff] = []

    try:
        orig_sections = original.get_sections()
        mut_sections = mutated.get_sections()
    except Exception:
        return diffs

    orig_names = {s.get("name", ""): s for s in orig_sections}
    mut_names = {s.get("name", ""): s for s in mut_sections}
    original_path = _binary_path(original)
    mutated_path = _binary_path(mutated)

    for name in orig_names:
        if name not in mut_names:
            diffs.append(
                BinaryDiff(
                    original_path=original_path,
                    mutated_path=mutated_path,
                    diff_type=DiffType.SECTION_REMOVED,
                    severity=ChangeSeverity.HIGH,
                    description=f"Section '{name}' removed",
                )
            )

    for name in mut_names:
        if name not in orig_names:
            diffs.append(
                BinaryDiff(
                    original_path=original_path,
                    mutated_path=mutated_path,
                    diff_type=DiffType.SECTION_ADDED,
                    severity=ChangeSeverity.MEDIUM,
                    description=f"Section '{name}' added",
                )
            )

    for name in set(orig_names.keys()) & set(mut_names.keys()):
        orig = orig_names[name]
        mut = mut_names[name]

        orig_addr = orig.get("addr", orig.get("virtual_address", 0))
        mut_addr = mut.get("addr", mut.get("virtual_address", 0))
        orig_size = orig.get("size", orig.get("virtual_size", 0))
        mut_size = mut.get("size", mut.get("virtual_size", 0))

        if orig_addr != mut_addr or orig_size != mut_size:
            section_diff = SectionDiff(
                name=name,
                original_address=orig_addr,
                mutated_address=mut_addr,
                original_size=orig_size,
                mutated_size=mut_size,
                original_permissions=orig.get("perm", ""),
                mutated_permissions=mut.get("perm", ""),
            )
            section_diff.byte_diffs = compare_section_bytes(original, mutated, orig, mut, context_bytes)
            severity = ChangeSeverity.HIGH if len(section_diff.byte_diffs) > 10 else ChangeSeverity.MEDIUM
            diffs.append(
                BinaryDiff(
                    original_path=original_path,
                    mutated_path=mutated_path,
                    diff_type=DiffType.SECTION_MODIFIED,
                    severity=severity,
                    description=f"Section '{name}' modified",
                    section_diffs=[section_diff],
                    byte_diff_count=len(section_diff.byte_diffs),
                )
            )

    return diffs


def compare_functions(original: Binary, mutated: Binary) -> list[BinaryDiff]:
    diffs: list[BinaryDiff] = []

    try:
        orig_funcs = original.get_functions()
        mut_funcs = mutated.get_functions()
    except Exception:
        return diffs

    orig_addrs = {f.get("offset", f.get("addr", 0)): f for f in orig_funcs}
    mut_addrs = {f.get("offset", f.get("addr", 0)): f for f in mut_funcs}
    original_path = _binary_path(original)
    mutated_path = _binary_path(mutated)

    for addr in orig_addrs:
        if addr not in mut_addrs:
            diffs.append(
                BinaryDiff(
                    original_path=original_path,
                    mutated_path=mutated_path,
                    diff_type=DiffType.FUNCTION_REMOVED,
                    severity=ChangeSeverity.HIGH,
                    description=f"Function at 0x{addr:x} removed",
                )
            )

    for addr in mut_addrs:
        if addr not in orig_addrs:
            diffs.append(
                BinaryDiff(
                    original_path=original_path,
                    mutated_path=mutated_path,
                    diff_type=DiffType.FUNCTION_ADDED,
                    severity=ChangeSeverity.MEDIUM,
                    description=f"Function at 0x{addr:x} added",
                )
            )

    for addr in set(orig_addrs.keys()) & set(mut_addrs.keys()):
        orig_func = orig_addrs[addr]
        mut_func = mut_addrs[addr]
        orig_size = orig_func.get("size", 0)
        mut_size = mut_func.get("size", 0)

        if orig_size != mut_size:
            func_diff = FunctionDiff(
                name=orig_func.get("name", f"func_{addr:x}"),
                address=addr,
                original_size=orig_size,
                mutated_size=mut_size,
            )
            diffs.append(
                BinaryDiff(
                    original_path=original_path,
                    mutated_path=mutated_path,
                    diff_type=DiffType.FUNCTION_MODIFIED,
                    severity=ChangeSeverity.LOW,
                    description=f"Function {func_diff.name} size changed",
                    function_diffs=[func_diff],
                )
            )

    return diffs


def compare_symbols(original: Binary, mutated: Binary) -> list[BinaryDiff]:
    _ = original, mutated
    return []


def compare_header(original: Binary, mutated: Binary) -> list[BinaryDiff]:
    diffs: list[BinaryDiff] = []

    try:
        orig_arch = original.get_arch_info()
        mut_arch = mutated.get_arch_info()
    except Exception:
        return diffs

    original_path = _binary_path(original)
    mutated_path = _binary_path(mutated)

    if orig_arch.get("arch") != mut_arch.get("arch"):
        diffs.append(
            BinaryDiff(
                original_path=original_path,
                mutated_path=mutated_path,
                diff_type=DiffType.HEADER_MODIFIED,
                severity=ChangeSeverity.CRITICAL,
                description=f"Architecture changed from {orig_arch.get('arch')} to {mut_arch.get('arch')}",
            )
        )

    if orig_arch.get("bits") != mut_arch.get("bits"):
        diffs.append(
            BinaryDiff(
                original_path=original_path,
                mutated_path=mutated_path,
                diff_type=DiffType.HEADER_MODIFIED,
                severity=ChangeSeverity.CRITICAL,
                description=f"Bits changed from {orig_arch.get('bits')} to {mut_arch.get('bits')}",
            )
        )

    return diffs


def build_diff_report(original: Binary, mutated: Binary, context_bytes: int) -> DiffReport:
    diffs: list[BinaryDiff] = []
    diffs.extend(compare_sections(original, mutated, context_bytes))
    diffs.extend(compare_functions(original, mutated))
    diffs.extend(compare_symbols(original, mutated))
    diffs.extend(compare_header(original, mutated))

    report = DiffReport(
        original_binary=_binary_path(original),
        mutated_binary=_binary_path(mutated),
        diffs=diffs,
    )
    report._compute_summary()
    return report
