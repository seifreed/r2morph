"""Documentation and release-claim checks for the release contract."""

from __future__ import annotations

import json
from pathlib import Path

try:
    from scripts.protection_maturity_baseline import CORPUS_PASS_NAMES
except ModuleNotFoundError:
    from protection_maturity_baseline import CORPUS_PASS_NAMES

try:
    from scripts.release_contract_common import (
        _BANNED_BINARY_NINJA_OMISSION_PHRASES,
        _DOCUMENTATION_LINK_FILES,
        _FORBIDDEN_RELEASE_CLAIMS,
        _MARKDOWN_LINK_PATTERN,
        _RELEASE_BLOCKER_FRAGMENTS,
        _RELEASE_BLOCKER_ID_PATTERN,
        _RELEASE_BLOCKER_IDS,
        _RELEASE_BLOCKER_INDEX_AREAS,
        _RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT,
        _RELEASE_HONESTY_FILES,
        ROOT,
        VM_HANDLER_COUNT,
        _check_version,
    )
except ModuleNotFoundError:
    from release_contract_common import (
        _BANNED_BINARY_NINJA_OMISSION_PHRASES,
        _DOCUMENTATION_LINK_FILES,
        _FORBIDDEN_RELEASE_CLAIMS,
        _MARKDOWN_LINK_PATTERN,
        _RELEASE_BLOCKER_FRAGMENTS,
        _RELEASE_BLOCKER_ID_PATTERN,
        _RELEASE_BLOCKER_IDS,
        _RELEASE_BLOCKER_INDEX_AREAS,
        _RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT,
        _RELEASE_HONESTY_FILES,
        ROOT,
        VM_HANDLER_COUNT,
        _check_version,
    )


def _check_readme_support_summary(matrix: dict[str, object]) -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    summary = matrix["matrix"]["summary"]
    stability_counts = summary["stability_counts"]
    official_total = summary["official_evidenced_cells"] + summary["official_not_supported_cells"]
    non_official_total = summary["non_official_evidenced_cells"] + summary["non_official_not_supported_cells"]
    instruction_gap_count = summary["instructions_affected_counts"].get("Not exhaustively catalogued.", 0)
    instruction_gap_fragment = (
        f"{instruction_gap_count} without an exhaustive affected-instruction catalogue"
        if instruction_gap_count
        else "no remaining affected-instruction catalogue gap"
    )
    performance_gap_count = summary["performance_counts"].get("Not measured per pass.", 0)
    performance_fragment = (
        f"{performance_gap_count} passes with no per-pass performance"
        if performance_gap_count
        else "scheduled extended maturity smoke now records output-size,"
    )
    compatibility_gap_count = summary["compatibility_counts"].get(
        "Composition with other passes is not contractually supported.", 0
    )
    for fragment in (
        "NOP, instruction substitution, register substitution, instruction expansion, and block reordering "
        "on the official target",
        f"{summary['official_evidenced_cells']}/{official_total} evidenced cells for the official",
        f"{summary['non_official_evidenced_cells']}/{non_official_total} evidenced cells for non-official",
        f"{summary['official_evidence_percent']}% evidence",
        f"{summary['non_official_evidence_percent']}% evidence",
        f"{stability_counts['tier-1']} passes as Tier 1",
        f"{stability_counts['experimental']} passes as experimental",
        performance_fragment,
        (
            f"{summary['false_positive_risk_counts'].get('Not independently measured.', 0)} with no independent "
            "false-positive measurement"
        ),
        (
            f"{summary['decompiler_effectiveness_counts'].get('Not independently measured.', 0)} with no independent "
            "decompiler-effectiveness measurement"
        ),
        (f"{compatibility_gap_count} " "without contractual composition support"),
        instruction_gap_fragment,
    ):
        if fragment not in readme:
            raise ValueError(f"README support summary is missing: {fragment}")


def _check_readme_pass_surface(matrix: dict[str, object]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pass_surface = {
        "nop": ("NOP Insertion", "`-m nop`"),
        "substitute": ("Instruction Substitution", "`-m substitute`"),
        "register": ("Register Substitution", "`-m register`"),
        "instruction-expansion": ("Instruction Expansion", "`-m expand`"),
        "block-reordering": ("Block Reordering", "`-m block`"),
        "dead-code-injection": ("Dead Code Injection", "engine-only"),
        "control-flow-flattening": ("Control Flow Flattening", "engine-only"),
        "opaque-predicates": ("Opaque Predicates", "engine-only"),
        "code-virtualization": ("Code Virtualization", "engine-only"),
        "anti-disassembly": ("Anti-Disassembly", "engine-only"),
        "data-flow-mutation": ("Data Flow Mutation", "engine-only"),
        "short-jump-patching": ("Short Jump Patching", "engine-only"),
        "constant-unfolding": ("Constant Unfolding", "engine-only"),
        "code-mobility": ("Code Mobility", "engine-only"),
        "function-outlining": ("Function Outlining", "engine-only"),
        "api-hashing": ("API Hashing", "engine-only"),
        "import-obfuscation": ("Import Obfuscation", "engine-only"),
        "self-modifying-code": ("Self-Modifying Code", "engine-only"),
        "stack-strings": ("Stack Strings", "engine-only"),
        "string-obfuscation": ("String Obfuscation", "engine-only"),
        "pattern-substitution": ("Pattern Substitution", "engine-only"),
        "polymorphic-engine": ("Polymorphic Engine", "engine-only"),
    }
    for entry in matrix["passes"]:
        name = entry["name"]
        if name not in pass_surface:
            raise ValueError(f"README pass surface map is missing: {name}")
        display_name, surface = pass_surface[name]
        row_prefix = f"| **{display_name}** | {surface} |"
        if row_prefix not in readme:
            raise ValueError(f"README pass surface is missing: {row_prefix}")


def _check_readme_cross_platform_parity() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    for fragment in (
        "PE, Mach-O, ARM, and AArch64 evidence does not imply parity with Linux ELF x86-64",
        "equivalent CodeVirtualization support",
    ):
        if fragment not in readme:
            raise ValueError(f"README cross-platform parity warning is missing: {fragment}")


def _check_readme_differential_summary() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    workflow = (ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    corpus = " ".join((ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())
    for fragment in ("--passes all", "--require-applied", "--require-complete-evidence"):
        if fragment not in workflow or fragment not in readme:
            raise ValueError(f"README differential summary is missing workflow flag: {fragment}")
    for fragment in (
        "nine seed-derived command-line inputs",
        "exit code, stdout, stderr, created files, and declared observable effects",
        "runtime, size, transform-duration, runtime-duration, and static analyzer evidence",
        "total_continuous_evidence_blockers",
    ):
        if fragment not in corpus:
            raise ValueError(f"compatibility corpus differential contract is missing: {fragment}")
    for fragment in (
        "nine seed-derived inputs",
        "exit code, stdout, stderr, created files, and declared observable effects",
        "runtime, output size, transform duration, runtime duration, and static analyzer evidence",
    ):
        if fragment not in readme:
            raise ValueError(f"README differential summary is missing: {fragment}")


def _check_pass_maturity_gap_summary(matrix: dict[str, object]) -> None:
    summary = matrix["matrix"]["summary"]
    contract = " ".join((ROOT / "docs" / "pass-maturity.md").read_text(encoding="utf-8").split())
    handler = json.loads((ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    stability_counts = summary["stability_counts"]
    maturity_profile_counts = summary["maturity_profile_counts"]
    performance_gap_count = summary["performance_counts"].get("Not measured per pass.", 0)
    performance_fragment = (
        f"{performance_gap_count} passes with no per-pass performance"
        if performance_gap_count
        else "scheduled extended maturity smoke now records output-size,"
    )
    compatibility_gap_count = summary["compatibility_counts"].get(
        "Composition with other passes is not contractually supported.", 0
    )
    maturity_gap_category_count = summary["maturity_blocker_totals"]["maturity_gap_categories"]
    maturity_gap_category_label = "category" if maturity_gap_category_count == 1 else "categories"
    fragments = [
        f"{summary['official_evidence_percent']}% official evidence",
        f"{summary['non_official_evidence_percent']}% non-official evidence",
        f"{summary['parity_blocker_totals']['total_parity_blockers']} total parity blockers",
        f"{stability_counts['tier-1']} tier-1 passes",
        f"{stability_counts['experimental']} experimental passes",
        f"{maturity_profile_counts['tier-1-native']} tier-1-native profile passes",
        f"{maturity_profile_counts['experimental-corpus-selected']} experimental-corpus-selected profile passes",
        f"{maturity_profile_counts['code-virtualization']} code-virtualization profile pass",
        performance_fragment,
        (
            f"{summary['false_positive_risk_counts'].get('Not independently measured.', 0)} with no independent "
            "false-positive measurement"
        ),
        (
            f"{summary['decompiler_effectiveness_counts'].get('Not independently measured.', 0)} with no independent "
            "decompiler-effectiveness measurement"
        ),
        (f"{compatibility_gap_count} " "without contractual composition support"),
        f"{summary['maturity_blocker_totals']['total_maturity_field_gaps']} total per-pass maturity field gaps",
        f"{maturity_gap_category_count} maturity gap {maturity_gap_category_label}",
        f"{summary['vm_semantic_blocker_totals']['total_vm_semantic_blockers']} VM semantic blockers",
        f"{summary['vm_resistance_blocker_totals']['total_vm_resistance_blockers']} VM resistance blockers",
        f"{handler['seed_count']} seeds with {VM_HANDLER_COUNT} handlers per seed",
        f"{handler['cross_seed_exact_normalised_matches']} exact normalized cross-seed handler matches",
        f"{bytecode['all_handler_stride_unique_count']} handler stride values",
        "target handler stride diversity",
        "not human approval of anti-tamper or progressive bytecode protection",
    ]
    experimental_profile_count = maturity_profile_counts.get("experimental", 0)
    if experimental_profile_count:
        fragments.append(f"{experimental_profile_count} experimental profile passes")
    instruction_gap_count = summary["instructions_affected_counts"].get("Not exhaustively catalogued.", 0)
    fragments.append(
        f"{instruction_gap_count} without an exhaustive affected-instruction catalogue"
        if instruction_gap_count
        else "no remaining exhaustive affected-instruction catalogue gap"
    )
    for fragment in fragments:
        if fragment not in contract:
            raise ValueError(f"pass maturity summary is missing: {fragment}")


def _check_corpus_pass_selection_docs() -> None:
    maturity = " ".join((ROOT / "docs" / "pass-maturity.md").read_text(encoding="utf-8").split())
    compatibility = " ".join((ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8").split())
    maturity_passes = ", ".join(f"`{pass_name}`" for pass_name in CORPUS_PASS_NAMES[:-1])
    compatibility_passes = ", ".join(CORPUS_PASS_NAMES[:-1])
    if f"{maturity_passes}, and `{CORPUS_PASS_NAMES[-1]}`." not in maturity:
        raise ValueError("pass maturity contract must name the public corpus selection")
    if f"for ten selected passes: {compatibility_passes}, and {CORPUS_PASS_NAMES[-1]}." not in compatibility:
        raise ValueError("compatibility corpus must name the full pass selection")


def _check_changelog(package_version: str) -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {package_version}" not in changelog:
        raise ValueError("changelog must contain the package version heading")
    if package_version == _check_version() and "Independent human review approval is recorded" not in changelog:
        raise ValueError("changelog must record the independent human review")


def _check_readme_adversarial_summary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    report_name = "protection-adversarial-angr-local-2026-09-18-59898697.json"
    report = json.loads((ROOT / "docs" / report_name).read_text(encoding="utf-8"))
    independent_review = json.loads((ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    tools = report["tools"]
    completed = sum(1 for tool in tools if tool["status"] == "completed")
    unavailable = sum(1 for tool in tools if tool["status"] == "unavailable")
    binary_ninja = next(tool for tool in tools if tool["tool"] == "binary-ninja")
    evidence_details = {check["name"]: check["detail"] for check in independent_review["checks"]}
    for fragment in (
        f"{completed} completed analyzer slots",
        f"{unavailable} unavailable analyzer slots",
        report_name,
        "Binary Ninja is an explicit analyzer slot",
        f"`binary-ninja` as {binary_ninja['status']}",
        binary_ninja["reason"],
        evidence_details["triton_corpus_evidence"],
        evidence_details["ida_corpus_evidence"],
        evidence_details["ida_current_summary_evidence"],
        "availability in one campaign does not fill unavailable rows in another",
        "the all-named-analyzers 1.0 criterion remains open",
    ):
        if fragment not in readme:
            raise ValueError(f"README adversarial summary is missing: {fragment}")


def _check_readme_vm_review_scope() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    packet = " ".join((ROOT / "docs" / "independent-review-packet.md").read_text(encoding="utf-8").split())
    review = json.loads((ROOT / "docs" / "independent-review.json").read_text(encoding="utf-8"))
    release_decision = review["release_decision"]
    for fragment in (
        f"human_signoff: {review['human_signoff']}",
        f"release_decision: {release_decision['status']}",
        "reviewed memory, direct/indirect calls, returns, flags, FP/SIMD, varargs/ABI, unwinding, TLS/signals, "
        "SSA, and liveness paths",
        "unsupported instructions must fail closed",
        "partial protected functions",
        "instruction address, mnemonic, type, size, bounded opcode preview, capability, and reason",
        "VM ISA/opcode diversification, dispatcher/handler alternatives, superinstructions, anti-tamper, "
        "and progressive bytecode protection",
        "Human independent review approved the reviewed commit",
    ):
        if fragment not in readme:
            raise ValueError(f"README VM review scope is missing: {fragment}")
    for fragment in (
        "VM ISA/opcode diversification, dispatcher/handler alternatives",
        "superinstructions, anti-tamper, and progressive bytecode protection",
    ):
        if fragment not in packet:
            raise ValueError(f"independent review packet VM scope is missing: {fragment}")


def _check_readme_vm_resistance_summary() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    handler = json.loads((ROOT / "docs" / "protection-handler-clustering.json").read_text(encoding="utf-8"))
    bytecode = json.loads((ROOT / "docs" / "protection-bytecode-grammar.json").read_text(encoding="utf-8"))
    independent_analysis = json.loads(
        (ROOT / "docs" / "protection-independent-analysis-2026-11-10.json").read_text(encoding="utf-8")
    )
    readiness = json.loads((ROOT / "docs" / "one-zero-readiness.json").read_text(encoding="utf-8"))
    required_limitations = (
        "does not establish general resistance to professional reverse engineering",
        "does not replace the required three-analyzer release campaign",
    )
    if not all(limitation in independent_analysis["limitations"] for limitation in required_limitations):
        raise ValueError("independent analysis must retain its resistance scope limitations")
    if (
        readiness["criteria"]["documented_resistance_scope"]["status"] != "complete"
        or "documented_resistance_scope" in readiness["blocking_criteria"]
    ):
        raise ValueError("documented resistance scope must match its published limitation evidence")
    for fragment in (
        f"{handler['seed_count']} seeds with {VM_HANDLER_COUNT} handlers per seed",
        f"{handler['cross_seed_exact_normalised_matches']} exact normalized cross-seed handler matches",
        f"{bytecode['all_handler_stride_unique_count']} handler stride values",
        "target handler stride diversity",
        "protection-handler-clustering.json",
        "protection-bytecode-grammar.json",
        "they do not measure generalized attack cost or establish resistance to professional reverse engineering",
        "Published resistance results remain an open 1.0 criterion.",
        *required_limitations,
    ):
        if fragment not in readme:
            raise ValueError(f"README VM resistance summary is missing: {fragment}")


def _check_documentation_links(documents: tuple[Path, ...] = _DOCUMENTATION_LINK_FILES) -> None:
    for document in documents:
        for target in _MARKDOWN_LINK_PATTERN.findall(document.read_text(encoding="utf-8")):
            target_path = target.split("#", 1)[0].strip().strip("<>")
            if not target_path or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if not (document.parent / target_path).exists():
                raise ValueError(f"missing documentation link: {target}")


def _forbidden_release_claims(text: str) -> tuple[str, ...]:
    normalized = text.lower()
    return tuple(phrase for phrase in _FORBIDDEN_RELEASE_CLAIMS if phrase in normalized)


def _check_documentation_claims() -> None:
    for document in _RELEASE_HONESTY_FILES:
        claims = _forbidden_release_claims(document.read_text(encoding="utf-8"))
        if claims:
            raise ValueError(f"{document.relative_to(ROOT)} contains unsupported release claim: {claims[0]}")
    corpus = (ROOT / "docs" / "compatibility-corpus.md").read_text(encoding="utf-8")
    if any(phrase in corpus for phrase in _BANNED_BINARY_NINJA_OMISSION_PHRASES):
        raise ValueError("compatibility corpus must not claim Binary Ninja is intentionally omitted")
    if "Binary Ninja through its installed API" not in corpus:
        raise ValueError("compatibility corpus must retain the Binary Ninja availability-slot contract")


def _validate_release_blockers_text(blockers: str) -> None:
    blocker_ids = tuple(_RELEASE_BLOCKER_ID_PATTERN.findall(blockers))
    if blocker_ids[: len(_RELEASE_BLOCKER_IDS)] != _RELEASE_BLOCKER_IDS:
        raise ValueError("release blockers ledger is missing stable blocker IDs")
    if (
        blocker_ids.count("RB-001") != _RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT
        or blocker_ids.count("RB-007") != _RELEASE_BLOCKER_REQUIRED_ENTRY_COUNT
    ):
        raise ValueError("release blockers ledger must include prose and index entries")
    for fragment in _RELEASE_BLOCKER_FRAGMENTS:
        if fragment not in blockers:
            raise ValueError(f"release blockers ledger is missing: {fragment}")
    for blocker_id in _RELEASE_BLOCKER_IDS:
        _, tail = blockers.split(blocker_id, 1)
        section = tail.split("RB-", 1)[0]
        if "Evidence map:" not in section or not _MARKDOWN_LINK_PATTERN.search(section):
            raise ValueError(f"release blocker is missing evidence links: {blocker_id}")
        if "Exit criteria:" not in section:
            raise ValueError(f"release blocker is missing exit criteria: {blocker_id}")
    for blocker_id, area in _RELEASE_BLOCKER_INDEX_AREAS.items():
        if f"| {blocker_id} | {area} |" not in blockers:
            raise ValueError(f"release blocker index is missing: {blocker_id}")


def _check_release_blockers() -> None:
    blockers = " ".join((ROOT / "docs" / "release-blockers.md").read_text(encoding="utf-8").split())
    _validate_release_blockers_text(blockers)
