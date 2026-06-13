"""Shared CLI workflow helpers for mutation and report filter resolution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.core.support import PRODUCT_SUPPORT, is_experimental_mutation
from r2morph.reporting import SEVERITY_ORDER
from r2morph.reporting.report_gate_helpers import (
    _attach_gate_evaluation,
    _pass_severity_requirements_met,
    _severity_threshold_met,
)
from r2morph.utils.logging import setup_logging
from r2morph.validation import BinaryValidator
from r2morph.validation.validator import RuntimeComparisonConfig

console = Console()


def _build_config(aggressive: bool, force: bool) -> EngineConfig:
    config = EngineConfig.create_aggressive() if aggressive else EngineConfig.create_default()
    if force:
        config.force_different = True
        config.nop.force_different = True
        config.substitution.force_different = True
        config.register.force_different = True
        config.expansion.force_different = True
        config.block.force_different = True
    return config


def _mutation_config(section: Any, seed: int | None, offset: int) -> dict[str, Any]:
    cfg: dict[str, Any] = section.to_dict()
    if seed is not None:
        cfg["seed"] = seed + offset
    return cfg


def _warn_experimental_mutations(mutations: list[str]) -> None:
    if not mutations:
        return
    console.print(f"[yellow]Experimental mutations selected:[/yellow] {', '.join(mutations)}")
    console.print("[yellow]These passes are outside the stable core and validation coverage is best-effort.[/yellow]")


def _warn_experimental_validation_mode(validation_mode: str) -> None:
    if validation_mode != "symbolic":
        return
    console.print("[yellow]Experimental validation mode selected:[/yellow] symbolic")
    console.print(
        "[yellow]This mode performs bounded symbolic prechecks and structural fallback; it does not prove general semantic equivalence.[/yellow]"
    )


def _build_runtime_validator(
    *,
    timeout: int,
    corpus: Path | None = None,
    compare_files: bool = False,
    normalize_whitespace: bool = False,
) -> BinaryValidator:
    """Build a runtime validator from CLI options."""
    validator = BinaryValidator(
        timeout=timeout,
        comparison=RuntimeComparisonConfig(
            compare_files=compare_files,
            normalize_whitespace=normalize_whitespace,
        ),
    )
    if corpus is not None:
        with open(corpus, encoding="utf-8") as handle:
            validator.load_test_cases(json.load(handle))
    return validator


def _load_mutation_pass_types() -> dict[str, type]:
    """Lazy import mutation passes so stable report/validate flows avoid extra imports."""
    from r2morph.mutations import (
        BlockReorderingPass,
        InstructionExpansionPass,
        InstructionSubstitutionPass,
        NopInsertionPass,
        RegisterSubstitutionPass,
    )

    return {
        "nop": NopInsertionPass,
        "substitute": InstructionSubstitutionPass,
        "register": RegisterSubstitutionPass,
        "expand": InstructionExpansionPass,
        "block": BlockReorderingPass,
    }


def _selected_mutation_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> list[tuple[str, Any]]:
    """Build pass instances for the selected mutation names."""
    pass_types = _load_mutation_pass_types()
    selected: list[tuple[str, Any]] = []
    offset = 0
    if "nop" in mutations:
        selected.append(("nop", pass_types["nop"](config=_mutation_config(config.nop, seed, offset))))
        offset += 1
    if "substitute" in mutations:
        selected.append(
            (
                "substitute",
                pass_types["substitute"](config=_mutation_config(config.substitution, seed, offset)),
            )
        )
        offset += 1
    if "register" in mutations:
        selected.append(
            (
                "register",
                pass_types["register"](config=_mutation_config(config.register, seed, offset)),
            )
        )
        offset += 1
    if "expand" in mutations:
        selected.append(
            (
                "expand",
                pass_types["expand"](config=_mutation_config(config.expansion, seed, offset)),
            )
        )
        offset += 1
    if "block" in mutations:
        selected.append(("block", pass_types["block"](config=_mutation_config(config.block, seed, offset))))
    return selected


def _mutation_pass_alias_map(
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> dict[str, str]:
    """Build aliases from short mutation names to concrete pass names."""
    aliases: dict[str, str] = {}
    all_mutations = list(set(PRODUCT_SUPPORT.stable_mutations) | set(PRODUCT_SUPPORT.experimental_mutations))
    for mutation_name, mutation_pass in _selected_mutation_passes(
        all_mutations,
        config,
        seed=seed,
    ):
        aliases[mutation_name] = mutation_pass.name
        aliases[mutation_pass.name] = mutation_pass.name
    return aliases


def _resolve_report_pass_filter(pass_name: str | None) -> str | None:
    """Resolve report-side pass filters using the product alias map."""
    if pass_name is None:
        return None
    alias_map = _mutation_pass_alias_map(_build_config(False, False), seed=None)
    return alias_map.get(pass_name.strip(), pass_name.strip())


def _limited_symbolic_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
) -> list[dict[str, str]]:
    """Return passes that declare symbolic support as limited."""
    limited = []
    for mutation_name, mutation_pass in _selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": str(symbolic_support.get("confidence", "unknown")),
                }
            )
    return limited


def _warn_or_block_limited_symbolic(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
    allow_limited_symbolic: bool,
) -> None:
    """Block symbolic mode for passes that declare limited symbolic support unless explicitly allowed."""
    limited = []
    for mutation_name, mutation_pass in _selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": symbolic_support.get("confidence", "unknown"),
                }
            )
    if not limited:
        return

    names = ", ".join(item["pass_name"] for item in limited)
    if not allow_limited_symbolic:
        console.print(f"[bold red]Error:[/bold red] symbolic validation is marked limited for: {names}")
        console.print("[yellow]Use structural/runtime, or pass --allow-limited-symbolic to continue anyway.[/yellow]")
        raise typer.Exit(2)

    console.print(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
    for item in limited:
        console.print(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")


def _resolve_min_severity(min_severity: str | None) -> tuple[str | None, int | None]:
    """Validate and normalize a minimum severity option."""
    if min_severity is None:
        return None, None
    if min_severity not in SEVERITY_ORDER:
        rprint(f"[bold red]Error:[/bold red] Invalid --min-severity: {min_severity}")
        raise typer.Exit(2)
    return min_severity, SEVERITY_ORDER[min_severity]


def _resolve_pass_severity_requirements(
    requirements: list[str] | None,
    *,
    alias_map: dict[str, str] | None = None,
) -> list[tuple[str, str, int]]:
    """Parse repeated PassName=severity requirements for mutate gating."""
    resolved: list[tuple[str, str, int]] = []
    aliases = {key.strip(): value for key, value in (alias_map or {}).items()}
    valid_pass_names = set(aliases.values())
    for item in requirements or []:
        if "=" not in item:
            console.print(
                f"[bold red]Error:[/bold red] Invalid --require-pass-severity: {item}. Expected PassName=severity"
            )
            raise typer.Exit(2)
        pass_name, severity = item.split("=", 1)
        pass_name = pass_name.strip()
        severity = severity.strip()
        pass_name = aliases.get(pass_name, pass_name)
        if not pass_name or severity not in SEVERITY_ORDER or (valid_pass_names and pass_name not in valid_pass_names):
            console.print(
                "[bold red]Error:[/bold red] "
                f"Invalid --require-pass-severity: {item}. "
                "Expected PassName=severity with severity in "
                "mismatch, without-coverage, bounded-only, clean, not-requested"
            )
            raise typer.Exit(2)
        resolved.append((pass_name, severity, SEVERITY_ORDER[severity]))
    return resolved


def _resolve_validation_mode(
    *,
    requested_mode: str,
    mutations: list[str],
    config: EngineConfig,
    seed: int | None,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
) -> tuple[str, dict[str, object] | None]:
    """Resolve requested vs effective validation mode for limited symbolic passes."""
    if requested_mode != "symbolic":
        return requested_mode, None

    limited = _limited_symbolic_passes(mutations, config, seed=seed)
    if not limited:
        return requested_mode, None

    if allow_limited_symbolic:
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
        for item in limited:
            console.print(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")
        return requested_mode, {
            "requested_mode": requested_mode,
            "effective_mode": requested_mode,
            "policy": "allow",
            "reason": "explicit-override",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-runtime":
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        console.print("[yellow]Degrading validation mode from symbolic to runtime.[/yellow]")
        return "runtime", {
            "requested_mode": requested_mode,
            "effective_mode": "runtime",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-structural":
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        console.print("[yellow]Degrading validation mode from symbolic to structural.[/yellow]")
        return "structural", {
            "requested_mode": requested_mode,
            "effective_mode": "structural",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    _warn_or_block_limited_symbolic(
        mutations,
        config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
    )
    return requested_mode, None


def _add_mutations(
    engine: MorphEngine,
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> None:
    for _mutation_name, mutation_pass in _selected_mutation_passes(
        mutations,
        config,
        seed=seed,
    ):
        engine.add_mutation(mutation_pass)


def _print_mutation_summary(result: dict[str, Any], output_path: Path | None = None) -> None:
    table = Table(title="Mutation Engine Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    requested_mode = result.get("requested_validation_mode", result.get("validation_mode", "off"))
    effective_mode = result.get("validation_mode", "off")
    table.add_row("Requested Validation", str(requested_mode))
    table.add_row("Effective Validation", str(effective_mode))
    table.add_row("Total Mutations", str(result.get("total_mutations", 0)))
    table.add_row("Passes Run", str(result.get("passes_run", 0)))
    table.add_row("Rolled Back Passes", str(result.get("rolled_back_passes", 0)))
    table.add_row("Discarded Mutations", str(result.get("discarded_mutations", 0)))
    table.add_row(
        "Validation Passed",
        "yes" if result.get("validation", {}).get("all_passed", False) else "no",
    )
    total_issues = result.get("validation", {}).get("total_issues", 0)
    table.add_row("Validation Issues", str(total_issues))
    for pass_name, pass_result in result.get("pass_results", {}).items():
        if "error" in pass_result:
            table.add_row(pass_name, f"[red]Error: {pass_result['error']}[/red]")
            continue
        rolled_back = ""
        if pass_result.get("rolled_back"):
            reason = pass_result.get("rollback_reason", "rollback")
            rolled_back = f" (rolled back: {reason})"
        table.add_row(
            pass_name,
            f"{pass_result.get('mutations_applied', 0)} mutations{rolled_back}",
        )

    console.print(table)
    if output_path is not None:
        console.print(f"\n[bold green]✓[/bold green] Binary saved to: {output_path}")


def _evaluate_and_write_gates(
    *,
    report_payload: dict[str, Any],
    report_path: Path | None,
    min_severity: str | None,
    min_severity_rank: int | None,
    pass_severity_requirements: list[tuple[str, str, int]] | None,
    report_format: str = "json",
) -> None:
    """Evaluate severity gates, write report, and exit on failure."""
    severity_rows = list(report_payload.get("summary", {}).get("symbolic_severity_by_pass", []))
    min_severity_passed = _severity_threshold_met(severity_rows, min_severity_rank)
    pass_requirements_ok = True
    pass_requirement_failures: list[str] = []
    if pass_severity_requirements:
        pass_requirements_ok, pass_requirement_failures = _pass_severity_requirements_met(
            severity_rows,
            pass_severity_requirements,
        )
    report_payload = _attach_gate_evaluation(
        report_payload,
        min_severity=min_severity,
        min_severity_passed=min_severity_passed,
        require_pass_severity=pass_severity_requirements or [],
        require_pass_severity_passed=pass_requirements_ok,
        require_pass_severity_failures=pass_requirement_failures,
    )
    if report_path is not None:
        if report_format.lower() == "sarif":
            from r2morph.reporting.sarif_formatter import format_as_sarif

            sarif = format_as_sarif(
                report_payload.get("mutations", []),
                report_payload.get("validation", {}).get("results", []),
                report_payload.get("input", {}).get("path", ""),
            )
            report_path.write_text(sarif.to_json(), encoding="utf-8")
        else:
            report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    if min_severity is not None and not min_severity_passed:
        console.print(f"[bold yellow]Severity gate failed:[/bold yellow] min_severity={min_severity}")
        raise typer.Exit(1)
    if min_severity is not None:
        console.print(f"[cyan]Severity gate passed:[/cyan] min_severity={min_severity}")
    if pass_severity_requirements and not pass_requirements_ok:
        console.print("[bold yellow]Pass severity gate failed:[/bold yellow] " + ", ".join(pass_requirement_failures))
        raise typer.Exit(1)
    if pass_severity_requirements:
        console.print(
            "[cyan]Pass severity gate passed:[/cyan] "
            + ", ".join(f"{pn}<={s}" for pn, s, _ in pass_severity_requirements)
        )


def _run_simple_mode(
    input_file: Path,
    output_file: Path | None,
    *,
    aggressive: bool,
    force: bool,
    seed: int | None,
    verbose: bool,
    debug: bool,
) -> None:
    setup_logging("DEBUG" if (verbose or debug) else "INFO")

    if output_file is None:
        output_file = input_file.parent / f"{input_file.stem}_morphed{input_file.suffix}"

    mode_str = "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    force_str = " [bold yellow](FORCE)[/bold yellow]" if force else ""
    console.print(f"[bold green]r2morph - Simple Mode ({mode_str}{force_str})[/bold green]")
    console.print(f"Input:  {input_file}")
    console.print(f"Output: {output_file}")
    console.print("Applying stable mutations: [cyan]nop, substitute, register[/cyan]\n")

    with console.status("[bold green]Transforming binary..."):
        with MorphEngine(config={"seed": seed, "requested_mutations": ["nop", "substitute", "register"]}) as engine:
            engine.load_binary(input_file).analyze()
            config = _build_config(aggressive, force)
            _add_mutations(engine, ["nop", "substitute", "register"], config, seed=seed)

            report_path = output_file.parent / f"{output_file.stem}.report.json"
            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
                report_path=report_path,
                seed=seed,
            )

            engine.save(output_file)

        _print_mutation_summary(result, output_file)
        console.print(f"[cyan]Report:[/cyan] {report_path}")


def _run_morph_workflow(
    *,
    binary: Path,
    output: Path,
    mutations: list[str],
    aggressive: bool,
    force: bool,
    validation_mode: str,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
    rollback_policy: str,
    report: Path | None,
    runtime_corpus: Path | None,
    runtime_compare_files: bool,
    runtime_normalize_whitespace: bool,
    runtime_timeout: int,
    min_severity: str | None,
    require_pass_severity: list[str] | None,
    seed: int | None,
    report_format: str = "json",
) -> None:
    """Execute the mutation pipeline, validate, and write results."""
    mode_str = "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    console.print(f"[bold green]Starting mutation pipeline ({mode_str})[/bold green]")
    console.print(f"Input:  {binary}")
    console.print(f"Output: {output}")
    console.print(f"Mutations: {', '.join(mutations)}\n")

    experimental = [m for m in mutations if is_experimental_mutation(m)]
    _warn_experimental_mutations(experimental)
    _warn_experimental_validation_mode(validation_mode)
    _, min_severity_rank = _resolve_min_severity(min_severity)
    config = _build_config(aggressive, force)
    pass_severity_requirements = _resolve_pass_severity_requirements(
        require_pass_severity,
        alias_map=_mutation_pass_alias_map(config, seed=seed),
    )
    effective_validation_mode, validation_policy = _resolve_validation_mode(
        requested_mode=validation_mode,
        mutations=mutations,
        config=config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
    )

    with console.status("[bold green]Transforming binary..."):
        try:
            with MorphEngine(
                config={
                    "seed": seed,
                    "requested_mutations": list(mutations),
                    "experimental_mutations": experimental,
                    "requested_validation_mode": validation_mode,
                    "effective_validation_mode": effective_validation_mode,
                    "validation_policy": validation_policy,
                }
            ) as engine:
                engine.load_binary(binary).analyze()
                _add_mutations(engine, mutations, config, seed=seed)

                runtime_validator = None
                if effective_validation_mode == "runtime":
                    runtime_validator = _build_runtime_validator(
                        timeout=runtime_timeout,
                        corpus=runtime_corpus,
                        compare_files=runtime_compare_files,
                        normalize_whitespace=runtime_normalize_whitespace,
                    )

                report_ext = ".sarif" if report_format.lower() == "sarif" else ".report.json"
                report_path = report or output.parent / f"{output.stem}{report_ext}"
                result = engine.run(
                    validation_mode=effective_validation_mode,
                    rollback_policy=rollback_policy,
                    checkpoint_per_mutation=rollback_policy == "skip-invalid-mutation",
                    runtime_validator=runtime_validator,
                    runtime_validate_per_pass=effective_validation_mode == "runtime",
                    report_path=report_path,
                    seed=seed,
                )
                engine.save(output)

            _print_mutation_summary(result, output)
            console.print(f"[cyan]Report:[/cyan] {report_path}")
            report_payload = engine.build_report(result)
            _evaluate_and_write_gates(
                report_payload=report_payload,
                report_path=report_path,
                min_severity=min_severity,
                min_severity_rank=min_severity_rank,
                pass_severity_requirements=pass_severity_requirements,
                report_format=report_format,
            )
        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)
