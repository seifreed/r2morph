"""Shared CLI workflow helpers for mutation and report filter resolution."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from r2morph.cli_workflow_output import evaluate_and_write_gates, print_mutation_summary
from r2morph.cli_workflow_selection import (
    build_config,
    mutation_pass_alias_map,
    selected_mutation_passes,
)
from r2morph.cli_workflow_validation import (
    resolve_min_severity,
    resolve_pass_severity_requirements,
    resolve_validation_mode,
    warn_experimental_validation_mode,
)
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.core.support import is_experimental_mutation
from r2morph.utils.logging import setup_logging
from r2morph.validation import BinaryValidator
from r2morph.validation.validator import RuntimeComparisonConfig

console = Console()


def _warn_experimental_mutations(mutations: list[str]) -> None:
    if not mutations:
        return
    console.print(f"[yellow]Experimental mutations selected:[/yellow] {', '.join(mutations)}")
    console.print("[yellow]These passes are outside the stable core and validation coverage is best-effort.[/yellow]")


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


def _resolve_report_pass_filter(pass_name: str | None) -> str | None:
    """Resolve report-side pass filters using the product alias map."""
    if pass_name is None:
        return None
    alias_map = mutation_pass_alias_map(build_config(False, False), seed=None)
    return alias_map.get(pass_name.strip(), pass_name.strip())




def _add_mutations(
    engine: MorphEngine,
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> None:
    for _mutation_name, mutation_pass in selected_mutation_passes(
        mutations,
        config,
        seed=seed,
    ):
        engine.add_mutation(mutation_pass)


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
            config = build_config(aggressive, force)
            _add_mutations(engine, ["nop", "substitute", "register"], config, seed=seed)

            report_path = output_file.parent / f"{output_file.stem}.report.json"
            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
                report_path=report_path,
                seed=seed,
            )

            engine.save(output_file)

        print_mutation_summary(result, output_file)
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
    warn_experimental_validation_mode(validation_mode)
    _, min_severity_rank = resolve_min_severity(min_severity)
    config = build_config(aggressive, force)
    pass_severity_requirements = resolve_pass_severity_requirements(
        require_pass_severity,
        alias_map=mutation_pass_alias_map(config, seed=seed),
    )
    effective_validation_mode, validation_policy = resolve_validation_mode(
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

            print_mutation_summary(result, output)
            console.print(f"[cyan]Report:[/cyan] {report_path}")
            report_payload = engine.build_report(result)
            evaluate_and_write_gates(
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
