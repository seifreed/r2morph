"""Shared CLI workflow helpers for mutation and report filter resolution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console

from r2morph.cli_workflow_output import GateOutputOptions, evaluate_and_write_gates, print_mutation_summary
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
from r2morph.cli_workflow_validation_policy import ValidationModeRequest
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from r2morph.core.support import is_experimental_mutation
from r2morph.utils.logging import setup_logging
from r2morph.validation import BinaryValidator
from r2morph.validation.validator_runtime import RuntimeComparisonConfig

console = Console()


@dataclass(frozen=True)
class SimpleModeRequest:
    input_file: Path
    output_file: Path | None
    aggressive: bool
    force: bool
    seed: int | None
    verbose: bool
    debug: bool


@dataclass(frozen=True)
class MorphWorkflowRequest:
    binary: Path
    output: Path
    mutations: list[str]
    aggressive: bool
    force: bool
    validation_mode: str
    allow_limited_symbolic: bool
    limited_symbolic_policy: str
    rollback_policy: str
    report: Path | None
    runtime_corpus: Path | None
    runtime_compare_files: bool
    runtime_normalize_whitespace: bool
    runtime_timeout: int
    min_severity: str | None
    require_pass_severity: list[str] | None
    seed: int | None
    report_format: str = "json"


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


def _run_simple_mode(request: SimpleModeRequest) -> None:
    setup_logging("DEBUG" if (request.verbose or request.debug) else "INFO")

    output_file = request.output_file
    if output_file is None:
        output_file = request.input_file.parent / f"{request.input_file.stem}_morphed{request.input_file.suffix}"

    mode_str = "[bold red]AGGRESSIVE[/bold red]" if request.aggressive else "[bold green]STANDARD[/bold green]"
    force_str = " [bold yellow](FORCE)[/bold yellow]" if request.force else ""
    console.print(f"[bold green]r2morph - Simple Mode ({mode_str}{force_str})[/bold green]")
    console.print(f"Input:  {request.input_file}")
    console.print(f"Output: {output_file}")
    console.print("Applying stable mutations: [cyan]nop, substitute, register[/cyan]\n")

    with console.status("[bold green]Transforming binary..."):
        with MorphEngine(
            config={"seed": request.seed, "requested_mutations": ["nop", "substitute", "register"]}
        ) as engine:
            engine.load_binary(request.input_file).analyze()
            config = build_config(request.aggressive, request.force)
            _add_mutations(engine, ["nop", "substitute", "register"], config, seed=request.seed)

            report_path = output_file.parent / f"{output_file.stem}.report.json"
            result = engine.run(
                EngineRunOptions(
                    validation_mode="structural",
                    rollback_policy="skip-invalid-pass",
                    report_path=report_path,
                    seed=request.seed,
                )
            )

            engine.save(output_file)

        print_mutation_summary(result, output_file)
        console.print(f"[cyan]Report:[/cyan] {report_path}")


def _run_morph_workflow(request: MorphWorkflowRequest) -> None:
    """Execute the mutation pipeline, validate, and write results."""
    mode_str = "[bold red]AGGRESSIVE[/bold red]" if request.aggressive else "[bold green]STANDARD[/bold green]"
    console.print(f"[bold green]Starting mutation pipeline ({mode_str})[/bold green]")
    console.print(f"Input:  {request.binary}")
    console.print(f"Output: {request.output}")
    console.print(f"Mutations: {', '.join(request.mutations)}\n")

    experimental = [mutation for mutation in request.mutations if is_experimental_mutation(mutation)]
    _warn_experimental_mutations(experimental)
    warn_experimental_validation_mode(request.validation_mode)
    _, min_severity_rank = resolve_min_severity(request.min_severity)
    config = build_config(request.aggressive, request.force)
    pass_severity_requirements = resolve_pass_severity_requirements(
        request.require_pass_severity,
        alias_map=mutation_pass_alias_map(config, seed=request.seed),
    )
    effective_validation_mode, validation_policy = resolve_validation_mode(
        ValidationModeRequest(
            requested_mode=request.validation_mode,
            mutations=request.mutations,
            config=config,
            seed=request.seed,
            allow_limited_symbolic=request.allow_limited_symbolic,
            limited_symbolic_policy=request.limited_symbolic_policy,
        )
    )

    with console.status("[bold green]Transforming binary..."):
        try:
            with MorphEngine(
                config={
                    "seed": request.seed,
                    "requested_mutations": list(request.mutations),
                    "experimental_mutations": experimental,
                    "requested_validation_mode": request.validation_mode,
                    "effective_validation_mode": effective_validation_mode,
                    "validation_policy": validation_policy,
                }
            ) as engine:
                engine.load_binary(request.binary).analyze()
                _add_mutations(engine, request.mutations, config, seed=request.seed)

                runtime_validator = None
                if effective_validation_mode == "runtime":
                    runtime_validator = _build_runtime_validator(
                        timeout=request.runtime_timeout,
                        corpus=request.runtime_corpus,
                        compare_files=request.runtime_compare_files,
                        normalize_whitespace=request.runtime_normalize_whitespace,
                    )

                report_ext = ".sarif" if request.report_format.lower() == "sarif" else ".report.json"
                report_path = request.report or request.output.parent / f"{request.output.stem}{report_ext}"
                result = engine.run(
                    EngineRunOptions(
                        validation_mode=effective_validation_mode,
                        rollback_policy=request.rollback_policy,
                        checkpoint_per_mutation=request.rollback_policy == "skip-invalid-mutation",
                        runtime_validator=runtime_validator,
                        runtime_validate_per_pass=effective_validation_mode == "runtime",
                        report_path=report_path,
                        seed=request.seed,
                    )
                )
                engine.save(request.output)

            print_mutation_summary(result, request.output)
            console.print(f"[cyan]Report:[/cyan] {report_path}")
            report_payload = engine.build_report(result)
            evaluate_and_write_gates(
                report_payload,
                GateOutputOptions(
                    report_path=report_path,
                    min_severity=request.min_severity,
                    min_severity_rank=min_severity_rank,
                    pass_severity_requirements=pass_severity_requirements,
                    report_format=request.report_format,
                ),
            )
        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1) from e
