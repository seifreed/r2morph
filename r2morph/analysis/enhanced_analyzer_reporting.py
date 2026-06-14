from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)


def display_detection_results(
    console: Console,
    binary_path: Path,
    detection_result: Any,
    custom_vm: dict[str, Any],
    layers: dict[str, Any],
    metamorphic: dict[str, Any],
    verbose: bool = False,
) -> None:
    if detection_result is None:
        return

    table = Table(title=f"Enhanced Analysis: {binary_path.name}")
    table.add_column("Detection", style="cyan")
    table.add_column("Result", style="green")

    table.add_row("Packer Detected", detection_result.packer_detected.value if detection_result.packer_detected else "None")
    table.add_row("VM Protection", "Yes" if detection_result.vm_detected else "No")
    table.add_row("Anti-Analysis", "Yes" if detection_result.anti_analysis_detected else "No")
    table.add_row("Control Flow Flattening", "Yes" if detection_result.control_flow_flattened else "No")
    table.add_row("MBA Detected", "Yes" if detection_result.mba_detected else "No")
    table.add_row("Confidence Score", f"{detection_result.confidence_score:.2f}")
    table.add_row("Techniques Found", str(len(detection_result.obfuscation_techniques)))

    console.print(table)
    console.print("\n[bold cyan]Extended Detection:[/bold cyan]")

    if custom_vm.get("detected"):
        vm_type = custom_vm.get("vm_type", "unknown")
        confidence = custom_vm.get("confidence", 0)
        console.print(f"  Custom Virtualizer: {vm_type} ({confidence:.2f})")

    if layers.get("layers_detected", 0) > 0:
        layers_count = layers["layers_detected"]
        console.print(f"  Packing Layers: {layers_count}")

    if metamorphic.get("detected"):
        poly_ratio = metamorphic.get("polymorphic_ratio", 0)
        console.print(f"  Metamorphic Engine: {poly_ratio:.1%}")

    if detection_result.obfuscation_techniques:
        console.print("\n[bold cyan]Obfuscation Techniques:[/bold cyan]")
        for i, technique in enumerate(detection_result.obfuscation_techniques[:10], 1):
            console.print(f"  {i}. {technique}")
        if len(detection_result.obfuscation_techniques) > 10:
            remaining = len(detection_result.obfuscation_techniques) - 10
            console.print(f"  ... and {remaining} more")

    if verbose:
        console.print("\n[dim]Verbose detection details enabled[/dim]")
        console.print(
            f"  Detection details: {detection_result.to_dict() if hasattr(detection_result, 'to_dict') else detection_result}"
        )


def display_analysis_results(console: Console, results: Any) -> None:
    results_dict: dict[str, Any] = {}

    if results.cfo_reduction > 0:
        results_dict["cfo_reduction"] = results.cfo_reduction

    if results.iterative_result:
        results_dict["iterative_result"] = results.iterative_result

    if results.vm_handlers > 0:
        results_dict["vm_handlers"] = results.vm_handlers

    if results.rewrite_output:
        results_dict["rewrite_output"] = results.rewrite_output

    if results_dict:
        console.print("\n[bold cyan]Advanced Analysis Results:[/bold cyan]")
        for key, value in results_dict.items():
            console.print(f"  {key}: {value}")


def display_recommendations(console: Console, detection_result: Any, layers: dict[str, Any]) -> None:
    if detection_result is None:
        return

    console.print("\n[bold cyan]Recommendations:[/bold cyan]")

    if detection_result.vm_detected:
        console.print("  - VM protection detected - use --devirt --iterative for comprehensive analysis")

    if detection_result.anti_analysis_detected:
        console.print("  - Anti-analysis techniques detected - use --bypass --dynamic")

    if detection_result.mba_detected:
        console.print("  - MBA expressions detected - use --iterative for expression simplification")

    if detection_result.control_flow_flattened:
        console.print("  - Control flow flattening detected - use --symbolic --devirt")

    layers_detected = layers.get("layers_detected", 0)
    if layers_detected > 1:
        console.print("  - Multiple packing layers detected - iterative unpacking recommended")

    if not any(
        [
            detection_result.vm_detected,
            detection_result.anti_analysis_detected,
            detection_result.mba_detected,
            detection_result.control_flow_flattened,
        ]
    ):
        console.print("  - Binary appears lightly obfuscated - standard analysis may suffice")


def generate_report(detector: Any, binary: Any, results: Any, console: Console) -> dict[str, Any]:
    console.print("\n[bold yellow]Generating comprehensive report...[/bold yellow]")
    report: dict[str, Any] = detector.get_comprehensive_report(binary)
    results.report = report
    return report


def save_report(output_dir: Path, report: dict[str, Any], console: Console) -> Path:
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "analysis_report.json"

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str, ensure_ascii=False)

    console.print(f"Report saved to {report_path}")
    return report_path
