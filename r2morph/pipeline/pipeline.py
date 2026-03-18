"""
Pipeline for orchestrating multiple transformation passes.
"""

import logging
import time
from copy import deepcopy
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


def _summarize_validation_regions(validation_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Group validation issues by region to keep reports compact and machine-readable."""
    grouped: dict[tuple[int, int], dict[str, Any]] = {}
    for issue in validation_payload.get("issues", []):
        address_range = issue.get("address_range")
        if not address_range or len(address_range) != 2:
            continue
        key = (int(address_range[0]), int(address_range[1]))
        entry = grouped.setdefault(
            key,
            {
                "address_range": [key[0], key[1]],
                "validators": [],
                "messages": [],
                "severities": [],
            },
        )
        validator = issue.get("validator")
        if validator and validator not in entry["validators"]:
            entry["validators"].append(validator)
        message = issue.get("message")
        if message and message not in entry["messages"]:
            entry["messages"].append(message)
        severity = issue.get("severity")
        if severity and severity not in entry["severities"]:
            entry["severities"].append(severity)
    return sorted(grouped.values(), key=lambda item: tuple(item["address_range"]))


class Pipeline:
    """
    Manages and executes a sequence of mutation passes.

    The pipeline runs mutation passes in order, allowing each pass
    to transform the binary independently.

    Attributes:
        passes: List of mutation passes to execute
    """

    def __init__(self):
        """Initialize an empty pipeline."""
        self.passes: list[MutationPass] = []

    def add_pass(self, mutation_pass: MutationPass) -> "Pipeline":
        """
        Add a mutation pass to the pipeline.

        Args:
            mutation_pass: Mutation pass to add

        Returns:
            Self for method chaining
        """
        self.passes.append(mutation_pass)
        logger.debug(f"Added pass: {mutation_pass.name}")
        return self

    def remove_pass(self, pass_name: str) -> bool:
        """
        Remove a pass by name.

        Args:
            pass_name: Name of the pass to remove

        Returns:
            True if pass was removed, False if not found
        """
        for i, p in enumerate(self.passes):
            if p.name == pass_name:
                self.passes.pop(i)
                logger.debug(f"Removed pass: {pass_name}")
                return True
        return False

    def clear(self):
        """Clear all passes from the pipeline."""
        self.passes.clear()
        logger.debug("Pipeline cleared")

    def run(
        self,
        binary: Binary,
        *,
        session: Any | None = None,
        validation_manager: Any | None = None,
        runtime_validator: Any | None = None,
        runtime_validate_per_pass: bool = False,
        rollback_policy: str = "skip-invalid-pass",
        checkpoint_per_mutation: bool = False,
    ) -> dict[str, Any]:
        """
        Execute all passes in the pipeline on the given binary.

        Args:
            binary: Binary instance to transform

        Returns:
            Dictionary with statistics from all passes
        """
        if not self.passes:
            logger.warning("Pipeline is empty, no transformations will be applied")
            return {"passes_run": 0, "total_mutations": 0}

        logger.info(f"Running pipeline with {len(self.passes)} passes")

        results = {
            "passes_run": 0,
            "total_mutations": 0,
            "rolled_back_passes": 0,
            "failed_passes": 0,
            "discarded_mutations": 0,
            "discarded_mutations_detail": [],
            "pass_results": {},
            "mutations": [],
            "validation": {
                "passes": [],
                "all_passed": True,
                "failed_passes": [],
                "total_issues": 0,
                "runtime_passes": [],
                "symbolic": {
                    "requested": False,
                    "proven": False,
                    "supported_passes": [],
                    "fallback_passes": [],
                    "statuses": [],
                },
            },
            "rollback_policy": rollback_policy,
        }

        for i, mutation_pass in enumerate(self.passes):
            logger.info(f"Running pass {i + 1}/{len(self.passes)}: {mutation_pass.name}")
            checkpoint_name = None
            if session is not None:
                checkpoint_name = f"pass_{i + 1}_{mutation_pass.name.lower()}"
                session.checkpoint(checkpoint_name, f"Before pass {mutation_pass.name}")
            mutation_pass.bind_runtime(
                validation_manager=validation_manager,
                session=session,
                rollback_policy=rollback_policy,
                checkpoint_per_mutation=checkpoint_per_mutation,
            )

            try:
                pass_started = time.perf_counter()
                pass_result = mutation_pass.run(binary)
                pass_result.setdefault("pass_name", mutation_pass.name)
                pass_result.setdefault("mutations", [])
                pass_result["execution_time_seconds"] = round(time.perf_counter() - pass_started, 6)
                pass_result["support"] = mutation_pass.get_support().to_dict()
                if session is not None and checkpoint_name is not None:
                    previous_binary = next(
                        (
                            cp.binary_path
                            for cp in session.list_checkpoints()
                            if cp.name == checkpoint_name
                        ),
                        None,
                    )
                    if previous_binary is not None:
                        pass_result["previous_binary_path"] = str(previous_binary)
                pass_result["diff_summary"] = {
                    "mutations": len(pass_result["mutations"]),
                    "changed_bytes": sum(
                        int(mutation.get("byte_diff_count", 0))
                        for mutation in pass_result["mutations"]
                    ),
                    "changed_regions": [
                        [mutation["start_address"], mutation["end_address"]]
                        for mutation in pass_result["mutations"]
                    ],
                    "region_details": [
                        {
                            "address_range": [
                                mutation["start_address"],
                                mutation["end_address"],
                            ],
                            "mutation_kind": mutation.get("mutation_kind", "unknown"),
                            "byte_diff_count": int(mutation.get("byte_diff_count", 0)),
                            "function_address": mutation.get("function_address"),
                        }
                        for mutation in pass_result["mutations"]
                    ],
                    "mutation_kinds": sorted(
                        {
                            mutation.get("mutation_kind", "unknown")
                            for mutation in pass_result["mutations"]
                        }
                    ),
                }
                validation_result = None
                runtime_pass_result = None
                if validation_manager is not None and pass_result["mutations"]:
                    validation_result = validation_manager.validate_pass(binary, pass_result)
                    pass_result["validation"] = validation_result.to_dict()
                    results["validation"]["passes"].append(validation_result.to_dict())
                    results["validation"]["total_issues"] += len(validation_result.issues)
                    symbolic = results["validation"]["symbolic"]
                    if validation_result.metadata.get("symbolic_requested"):
                        symbolic["requested"] = True
                        status = validation_result.metadata.get("symbolic_status", "unknown")
                        symbolic["statuses"].append(
                            {
                                "pass_name": mutation_pass.name,
                                "status": status,
                                "reason": validation_result.metadata.get("symbolic_reason", ""),
                            }
                        )
                        if status in {
                            "precheck-passed",
                            "bounded-step-passed",
                            "bounded-step-known-equivalence",
                            "bounded-step-observables-match",
                            "shellcode-observables-match",
                            "real-binary-observables-match",
                        }:
                            symbolic["supported_passes"].append(mutation_pass.name)
                        else:
                            symbolic["fallback_passes"].append(mutation_pass.name)
                        symbolic["proven"] = symbolic["proven"] or bool(
                            validation_result.metadata.get("symbolic_proven", False)
                        )
                    if not validation_result.passed:
                        results["validation"]["all_passed"] = False
                        results["validation"]["failed_passes"].append(mutation_pass.name)
                        discarded = pass_result.get(
                            "mutations_applied", len(pass_result["mutations"])
                        )
                        if session is not None and checkpoint_name is not None:
                            session.rollback_to(checkpoint_name)
                            binary.reload()
                        if rollback_policy == "fail-fast":
                            raise RuntimeError(f"Validation failed for pass {mutation_pass.name}")
                        pass_result["rolled_back"] = True
                        pass_result["rollback_reason"] = "validation_failed"
                        pass_result["status"] = "rolled_back"
                        pass_result["discarded_mutations"] = discarded
                        discarded_records = []
                        for mutation in pass_result["mutations"]:
                            discarded_mutation = deepcopy(mutation)
                            discarded_mutation["status"] = "discarded"
                            discarded_mutation.setdefault("metadata", {})
                            discarded_mutation["metadata"]["discard_reason"] = "validation_failed"
                            discarded_mutation["metadata"]["discarded_by_pass"] = mutation_pass.name
                            discarded_records.append(discarded_mutation)
                        pass_result["discarded_mutations_detail"] = discarded_records
                        pass_result["mutations_applied"] = 0
                        pass_result["mutations"] = []
                        results["rolled_back_passes"] += 1
                        results["discarded_mutations"] += discarded
                        results["discarded_mutations_detail"].extend(discarded_records)
                    else:
                        pass_result["rolled_back"] = False
                        pass_result["discarded_mutations"] = 0
                        pass_result["discarded_mutations_detail"] = []
                        pass_result["status"] = "applied"
                    pass_result["diff_summary"]["structural_regions"] = (
                        _summarize_validation_regions(validation_result.to_dict())
                    )
                    pass_result["diff_summary"]["structural_issue_count"] = len(
                        validation_result.issues
                    )

                if (
                    runtime_validate_per_pass
                    and runtime_validator is not None
                    and session is not None
                    and checkpoint_name is not None
                    and pass_result.get("mutations")
                ):
                    previous_binary = next(
                        (
                            cp.binary_path
                            for cp in session.list_checkpoints()
                            if cp.name == checkpoint_name
                        ),
                        None,
                    )
                    if previous_binary is not None:
                        runtime_pass_result = runtime_validator.validate(
                            previous_binary, binary.path
                        )
                        pass_result.setdefault("validation", {})
                        pass_result["validation"]["runtime"] = runtime_pass_result.to_dict()
                        results["validation"]["runtime_passes"].append(
                            {
                                "pass_name": mutation_pass.name,
                                **runtime_pass_result.to_dict(),
                            }
                        )
                        if not runtime_pass_result.passed and not pass_result.get(
                            "rolled_back", False
                        ):
                            results["validation"]["all_passed"] = False
                            results["validation"]["failed_passes"].append(mutation_pass.name)
                            discarded = pass_result.get(
                                "mutations_applied", len(pass_result["mutations"])
                            )
                            session.rollback_to(checkpoint_name)
                            binary.reload()
                            if rollback_policy == "fail-fast":
                                raise RuntimeError(
                                    f"Runtime validation failed for pass {mutation_pass.name}"
                                )
                            pass_result["rolled_back"] = True
                            pass_result["rollback_reason"] = "runtime_validation_failed"
                            pass_result["status"] = "rolled_back"
                            pass_result["discarded_mutations"] = discarded
                            discarded_records = []
                            for mutation in pass_result["mutations"]:
                                discarded_mutation = deepcopy(mutation)
                                discarded_mutation["status"] = "discarded"
                                discarded_mutation.setdefault("metadata", {})
                                discarded_mutation["metadata"]["discard_reason"] = (
                                    "runtime_validation_failed"
                                )
                                discarded_mutation["metadata"]["discarded_by_pass"] = (
                                    mutation_pass.name
                                )
                                discarded_records.append(discarded_mutation)
                            pass_result["discarded_mutations_detail"] = discarded_records
                            pass_result["mutations_applied"] = 0
                            pass_result["mutations"] = []
                            results["rolled_back_passes"] += 1
                            results["discarded_mutations"] += discarded
                            results["discarded_mutations_detail"].extend(discarded_records)

                if not pass_result.get("rolled_back", False):
                    results["passes_run"] += 1
                    results["total_mutations"] += pass_result.get("mutations_applied", 0)
                    results["mutations"].extend(pass_result.get("mutations", []))
                    if session is not None and hasattr(session, "mutations_count"):
                        session.mutations_count += pass_result.get("mutations_applied", 0)

                results["pass_results"][mutation_pass.name] = pass_result

                status_msg = "rolled back" if pass_result.get("rolled_back", False) else "complete"
                logger.info(
                    f"Pass {mutation_pass.name} {status_msg}: "
                    f"{pass_result.get('mutations_applied', 0)} mutations"
                )
            except Exception as e:
                logger.error(f"Pass {mutation_pass.name} failed: {e}")
                if session is not None and checkpoint_name is not None:
                    session.rollback_to(checkpoint_name)
                    binary.reload()
                results["validation"]["all_passed"] = False
                results["failed_passes"] += 1
                results["validation"]["failed_passes"].append(mutation_pass.name)
                results["pass_results"][mutation_pass.name] = {
                    "error": str(e),
                    "rolled_back": checkpoint_name is not None,
                    "rollback_reason": "pass_error",
                    "status": "failed",
                    "discarded_mutations": 0,
                    "discarded_mutations_detail": [],
                    "support": mutation_pass.get_support().to_dict(),
                }
                if rollback_policy == "fail-fast":
                    mutation_pass.clear_runtime()
                    raise
            finally:
                mutation_pass.clear_runtime()

        logger.info(f"Pipeline complete: {results['total_mutations']} total mutations")
        return results

    def get_pass_names(self) -> list[str]:
        """Get list of pass names in the pipeline."""
        return [p.name for p in self.passes]

    def __len__(self) -> int:
        """Get number of passes in pipeline."""
        return len(self.passes)

    def __repr__(self) -> str:
        return f"<Pipeline with {len(self.passes)} passes>"
