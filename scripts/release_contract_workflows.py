"""CI and release workflow checks for the release contract."""

from __future__ import annotations

import tomllib

try:
    from scripts.release_contract_common import (
        MINIMUM_COVERAGE_PERCENT,
        REQUIRED_CI_JOBS,
        ROOT,
    )
except ModuleNotFoundError:
    from release_contract_common import (
        MINIMUM_COVERAGE_PERCENT,
        REQUIRED_CI_JOBS,
        ROOT,
    )


def _check_ci_contract() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    cross_platform_job = workflow.split("  cross-platform-tests:", 1)[1].split("  package-smoke:", 1)[0]
    for job in REQUIRED_CI_JOBS:
        if f"\n  {job}:" not in workflow:
            raise ValueError(f"CI is missing required job: {job}")
    for fragment in (
        "python -m build",
        "dist/*.whl",
        "import r2morph",
        "r2morph --version",
        "--no-cov --tb=short",
        "python -W error -m pytest",
        "windows-latest",
        "runner.os == 'Windows'",
        "Install radare2 (Windows)",
        '"https://github.com/radareorg/radare2/releases/download/$version/$archiveName"',
        '"913e7d95e7458226a5e783240877f2c1d405398ab38ba176ce9b12e046e31f34"',
        '& ".github/scripts/download_verified_artifact.ps1" -Url $url -Output $archive -Sha256 $expectedSha256',
        "Expand-Archive -Path $archive -DestinationPath $destination -Force",
        "$env:GITHUB_PATH",
        "git build-essential clang gcc-arm-linux-gnueabihf qemu-user",
        "python -m pip install --force-reinstall dist/*.whl",
        'tempfile.mkdtemp(prefix="r2morph-cross-platform-wheel-")',
        'for name in ("tests", "fixtures", "scripts", "docs", "README.md", "pyproject.toml")',
        'subprocess.run([sys.executable, "-c", "import r2morph; print(r2morph.__file__)"]',
        '"tests/unit/test_circular_imports.py"',
        '"tests/unit/test_cli_basic_commands.py::test_cli_version_function"',
        '"tests/unit/test_public_surface_contract.py"',
        "python scripts/support_matrix.py --check docs/support-matrix.json",
    ):
        if fragment not in workflow:
            raise ValueError(f"CI is missing wheel smoke contract: {fragment}")
    for fragment in (
        "Install build backend for cross-platform wheel smoke",
        'run: python -m pip install "build>=1.2.0"',
        "shell: bash",
        "python -m build",
        "python -m pip install --force-reinstall dist/*.whl",
        "import platform",
        'tempfile.mkdtemp(prefix="r2morph-cross-platform-wheel-")',
        "test_targets = [",
        "x64_assembler_targets = [",
        'if platform.machine().lower() in {"amd64", "x86_64"}:',
        '"tests/unit/test_public_surface_contract.py"',
        '"tests/unit/test_pe_handler_parsing_contract.py"',
        '"tests/unit/test_pe_handler_struct_parse.py"',
        '"tests/unit/test_macho_parse_basic.py"',
        '"tests/unit/test_instruction_substitution_arm64_contract.py"',
        '"tests/unit/test_package_data.py"',
        '"tests/unit/test_support_matrix_contract.py"',
        '"tests/unit/test_benchmark_metrics_contract.py"',
        '"tests/unit/test_benchmark_runners_contract.py"',
        '"tests/unit/test_benchmark_reporting_summary_contract.py"',
        '"tests/unit/test_benchmark_reporting_breakdown_contract.py"',
        '"tests/unit/test_benchmark_reporting_text_contract.py"',
        '"tests/unit/test_benchmark_reporting_io_contract.py"',
        '"tests/unit/test_benchmark_reporting_exports_contract.py"',
        '"tests/unit/test_performance_regression_suite_contract.py"',
        '"tests/unit/test_performance_regression_measurement_contract.py"',
        '"tests/unit/test_performance_regression_execution_contract.py"',
        '"tests/unit/test_performance_regression_models_contract.py"',
        '"tests/unit/test_performance_regression_metadata_contract.py"',
        '"tests/unit/test_performance_regression_comparison_contract.py"',
        '"tests/unit/test_performance_regression_storage_contract.py"',
        '"tests/unit/test_pass_dependency_catalogs_contract.py"',
        '"tests/unit/test_evasion_scorer_helpers_contract.py"',
        '"tests/unit/test_enhanced_analyzer_reporting_contract.py"',
        '"tests/unit/test_mutation_annotator_instruction_contract.py"',
        '"tests/unit/test_code_virtualization_memory_widths.py"',
        '"tests/unit/test_code_virtualization_call_abi.py"',
        '"tests/unit/test_code_virtualization_tls.py"',
        '"tests/unit/test_code_virtualization_static_dataflow.py"',
        '"tests/unit/test_code_virtualization_diagnostics.py"',
        '"tests/unit/test_code_virtualization_fp_indexed_shapes.py"',
        '"tests/unit/test_code_virtualization_avx256.py"',
    ):
        if fragment not in cross_platform_job:
            raise ValueError(f"cross-platform CI is missing installed-wheel contract: {fragment}")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pytest_options = project["tool"]["pytest"]["ini_options"]
    if pytest_options["filterwarnings"] != ["error"]:
        raise ValueError("pytest warnings must remain errors")
    if project["tool"]["coverage"]["report"]["fail_under"] < MINIMUM_COVERAGE_PERCENT:
        raise ValueError("coverage gate must be at least 75 percent")


def _check_windows_download_contract() -> None:
    root = ROOT / ".github"
    script = (root / "scripts" / "download_verified_artifact.ps1").read_text(encoding="utf-8")
    for workflow_name in ("ci.yml", "differential-corpus.yml"):
        workflow = (root / "workflows" / workflow_name).read_text(encoding="utf-8")
        if (
            '& ".github/scripts/download_verified_artifact.ps1" -Url $url -Output $archive -Sha256 $expectedSha256'
            not in workflow
        ):
            raise ValueError(f"{workflow_name} must use the verified Windows artifact downloader")
    for fragment in (
        "$maximumAttempts = 3",
        "Invoke-WebRequest -Uri $Url -OutFile $partialOutput -TimeoutSec 120",
        "$statusCode -in @(408, 429)",
        "$statusCode -ge 500",
        "Start-Sleep -Seconds $attempt",
        "Get-FileHash -Algorithm SHA256 -Path $partialOutput",
        "Move-Item -LiteralPath $partialOutput -Destination $Output -Force",
    ):
        if fragment not in script:
            raise ValueError(f"verified Windows artifact downloader is missing: {fragment}")


def _check_release_workflow() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for fragment in (
        "Validate support contract",
        "run: python scripts/check_release_contract.py",
        "Require release commit on main",
        'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
        "sbom.cdx.json",
        "rm dist/sbom.cdx.json",
        "actions/attest-build-provenance@v4",
        "attestations: write",
        'gh run download "$GITHUB_RUN_ID" --name dist --dir dist',
        "dist/*.whl",
        "python -m pip install --force-reinstall dist/*.whl",
        "Run tests against installed wheel",
        "python -W error -m pytest --no-cov",
        'awk -v version="$RELEASE_VERSION"',
        "test -s /tmp/changes.md",
        "r2morph --version",
        "Require green validation workflows for release commit",
        "for workflow_file in ci.yml differential-corpus.yml adversarial-benchmark.yml independent-review.yml",
        '--workflow "$workflow_file"',
        '--commit "$GITHUB_SHA"',
        'if [[ "$conclusion" != "success" ]]; then',
    ):
        if fragment not in workflow:
            raise ValueError(f"release workflow is missing: {fragment}")


def _check_release_recovery_workflow() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-recovery.yml").read_text(encoding="utf-8")
    for fragment in (
        "workflow_dispatch:",
        "validate-release",
        "publish-pypi",
        'git rev-parse "${RELEASE_TAG}^{commit}"',
        'gh run download "$SOURCE_RUN_ID" --name dist --dir dist',
        "attestations: write",
        "actions/attest-build-provenance@v4",
        "softprops/action-gh-release@v2",
    ):
        if fragment not in workflow:
            raise ValueError(f"release recovery workflow is missing: {fragment}")


def _check_corpus_workflows() -> None:
    adversarial = (ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")
    differential = (ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    fuzz = (ROOT / ".github" / "workflows" / "fuzz.yml").read_text(encoding="utf-8")
    independent_review = (ROOT / ".github" / "workflows" / "independent-review.yml").read_text(encoding="utf-8")
    for fragment in (
        "schedule:",
        "workflow_dispatch:",
        "cron:",
        "Build and install package wheel",
        "python -m build",
        "python -m pip install --force-reinstall dist/*.whl",
        "wheel_root=/tmp/r2morph-adversarial-wheel-check",
        "cp -R scripts tests fixtures",
        'pyproject.toml "$wheel_root"/',
        'cd "$wheel_root"',
        '--output "$GITHUB_WORKSPACE/adversarial-benchmark.json"',
        "--passes all",
        "--require-tool-slots",
        "--require-applied",
        "--fixture-shard-count 16",
        "Validate adversarial campaign summary",
        "expected_tools",
        "observed_tools",
        "binary-ninja",
        "missing_pass_runs",
        "missing_tool_runs",
        "adversarial_evidence_blockers",
        "total_adversarial_evidence_blockers",
        "incomplete_tool_coverage",
        "completed_tool_runs_by_tool",
        "unavailable_tool_runs_by_tool",
        "unavailable_reasons_by_tool",
        "incomplete tool coverage mismatch",
        "passes without applications",
        "Run VM resistance seed-diversity smoke",
        "scripts/protection_handler_clustering.py",
        '--output "$GITHUB_WORKSPACE/vm-resistance-seed-diversity.json"',
        "Validate VM resistance seed-diversity evidence",
        "pending-human-adversarial-review",
        "cross_seed_has_exact_normalised_matches",
        "cross_seed_largest_normalised_cluster",
        "cross_seed_nearest_similarity_mean",
        "similarity_threshold",
        'cp -R docs "$wheel_root"/',
        "test_protection_bytecode_grammar.py",
        "test_protection_handler_clustering.py",
        "test_resistance_measurement_contract.py",
        "scripts/vm_resistance_adversarial.py",
        "test_vm_resistance_adversarial.py",
        '--output "$GITHUB_WORKSPACE/vm-resistance-adversarial.json"',
        "automated VM resistance evidence is missing",
        "dispatcher_unique_count",
        "tamper_diverged",
        "growth_observed",
        "Upload VM resistance seed-diversity evidence",
        "vm-resistance-seed-diversity",
    ):
        if fragment not in adversarial:
            raise ValueError(f"adversarial benchmark workflow is missing: {fragment}")
    for fragment in (
        "push:",
        "branches: [main]",
        '"r2morph/**"',
        "schedule:",
        "workflow_dispatch:",
        "cron:",
        "Build and install package wheel",
        "python -m build",
        "python -m pip install --force-reinstall dist/*.whl",
        "wheel_root=/tmp/r2morph-differential-wheel-check",
        "cp -R scripts tests fixtures",
        'pyproject.toml "$wheel_root"/',
        'cd "$wheel_root"',
        "fixture_shard",
        "--fixture-shard-count 16",
        "--fixture-shard-index",
        '--output "$GITHUB_WORKSPACE/differential-corpus.json"',
        '--output "$GITHUB_WORKSPACE/extended-maturity-passes.json"',
        "--passes all",
        "--require-complete-evidence",
        "--require-applied",
        "--count 1",
        "Validate differential campaign summary",
        "platform_scope",
        "platform_gap_scope",
        "corpus_gap_scope",
        "corpus_scope",
        "linux",
        "ELF",
        "x86-64",
        "fixtures/dataset",
        "missing_corpus_passes",
        "total_complete_evidence_missing_runs",
        "passes_with_incomplete_coverage",
        "continuous_evidence_blockers",
        "differential-corpus-by-pass",
        "Run cross-format differential smoke",
        "test_binary_rewriter_formats_real.py",
        "test_binary_rewriter_noop_preserves_real_format",
        "test_platform_deeper.py",
        "cross-format-differential.xml",
        "Validate cross-format differential evidence",
        "cross-format smoke coverage drift",
        "Upload cross-format differential evidence",
        "cross-format-differential",
        "Run VM semantic regression smoke",
        "test_memory_width_fixture_virtualization_preserves_exit_code",
        "test_virtualized_callee_saved_fixture_preserves_registers",
        "test_call_flags_stack_fixture_virtualization_preserves_exit_code",
        "test_virtualized_elf_preserves_fs_relative_access",
        "test_virtualized_threads_tls_and_signal_preserve_exit_code",
        "test_virtualized_elf_preserves_integer_varargs_stack_abi",
        "test_virtualized_elf_preserves_floating_point_varargs_register_and_stack_abi",
        "test_virtualized_direct_call_to_separate_function_preserves_exit_code",
        "test_virtualized_local_indirect_call_preserves_exit_code",
        "test_virtualized_vex_nondestructive_packed_add_preserves_result",
        "test_simd_integer_fixture_virtualization_preserves_exit_code",
        "test_code_virtualization_preserves_exception_from_call_inside_virtualized_function",
        "tests/unit/test_code_virtualization_static_dataflow.py",
        '--junitxml="$GITHUB_WORKSPACE/vm-semantic-differential.xml"',
        "Validate VM semantic differential evidence",
        "VM semantic smoke ran too few cases",
        "VM semantic smoke coverage drift",
        "Upload VM semantic differential evidence",
        "vm-semantic-differential.xml",
        "vm-semantic-differential",
        "Run parser and rewriter fuzz smoke",
        "Validate parser and rewriter fuzz smoke",
        "scripts/continuous_fuzz.py",
        "--cases 64",
        "--max-payload 512",
        "differential-fuzz-smoke.json",
        "binary_parsers",
        "vm_dispatcher",
        "relocations",
        "binary_rewriter",
        "Upload differential fuzz smoke",
        "differential-fuzz-smoke",
        "Run extended maturity pass smoke",
        "Validate extended maturity pass smoke",
        "EXTENDED_MATURITY_PASSES",
        "AntiDisassembly,APIHashing,CodeMobility,DataFlowMutation",
        "SelfModifyingCode,ShortJumpPatching",
        "missing_extended_passes",
        "passes_without_extended_applied_runs",
        "extended_passes_with_error_runs",
        "extended_maturity_evidence_blockers",
        "total_extended_maturity_evidence_blockers",
        "extended maturity pass errors",
        "extended-maturity-passes",
        "extended-maturity-merged.json",
        "cross-platform-differential:",
        "Cross-platform differential (macOS ARM64)",
        "runs-on: macos-latest",
        "test_mutation_nop_insertion_arm64.py",
        "test_mutation_register_substitution_arm64.py",
        "cross-platform-differential-macos-arm64",
        "public-compatibility-corpus:",
        "repository: seifreed/r2morph-corpus",
        "5f16a6fdcccbe2c3c97100f339a68ab916ca2e19",
        "Build public compatibility corpus",
        "Run public differential matrix",
        "Validate public differential matrix",
        "Run public static recovery benchmark",
        "Select bounded public corpus matrix",
        "public-corpus/build-selected",
        "O0",
        "O2",
        "O3",
        "aggregate-platform-differential:",
        "Aggregate platform differential evidence",
        "cross-platform-differential-macos-arm64",
        "cross-platform-differential-windows-pe",
        "elf-arm64-native",
        "differential-platform-aggregate",
        "Validate aggregated platform evidence",
    ):
        if fragment not in differential:
            raise ValueError(f"differential corpus workflow is missing: {fragment}")
    for fragment in (
        "workflow_run:",
        'workflows: ["Adversarial Analysis Benchmark"]',
        "types: [completed]",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.head_sha || github.sha",
    ):
        if fragment not in independent_review:
            raise ValueError(f"independent review workflow is missing: {fragment}")
    for fragment in (
        "schedule:",
        "workflow_dispatch:",
        "Build and install package wheel",
        "python -m build",
        "python -m pip install --force-reinstall dist/*.whl",
        "wheel_root=/tmp/r2morph-fuzz-wheel-check",
        'cp -R scripts fixtures "$wheel_root"/',
        'cd "$wheel_root"',
        'python -c "import r2morph; print(r2morph.__file__)"',
        "scripts/continuous_fuzz.py",
        '--output "$GITHUB_WORKSPACE/fuzz-campaign.json"',
        "continuous-fuzz-report",
    ):
        if fragment not in fuzz:
            raise ValueError(f"continuous fuzz workflow is missing: {fragment}")
