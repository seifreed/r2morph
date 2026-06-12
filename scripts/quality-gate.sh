#!/usr/bin/env bash
#
# r2morph quality gate
# ---------------------
# Enforces the rules in CLAUDE.md:
#   * No inline suppressions in source code or pyproject.toml.
#   * pyproject.toml has the required strict sections.
#   * black, ruff, mypy, bandit, pip-audit, pytest -W error all pass clean.
#
# Usage:
#   scripts/quality-gate.sh                # run everything
#   scripts/quality-gate.sh --no-tests     # skip pytest (faster pre-commit run)
#   scripts/quality-gate.sh --only suppr   # run a single section: pyproject|suppr|mocks|black|ruff|mypy|bandit|pip-audit|tests
#
# Exit code: 0 only if every check passes with zero errors and zero warnings.

set -u -o pipefail

# ---------------------------------------------------------------------------
# Paths and environment
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PYPROJECT="${REPO_ROOT}/pyproject.toml"
SRC_DIR="${REPO_ROOT}/r2morph"

if [[ -f "${REPO_ROOT}/venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/venv/bin/activate"
elif [[ -f "${REPO_ROOT}/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.venv/bin/activate"
fi

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;34m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

FAILED_CHECKS=()
PASSED_CHECKS=()

section() { printf '\n%s==> %s%s\n' "${C_BOLD}${C_BLUE}" "$1" "${C_RESET}"; }
pass()    { printf '   %s[PASS]%s %s\n' "${C_GREEN}" "${C_RESET}" "$1"; PASSED_CHECKS+=("$1"); }
fail()    { printf '   %s[FAIL]%s %s\n' "${C_RED}"   "${C_RESET}" "$1"; FAILED_CHECKS+=("$1"); }
warn()    { printf '   %s[WARN]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$1"; }
info()    { printf '          %s\n' "$1"; }

require_tool() {
    local tool="$1"
    if ! command -v "${tool}" >/dev/null 2>&1; then
        fail "tool '${tool}' not found in PATH — install it and re-run"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

RUN_TESTS=1
ONLY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-tests) RUN_TESTS=0; shift ;;
        --only)     ONLY="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) fail "unknown argument: $1"; exit 2 ;;
    esac
done

should_run() {
    [[ -z "${ONLY}" || "${ONLY}" == "$1" ]]
}

# ---------------------------------------------------------------------------
# Check 1 — pyproject.toml integrity
# ---------------------------------------------------------------------------

check_pyproject() {
    section "pyproject.toml — strict configuration"

    if [[ ! -f "${PYPROJECT}" ]]; then
        fail "pyproject.toml missing at ${PYPROJECT}"
        return
    fi

    local content
    content="$(cat "${PYPROJECT}")"

    declare -a FORBIDDEN_PATTERNS=(
        '"pragma: no cover"|pyproject.toml uses coverage exclude for pragma: no cover'
        '^\s*omit\s*=\s*\[[^]]*r2morph|pyproject.toml omits production modules from coverage'
        '^\s*ignore_errors\s*=\s*true|mypy ignores errors'
        'filterwarnings\s*=\s*\[[^]]*ignore::|pytest filterwarnings silences warnings (must use "error")'
        'per-file-ignores|per-file-ignores present (forbidden by CLAUDE.md)'
        '--exit-zero|tool invocation uses --exit-zero'
    )

    local section_failed=0
    while IFS='|' read -r pattern message; do
        if grep -nE "${pattern}" "${PYPROJECT}" >/dev/null 2>&1; then
            fail "${message}"
            grep -nE "${pattern}" "${PYPROJECT}" | sed 's/^/          → /'
            section_failed=1
        fi
    done < <(printf '%s\n' "${FORBIDDEN_PATTERNS[@]}")

    # mypy ignore_missing_imports allowed ONLY inside [[tool.mypy.overrides]] blocks.
    # Detect any occurrence outside such a block.
    local mypy_global_ignore
    mypy_global_ignore="$(python3 - "${PYPROJECT}" <<'PY' || true
import sys, re
text = open(sys.argv[1]).read()
in_override = False
violations = []
for i, line in enumerate(text.splitlines(), 1):
    stripped = line.strip()
    if stripped.startswith("[["):
        in_override = stripped.startswith("[[tool.mypy.overrides")
        continue
    if stripped.startswith("["):
        in_override = False
        continue
    if re.match(r"\s*ignore_missing_imports\s*=\s*true", line) and not in_override:
        violations.append(f"{i}: {line}")
print("\n".join(violations))
PY
)"
    if [[ -n "${mypy_global_ignore}" ]]; then
        fail "mypy globally ignores missing imports (only allowed inside [[tool.mypy.overrides]])"
        printf '%s\n' "${mypy_global_ignore}" | sed 's/^/          → /'
        section_failed=1
    fi

    # ruff ignore list must be empty
    local ruff_ignore
    ruff_ignore="$(python3 - "${PYPROJECT}" <<'PY' || true
import sys, re
text = open(sys.argv[1]).read()
m = re.search(r"\[tool\.ruff\.lint\][^\[]*?ignore\s*=\s*\[([^\]]*)\]", text, re.DOTALL)
if m and m.group(1).strip():
    print(f"ignore = [{m.group(1).strip()}]")
PY
)"
    if [[ -n "${ruff_ignore}" ]]; then
        fail "ruff ignore list is non-empty"
        printf '          → %s\n' "${ruff_ignore}"
        section_failed=1
    fi

    declare -a REQUIRED_SECTIONS=(
        '\[tool\.black\]|missing [tool.black] section'
        '\[tool\.ruff\]|missing [tool.ruff] section'
        '\[tool\.mypy\]|missing [tool.mypy] section'
        '\[tool\.bandit\]|missing [tool.bandit] section'
        '\[tool\.coverage\.run\]|missing [tool.coverage.run] section'
        '\[tool\.pytest\.ini_options\]|missing [tool.pytest.ini_options] section'
    )

    while IFS='|' read -r pattern message; do
        if ! grep -nE "^${pattern}$" "${PYPROJECT}" >/dev/null 2>&1; then
            fail "${message}"
            section_failed=1
        fi
    done < <(printf '%s\n' "${REQUIRED_SECTIONS[@]}")

    declare -a REQUIRED_MYPY_FLAGS=(
        'disallow_untyped_defs\s*=\s*true'
        'warn_unused_ignores\s*=\s*true'
        'warn_return_any\s*=\s*true'
    )

    for flag in "${REQUIRED_MYPY_FLAGS[@]}"; do
        if ! grep -nE "^${flag}" "${PYPROJECT}" >/dev/null 2>&1; then
            fail "pyproject.toml missing mypy flag: ${flag%%\\s*}"
            section_failed=1
        fi
    done

    local filterwarn_ok
    filterwarn_ok="$(python3 - "${PYPROJECT}" <<'PY' || true
import sys, re
text = open(sys.argv[1]).read()
m = re.search(r"filterwarnings\s*=\s*\[(.*?)\]", text, re.DOTALL)
if m:
    items = [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]
    if items == ["error"]:
        print("OK")
PY
)"
    if [[ "${filterwarn_ok}" != "OK" ]]; then
        fail 'pytest filterwarnings must be set to ["error"] (warnings are errors)'
        section_failed=1
    fi

    if [[ ${section_failed} -eq 0 ]]; then
        pass "pyproject.toml passes strict-config checks"
    fi
}

# ---------------------------------------------------------------------------
# Check 1b — forbidden test-mocking dependencies in pyproject.toml
# ---------------------------------------------------------------------------

check_mock_dependencies() {
    section "pyproject.toml — forbidden mocking dependencies"

    if [[ ! -f "${PYPROJECT}" ]]; then
        return
    fi

    declare -a FORBIDDEN_DEPS=(
        'pytest-mock'
        '"mock"'
        '"mock>'
        '"mock=='
        'responses>='
        'freezegun>='
    )

    local section_failed=0
    for dep in "${FORBIDDEN_DEPS[@]}"; do
        if grep -nE "${dep}" "${PYPROJECT}" >/dev/null 2>&1; then
            fail "pyproject.toml declares forbidden mocking dependency: ${dep}"
            grep -nE "${dep}" "${PYPROJECT}" | sed 's/^/          → /'
            section_failed=1
        fi
    done

    if [[ ${section_failed} -eq 0 ]]; then
        pass "pyproject.toml has no mocking dependencies declared"
    fi
}

# ---------------------------------------------------------------------------
# Check 2 — inline suppressions in source tree
# ---------------------------------------------------------------------------

check_suppressions() {
    section "Inline suppressions in r2morph/"

    declare -a SUPPR_PATTERNS=(
        '#\s*nosec(\b|[^a-zA-Z])'
        '#\s*pragma:\s*no\s*cover'
        '#\s*noqa(\b|[^a-zA-Z])'
        '#\s*type:\s*ignore'
        '#\s*fmt:\s*off'
        '#\s*fmt:\s*skip'
    )

    local total_hits=0
    for pat in "${SUPPR_PATTERNS[@]}"; do
        local matches
        matches="$(grep -RInE --include='*.py' "${pat}" "${SRC_DIR}" 2>/dev/null || true)"
        if [[ -n "${matches}" ]]; then
            local count
            count="$(printf '%s\n' "${matches}" | wc -l | tr -d ' ')"
            total_hits=$((total_hits + count))
            fail "found ${count} instance(s) of pattern: ${pat}"
            printf '%s\n' "${matches}" | sed 's/^/          → /'
        fi
    done

    if [[ ${total_hits} -eq 0 ]]; then
        pass "no inline suppressions found in r2morph/"
    fi
}

# ---------------------------------------------------------------------------
# Check 2b — mocks and monkeypatch usage in tests/
# ---------------------------------------------------------------------------

check_mocks() {
    section "Mocks / monkeypatch in tests/"

    local tests_dir="${REPO_ROOT}/tests"
    if [[ ! -d "${tests_dir}" ]]; then
        warn "no tests/ directory found"
        return
    fi

    # Each entry: "regex|description". Patterns crafted to minimise false positives.
    declare -a MOCK_PATTERNS=(
        '^\s*from\s+unittest\s*\.\s*mock\s+import|unittest.mock import'
        '^\s*from\s+unittest\s+import\s+.*\bmock\b|unittest import mock'
        '^\s*import\s+unittest\.mock\b|import unittest.mock'
        '^\s*from\s+mock\s+import|third-party "mock" import'
        '^\s*import\s+mock\b|bare "import mock"'
        '^\s*from\s+pytest_mock\b|pytest_mock import'
        '^\s*import\s+pytest_mock\b|pytest_mock import'
        '\bMagicMock\b|MagicMock usage'
        '\bAsyncMock\b|AsyncMock usage'
        '\bPropertyMock\b|PropertyMock usage'
        '\bcreate_autospec\b|create_autospec usage'
        '@patch\b|@patch decorator'
        '@mock\.patch\b|@mock.patch decorator'
        'def\s+test_\w+\s*\([^)]*\bmonkeypatch\b|monkeypatch fixture parameter'
        'def\s+test_\w+\s*\([^)]*\bmocker\b|mocker fixture parameter'
        '\bpytest\.MonkeyPatch\b|pytest.MonkeyPatch reference'
    )

    local total_hits=0
    while IFS='|' read -r pattern desc; do
        local matches
        matches="$(grep -RInE --include='*.py' "${pattern}" "${tests_dir}" 2>/dev/null || true)"
        if [[ -n "${matches}" ]]; then
            local count
            count="$(printf '%s\n' "${matches}" | wc -l | tr -d ' ')"
            total_hits=$((total_hits + count))
            fail "${desc} (${count} hit$([[ ${count} -ne 1 ]] && echo s)):"
            printf '%s\n' "${matches}" | head -8 | sed 's/^/          → /'
            if [[ ${count} -gt 8 ]]; then
                info "(… and $((count - 8)) more — full list with: grep -RInE \"${pattern}\" tests/)"
            fi
        fi
    done < <(printf '%s\n' "${MOCK_PATTERNS[@]}")

    if [[ ${total_hits} -eq 0 ]]; then
        pass "no mock / monkeypatch usage in tests/"
    fi
}

# ---------------------------------------------------------------------------
# Check 3..N — tool runners
# ---------------------------------------------------------------------------

run_black() {
    section "black --check (formatting)"
    require_tool black || return
    if black --check --quiet "${SRC_DIR}" tests; then
        pass "black: no formatting drift"
    else
        fail "black: formatting drift detected — run 'black r2morph tests' and review the diff"
    fi
}

run_ruff() {
    section "ruff check (lint)"
    require_tool ruff || return
    local output
    if output="$(ruff check "${SRC_DIR}" tests 2>&1)"; then
        if [[ -n "${output}" && "${output}" != *"All checks passed"* ]]; then
            warn "ruff exited 0 but produced output:"
            printf '%s\n' "${output}" | sed 's/^/          /'
        fi
        pass "ruff: clean"
    else
        fail "ruff: lint errors"
        printf '%s\n' "${output}" | sed 's/^/          /'
    fi
}

run_mypy() {
    section "mypy (type check)"
    require_tool mypy || return
    local output rc
    output="$(mypy "${SRC_DIR}" 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then
        # mypy in success still prints a summary line; treat it as PASS only if no "warning" appears
        if printf '%s\n' "${output}" | grep -qiE '\bwarning\b'; then
            fail "mypy: produced warnings (must be zero)"
            printf '%s\n' "${output}" | sed 's/^/          /'
        else
            pass "mypy: clean"
        fi
    else
        fail "mypy: type errors"
        printf '%s\n' "${output}" | sed 's/^/          /'
    fi
}

run_bandit() {
    section "bandit (security)"
    require_tool bandit || return
    local args=(-r "${SRC_DIR}" -q)
    # Use pyproject config only if a [tool.bandit] section exists
    if grep -qE '^\[tool\.bandit\]' "${PYPROJECT}" 2>/dev/null; then
        args+=(-c "${PYPROJECT}")
    fi
    local output rc
    output="$(bandit "${args[@]}" 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then
        pass "bandit: no issues"
    else
        fail "bandit: security findings"
        printf '%s\n' "${output}" | sed 's/^/          /'
    fi
}

run_pip_audit() {
    section "pip-audit (dependency vulnerabilities)"
    if ! command -v pip-audit >/dev/null 2>&1; then
        fail "pip-audit not installed — 'pip install pip-audit' and re-run"
        return
    fi
    local output rc
    output="$(pip-audit --strict --disable-pip 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then
        pass "pip-audit: no known vulnerabilities"
    else
        fail "pip-audit: vulnerabilities or audit error"
        printf '%s\n' "${output}" | sed 's/^/          /'
    fi
}

run_pytest() {
    section "pytest -W error"
    require_tool pytest || return
    local output rc
    output="$(pytest -W error --no-header -q 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then
        pass "pytest: all tests green, no warnings"
    else
        fail "pytest: failures or warnings"
        printf '%s\n' "${output}" | tail -50 | sed 's/^/          /'
    fi
}

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

should_run "pyproject"  && check_pyproject
should_run "pyproject"  && check_mock_dependencies
should_run "suppr"      && check_suppressions
should_run "mocks"      && check_mocks
should_run "black"      && run_black
should_run "ruff"       && run_ruff
should_run "mypy"       && run_mypy
should_run "bandit"     && run_bandit
should_run "pip-audit"  && run_pip_audit
if [[ ${RUN_TESTS} -eq 1 ]] && should_run "tests"; then
    run_pytest
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf '\n%s==> Summary%s\n' "${C_BOLD}${C_BLUE}" "${C_RESET}"
printf '   %sPassed:%s %d\n' "${C_GREEN}" "${C_RESET}" "${#PASSED_CHECKS[@]}"
printf '   %sFailed:%s %d\n' "${C_RED}"   "${C_RESET}" "${#FAILED_CHECKS[@]}"

if [[ ${#FAILED_CHECKS[@]} -gt 0 ]]; then
    printf '\n%sQuality gate FAILED.%s Failing checks:\n' "${C_BOLD}${C_RED}" "${C_RESET}"
    for c in "${FAILED_CHECKS[@]}"; do
        printf '   - %s\n' "${c}"
    done
    exit 1
fi

printf '\n%sQuality gate PASSED.%s\n' "${C_BOLD}${C_GREEN}" "${C_RESET}"
exit 0
