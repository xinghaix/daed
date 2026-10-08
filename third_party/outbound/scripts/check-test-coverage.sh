#!/usr/bin/env bash
#
# Zero-test-debt ledger gate.
#
# `go test ./...` passes silently for a package that has no test files at all,
# so a large hot-path package with zero tests looks green in CI. This script
# makes that debt explicit: every package without tests must be listed in
# docs/zero-test-debt.txt, and the ledger is a RATCHET - it may only shrink.
#
# It fails when:
#   * a package has no test files and is not in the ledger (new debt);
#   * a package is in the ledger but now has tests (stale entry: remove the line);
#   * a package is in the ledger but no longer exists (stale entry: remove it).
#
# Regenerate the ledger after adding tests:
#   bash scripts/check-test-coverage.sh --list > docs/zero-test-debt.txt
# (then re-add the explanatory header the file carries).
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
ledger="${repo_root}/docs/zero-test-debt.txt"

cd -- "${repo_root}"

# untested_packages prints the import path of every package that has no test
# files. `go list -f` reports TestGoFiles/XTestGoFiles as the test files in the
# package directory, so an empty pair means "no tests here".
untested_packages() {
  go list -f '{{if and (eq (len .TestGoFiles) 0) (eq (len .XTestGoFiles) 0)}}{{.ImportPath}}{{end}}' ./... |
    sed '/^$/d' |
    sort
}

all_packages() {
  go list ./... | sort
}

if [[ "${1:-}" == "--list" ]]; then
  echo "# Packages with no test files, as of $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown revision')."
  echo "# Regenerate with: bash scripts/check-test-coverage.sh --list"
  echo "#"
  echo "# This ledger is a ratchet: it may only shrink. Adding tests to a listed"
  echo "# package? Delete its line in the same commit. Adding a new package without"
  echo "# tests? The gate will fail until it is listed here, which is the point."
  echo
  untested_packages
  exit 0
fi

if [[ ! -f "${ledger}" ]]; then
  echo "::error::missing ledger ${ledger#"${repo_root}/"}" >&2
  exit 1
fi

# Ledger entries: strip comments and blanks, trim surrounding whitespace.
ledger_entries() {
  sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "${ledger}" |
    sed '/^$/d' |
    sort -u
}

untested="$(untested_packages)"
known="$(all_packages)"
entries="$(ledger_entries)"

status=0

# 1. New debt: untested package that nobody declared.
while IFS= read -r pkg; do
  [[ -z "${pkg}" ]] && continue
  if ! grep -qxF "${pkg}" <<<"${entries}"; then
    echo "::error::package ${pkg} has no test files and is not in ${ledger#"${repo_root}/"}"
    echo "         add the line:  ${pkg}" >&2
    echo "         (or write tests for it, which is the better answer)" >&2
    status=1
  fi
done <<<"${untested}"

# 2. Stale entries: listed as debt but the package now has tests.
while IFS= read -r pkg; do
  [[ -z "${pkg}" ]] && continue
  if ! grep -qxF "${pkg}" <<<"${known}"; then
    echo "::error::${ledger#"${repo_root}/"} lists ${pkg}, which is not a package in this module"
    echo "         remove that line (the package was renamed or deleted)" >&2
    status=1
    continue
  fi
  if ! grep -qxF "${pkg}" <<<"${untested}"; then
    echo "::error::${ledger#"${repo_root}/"} lists ${pkg}, but it now has tests"
    echo "         remove that line: the ledger is a ratchet and may only shrink" >&2
    status=1
  fi
done <<<"${entries}"

if [[ "${status}" -eq 0 ]]; then
  listed="$(wc -l <<<"${entries}" | tr -d ' ')"
  echo "zero-test-debt ledger OK: ${listed} package(s) declared, ${listed} package(s) without tests"
fi

exit "${status}"
