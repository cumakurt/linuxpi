#!/usr/bin/env bash
# tests/test_kernel_matching.sh - Kernel CVE matcher unit tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
TOTAL=0

_assert() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$(( TOTAL + 1 ))

    if [[ "$expected" == "$actual" ]]; then
        echo -e "  \033[32m[PASS]\033[0m $desc"
        PASS=$(( PASS + 1 ))
    else
        echo -e "  \033[31m[FAIL]\033[0m $desc (expected: '$expected', got: '$actual')"
        FAIL=$(( FAIL + 1 ))
    fi
}

# Minimal bootstrap for matcher helpers only.
source "$SCRIPT_DIR/utils/helpers.sh"
source "$SCRIPT_DIR/modules/kernel/kernel_enum.sh"

_range_result() {
    _kernel_version_in_affected_range "$1" "$2" "$3" && echo "yes" || echo "no"
}

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  Kernel CVE Matcher Test Suite             ║"
echo "╚════════════════════════════════════════════╝"
echo ""

echo "── Test Group 1: Stable Branch Boundaries ──"
_assert "Inclusive lower bound" "yes" "$(_range_result 6.2.0 6.2.0 6.6.136)"
_assert "Inclusive upper bound" "yes" "$(_range_result 6.6.136 6.2.0 6.6.136)"
_assert "Patched next stable is excluded" "no" "$(_range_result 6.6.137 6.2.0 6.6.136)"
_assert "Previous stable branch is excluded" "no" "$(_range_result 6.1.170 6.2.0 6.6.136)"

echo ""
echo "── Test Group 2: Embedded DB Fallback ──"
KERNEL_DB_CONTENT="CVE-TEST-0001|Unit Test|1.0.0|1.0.1|HIGH|7.8|false|embedded fallback"
_assert "Embedded DB is used when file is absent" "$KERNEL_DB_CONTENT" "$(_kernel_db_stream /tmp/linuxpi-nonexistent-kernel-db)"
unset KERNEL_DB_CONTENT

echo ""
echo "── Test Group 3: Recent CVE References ──"
_assert "CopyFail exploit reference" "https://github.com/theori-io/copy-fail-CVE-2026-31431" "$(_kernel_cve_exploit_reference CVE-2026-31431)"
_assert "Generic exploit reference" "https://www.exploit-db.com/search?cve=CVE-2099-0001" "$(_kernel_cve_exploit_reference CVE-2099-0001)"

echo ""
echo "════════════════════════════════════════════"
echo "  Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "════════════════════════════════════════════"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
