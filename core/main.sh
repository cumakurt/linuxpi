#!/usr/bin/env bash
# core/main.sh - LinuxPi main orchestration engine

set -o pipefail

# ──────────────────────────────────────────────────────────────
# Signal handling - clean exit on Ctrl+C
# ──────────────────────────────────────────────────────────────
_INTERRUPTED=0

_setup_timeout_handler() {
    local timeout="${SCAN_TIMEOUT:-300}"

    (
        exec 0</dev/null 1>/dev/null
        sleep "$timeout"
        echo -e "\n  ${BOLD_YELLOW:-}[WARN]${RESET:-} Scan timeout reached (${timeout}s) - generating partial report" >&2
        kill -SIGTERM $$ 2>/dev/null
    ) &
    TIMEOUT_PID=$!

    trap '_on_sigint' INT
    trap '_on_sigterm' TERM
    trap '_cleanup_exit' EXIT
}

_on_sigint() {
    _INTERRUPTED=1
    echo "" >&2
    echo -e "  ${BOLD_RED:-}[!] Ctrl+C detected - aborting scan immediately${RESET:-}" >&2

    _kill_children
    _cleanup_files

    trap - INT
    kill -INT $$ 2>/dev/null
}

_on_sigterm() {
    _INTERRUPTED=1
    _kill_children
    _cleanup_files
    exit 143
}

_kill_children() {
    local child_pids
    child_pids=$(jobs -p 2>/dev/null)
    if [[ -n "$child_pids" ]]; then
        kill $child_pids 2>/dev/null || true
        wait $child_pids 2>/dev/null || true
    fi

    [[ -n "${TIMEOUT_PID:-}" ]] && kill "$TIMEOUT_PID" 2>/dev/null || true
}

_cleanup_files() {
    if [[ "${STEALTH_MODE:-0}" == "1" ]]; then
        [[ -n "${LOG_FILE:-}" && "${LOG_FILE}" != "/dev/null" ]] && rm -f "$LOG_FILE" 2>/dev/null || true
    fi
}

_MAIN_BASHPID=$BASHPID
_cleanup_exit() {
    [[ $BASHPID -ne $_MAIN_BASHPID ]] && return 0
    _kill_children
    _cleanup_files
}

# ──────────────────────────────────────────────────────────────
# Preflight checks
# ──────────────────────────────────────────────────────────────
_preflight_checks() {
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        echo "[FATAL] Bash 4.0+ required (associative arrays). Current: ${BASH_VERSION}" >&2
        exit 1
    fi

    if [[ "${EXPLOIT_MODE:-0}" == "1" ]] && [[ "$(id -u)" != "0" ]]; then
        echo "[INFO] Note: Running exploit mode as non-root user" >&2
    fi

    if [[ "${STEALTH_MODE:-0}" == "1" ]] && [[ -z "${_LINUXPI_STEALTH_INIT:-}" ]]; then
        export _LINUXPI_STEALTH_INIT=1
        exec -a "[kworker/0:0H]" bash -- "$0" "${ORIGINAL_ARGS[@]}" 2>/dev/null || true
    fi
}

# ──────────────────────────────────────────────────────────────
# Progress tracking
# ──────────────────────────────────────────────────────────────
declare -a _MODULE_TIMINGS=()

_track_module_time() {
    local module_name="$1"
    local elapsed_ms="$2"
    _MODULE_TIMINGS+=("${module_name}:${elapsed_ms}")
}

_print_timing_summary() {
    [[ "${QUIET_MODE:-0}" == "1" ]] && return
    [[ ${#_MODULE_TIMINGS[@]} -eq 0 ]] && return

    echo -e "\n  ${GREY:-}Module Timings:${RESET:-}"
    for entry in "${_MODULE_TIMINGS[@]}"; do
        IFS=: read -r mod ms <<< "$entry"
        printf "  ${GREY:-}  %-20s %s${RESET:-}\n" "$mod" "$(format_duration "$ms")"
    done
}

# ──────────────────────────────────────────────────────────────
# Main execution flow
# ──────────────────────────────────────────────────────────────
main() {
    local scan_start_ms
    scan_start_ms=$(timestamp_ms 2>/dev/null || echo 0)

    # Keep real stdout on fd 3; send scan-phase stdout elsewhere so HTML/JSON/XML/MD
    # are the only stream on the restored stdout (avoids dumping the report into stderr noise).
    # With -v/--verbose, scan output goes to stderr so you still see it on a TTY.
    local _redir=""
    if [[ "${OUTPUT_FORMAT:-text}" != "text" ]]; then
        exec 3>&1
        # Send scan-phase stdout to stderr so the terminal shows progress; restore fd 1 before
        # generate_report so only the report hits the original stdout (e.g. -o file).
        exec 1>&2
        _redir="1"
    fi

    _preflight_checks

    if [[ "${QUIET_MODE:-0}" == "0" ]] && [[ "${STEALTH_MODE:-0}" == "0" ]]; then
        print_banner
    fi

    logger_init
    log_info "LinuxPi starting"

    if [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]]; then
        echo -e "  ${BOLD_RED:-}[!] REPORT_FULL_SECRETS enabled: reports may contain plaintext passwords, hashes, and tokens.${RESET:-}" >&2
        log_warn "REPORT_FULL_SECRETS=1 (plaintext credentials in reports)"
    fi

    run_detection

    [[ "${QUIET_MODE:-0}" == "0" ]] && print_system_info

    load_cve_database 2>/dev/null || true
    load_gtfobins 2>/dev/null || true

    run_all_enumerations

    _load_epss_cache 2>/dev/null || true
    _sort_findings

    local scan_end_ms
    scan_end_ms=$(timestamp_ms 2>/dev/null || echo 0)
    local elapsed_ms=$(( scan_end_ms - scan_start_ms ))

    [[ -n "$_redir" ]] && exec 1>&3 3>&-

    generate_report

    run_exploit_mode

    if [[ "${QUIET_MODE:-0}" == "0" ]]; then
        echo "" >&2
        _print_timing_summary >&2
        echo -e "  ${GREY:-}Scan completed in $(format_duration $elapsed_ms)${RESET:-}" >&2
        echo -e "  ${GREY:-}Total findings: $(get_total_findings) (C:${CRITICAL_COUNT} H:${HIGH_COUNT} M:${MEDIUM_COUNT} L:${LOW_COUNT} I:${INFO_COUNT})${RESET:-}" >&2
        [[ "${LOG_FILE}" != "/dev/null" ]] && echo -e "  ${GREY:-}Log file: ${LOG_FILE}${RESET:-}" >&2
    fi

    logger_finalize "$(get_total_findings)"

    local total
    total=$(get_total_findings)
    [[ $CRITICAL_COUNT -gt 0 ]] && exit 2
    [[ $HIGH_COUNT -gt 0 ]] && exit 3
    [[ $total -gt 0 ]] && exit 4
    exit 0
}
