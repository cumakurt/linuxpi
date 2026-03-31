#!/usr/bin/env bash
# utils/logger.sh - Structured JSON logging infrastructure

# ──────────────────────────────────────────────────────────────
# Log state
# ──────────────────────────────────────────────────────────────
LOG_FILE="${LOG_FILE:-/tmp/.linuxpi_$(date +%s).log}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
LOG_JSON="${LOG_JSON:-0}"
_SESSION_ID=""
_START_TIME=""

_level_to_num() {
    local level="${1:-INFO}"
    case "$level" in
        DEBUG)    echo 0 ;;
        INFO)     echo 1 ;;
        WARN)     echo 2 ;;
        ERROR)    echo 3 ;;
        CRITICAL) echo 4 ;;
        *)        echo 1 ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Init
# ──────────────────────────────────────────────────────────────
logger_init() {
    _SESSION_ID="$(date +%s%N | sha256sum | head -c 16 2>/dev/null || date +%s)"
    _START_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    if [[ "${QUIET_MODE:-0}" == "1" ]]; then
        LOG_FILE="/dev/null"
        return
    fi

    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/stderr"

    _log_entry "INFO" "logger" "Session initialized" \
        "{\"session_id\":\"${_SESSION_ID}\",\"user\":\"$(id -un)\",\"uid\":$(id -u),\"start_time\":\"${_START_TIME}\"}"
}

# ──────────────────────────────────────────────────────────────
# Core logging function
# ──────────────────────────────────────────────────────────────
_log_entry() {
    local level="$1"
    local module="$2"
    local message="$3"
    local extra="${4:-}"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

    local level_num
    level_num="$(_level_to_num "$level")"
    local min_level_num
    min_level_num="$(_level_to_num "${LOG_LEVEL:-INFO}")"
    [[ $level_num -lt $min_level_num ]] && return 0

    local json_entry
    if [[ -n "$extra" ]]; then
        json_entry="{\"ts\":\"${timestamp}\",\"level\":\"${level}\",\"session\":\"${_SESSION_ID}\",\"module\":\"${module}\",\"msg\":$(json_escape "$message"),\"data\":${extra}}"
    else
        json_entry="{\"ts\":\"${timestamp}\",\"level\":\"${level}\",\"session\":\"${_SESSION_ID}\",\"module\":\"${module}\",\"msg\":$(json_escape "$message")}"
    fi

    echo "$json_entry" >> "$LOG_FILE" 2>/dev/null
}

# ──────────────────────────────────────────────────────────────
# JSON string escape
# ──────────────────────────────────────────────────────────────
json_escape() {
    local raw="$1"
    raw="${raw//\\/\\\\}"
    raw="${raw//\"/\\\"}"
    raw="${raw//$'\n'/\\n}"
    raw="${raw//$'\r'/\\r}"
    raw="${raw//$'\t'/\\t}"
    echo "\"${raw}\""
}

# ──────────────────────────────────────────────────────────────
# Public log functions
# ──────────────────────────────────────────────────────────────
log_debug()    { _log_entry "DEBUG"    "${BASH_SOURCE[1]##*/}:${BASH_LINENO[0]}" "$*"; }
log_info()     { _log_entry "INFO"     "${BASH_SOURCE[1]##*/}:${BASH_LINENO[0]}" "$*"; }
log_warn()     { _log_entry "WARN"     "${BASH_SOURCE[1]##*/}:${BASH_LINENO[0]}" "$*"; }
log_error()    { _log_entry "ERROR"    "${BASH_SOURCE[1]##*/}:${BASH_LINENO[0]}" "$*"; }
log_critical() { _log_entry "CRITICAL" "${BASH_SOURCE[1]##*/}:${BASH_LINENO[0]}" "$*"; }

# ──────────────────────────────────────────────────────────────
# Finding log — record a security finding
# ──────────────────────────────────────────────────────────────
log_finding() {
    local severity="$1"    # CRITICAL|HIGH|MEDIUM|LOW|INFO
    local category="$2"    # kernel|sudo|suid|cred|container|etc.
    local cve="${3:-}"
    local title="$4"
    local detail="${5:-}"
    local exploit="${6:-}"

    local extra
    extra="{\"severity\":\"${severity}\",\"category\":\"${category}\",\"cve\":\"${cve}\",\"title\":$(json_escape "$title"),\"detail\":$(json_escape "$detail"),\"exploit\":$(json_escape "$exploit")}"

    _log_entry "INFO" "finding" "$title" "$extra"
}

# ──────────────────────────────────────────────────────────────
# Timing helper
# ──────────────────────────────────────────────────────────────
log_timing() {
    local module="$1"
    local elapsed_ms="$2"
    _log_entry "DEBUG" "$module" "Module completed" "{\"elapsed_ms\":${elapsed_ms}}"
}

# ──────────────────────────────────────────────────────────────
# Session summary
# ──────────────────────────────────────────────────────────────
logger_finalize() {
    local total_findings="$1"
    local end_time
    end_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    _log_entry "INFO" "logger" "Session finalized" \
        "{\"session_id\":\"${_SESSION_ID}\",\"end_time\":\"${end_time}\",\"total_findings\":${total_findings},\"log_file\":\"${LOG_FILE}\"}"
}
