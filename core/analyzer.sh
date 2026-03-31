#!/usr/bin/env bash
# core/analyzer.sh - CVE matching, scoring and exploit suggestion engine

# ──────────────────────────────────────────────────────────────
# CVE Database loader
# ──────────────────────────────────────────────────────────────
DB_DIR="${SCRIPT_DIR}/database"
CVE_DB="${DB_DIR}/cve_database.json"
GTFOBINS_DB="${DB_DIR}/gtfobins.json"
# Canonical site: https://gtfobins.org/ (same project as GTFOBins.github.io)
GTFOR_BINS_BASE_URL="${GTFOR_BINS_BASE_URL:-https://gtfobins.org}"
EPSS_DB="${DB_DIR}/epss_scores.db"

declare -gA _EPSS_CACHE=()
declare -gA _CVSS_CACHE=()
declare -gA _CVSS_VECTOR_CACHE=()

load_cve_database() {
    [[ -f "$CVE_DB" ]] || { log_error "CVE database not found: $CVE_DB"; return 1; }
    log_info "CVE database loaded: $CVE_DB"
}

load_gtfobins() {
    [[ -f "$GTFOBINS_DB" ]] || { log_warn "GTFOBins database not found"; return 1; }
    log_info "GTFOBins database loaded"
}

# ──────────────────────────────────────────────────────────────
# EPSS + CVSS scoring engine
# ──────────────────────────────────────────────────────────────
_load_epss_cache() {
    [[ ${#_EPSS_CACHE[@]} -gt 0 ]] && return 0
    [[ -f "$EPSS_DB" ]] || return 1

    while IFS='|' read -r cve_id epss_score epss_pct cvss_base cvss_vector; do
        [[ "$cve_id" =~ ^# ]] && continue
        [[ -z "$cve_id" ]] && continue
        _EPSS_CACHE["$cve_id"]="$epss_score"
        _CVSS_CACHE["$cve_id"]="$cvss_base"
        _CVSS_VECTOR_CACHE["$cve_id"]="$cvss_vector"
    done < "$EPSS_DB"

    log_info "EPSS database loaded: ${#_EPSS_CACHE[@]} entries"
    return 0
}

epss_lookup() {
    local cve_id="$1"
    [[ -z "$cve_id" || "$cve_id" == "-" ]] && { echo "0.0"; return; }
    _load_epss_cache 2>/dev/null
    echo "${_EPSS_CACHE[$cve_id]:-0.0}"
}

cvss_lookup() {
    local cve_id="$1"
    [[ -z "$cve_id" || "$cve_id" == "-" ]] && { echo "0.0"; return; }
    _load_epss_cache 2>/dev/null
    echo "${_CVSS_CACHE[$cve_id]:-0.0}"
}

cvss_vector_lookup() {
    local cve_id="$1"
    [[ -z "$cve_id" || "$cve_id" == "-" ]] && { echo "-"; return; }
    _load_epss_cache 2>/dev/null
    echo "${_CVSS_VECTOR_CACHE[$cve_id]:--}"
}

severity_from_cvss() {
    local cvss="$1"
    awk "BEGIN {
        c = $cvss + 0
        if (c >= 9.0) print \"CRITICAL\"
        else if (c >= 7.0) print \"HIGH\"
        else if (c >= 4.0) print \"MEDIUM\"
        else if (c >= 0.1) print \"LOW\"
        else print \"INFO\"
    }"
}

_severity_to_weight() {
    case "${1^^}" in
        CRITICAL) echo 50 ;; HIGH) echo 30 ;; MEDIUM) echo 15 ;;
        LOW) echo 5 ;; *) echo 0 ;;
    esac
}

# Composite priority score: weighted blend of CVSS, EPSS, and exploit availability
# Range: 0.0 - 10.0
# Formula: (CVSS * 0.35) + (EPSS * 10 * 0.40) + (exploit_bonus * 0.25)
calculate_priority_score() {
    local cve_id="$1"
    local severity="$2"
    local has_exploit="$3"

    local cvss epss exploit_bonus
    cvss=$(cvss_lookup "$cve_id")
    epss=$(epss_lookup "$cve_id")

    [[ "$has_exploit" == "true" || "$has_exploit" == "1" || -n "$has_exploit" && "$has_exploit" != "-" && "$has_exploit" != "false" ]] \
        && exploit_bonus="10.0" || exploit_bonus="0.0"

    if [[ "$cvss" == "0.0" && "$epss" == "0.0" ]]; then
        local sev_weight
        sev_weight=$(_severity_to_weight "$severity")
        awk "BEGIN { printf \"%.1f\", ($sev_weight / 5.0) }"
        return
    fi

    awk "BEGIN {
        cvss = $cvss + 0
        epss = $epss + 0
        expl = $exploit_bonus + 0
        score = (cvss * 0.35) + (epss * 10.0 * 0.40) + (expl * 0.25)
        if (score > 10.0) score = 10.0
        printf \"%.1f\", score
    }"
}

# Risk tier classification based on priority score
priority_tier() {
    local score="$1"
    awk "BEGIN {
        s = $score + 0
        if (s >= 8.0) print \"IMMINENT\"
        else if (s >= 6.0) print \"LIKELY\"
        else if (s >= 4.0) print \"POSSIBLE\"
        else if (s >= 2.0) print \"UNLIKELY\"
        else print \"MINIMAL\"
    }"
}

# ──────────────────────────────────────────────────────────────
# GTFOBins lookup - sudo/suid exploit commands for binaries
# ──────────────────────────────────────────────────────────────
gtfobins_lookup() {
    local binary="$1"
    local context="${2:-suid}"  # sudo|suid|capabilities

    if cmd_exists jq; then
        jq -r --arg bin "$binary" --arg ctx "$context" '
            .binaries[$bin] |
            if . then
                .[$ctx]? // [] |
                .[] |
                "\(.type // "shell")|\(.command // "")"
            else
                empty
            end
        ' "$GTFOBINS_DB" 2>/dev/null
    else
        _grep_gtfobins "$binary" "$context"
    fi
}

_grep_gtfobins() {
    local binary="$1"
    local context="$2"
    local db_file="${SCRIPT_DIR}/database/gtfobins_flat.db"

    [[ -f "$db_file" ]] || return 1

    awk -F'|' -v bin="$binary" -v ctx="$context" \
        '$1 == bin && $2 == ctx {print $3"|"$4}' "$db_file"
}

# Human-readable URL for a binary on GTFOBins (https://gtfobins.org/).
gtfobins_binary_url() {
    local binary="${1:?}"
    echo "${GTFOR_BINS_BASE_URL}/gtfobins/${binary}/"
}

# Anchor for exploit class (shell, file-read, …) on the GTFOBins page.
gtfobins_function_anchor() {
    local func_type="${1:-shell}"
    echo "#${func_type}"
}

# Up to N additional GTFOBins techniques as evidence text (type + truncated command).
gtfobins_techniques_evidence() {
    local binary="$1"
    local context="${2:-suid}"
    local max="${3:-5}"
    local acc="" n=0
    local line t c

    while IFS='|' read -r t c && [[ $n -lt $max ]]; do
        [[ -z "$t" ]] && continue
        local clip="$c"
        [[ ${#clip} -gt 140 ]] && clip="${clip:0:140}…"
        acc="${acc:+${acc} ; }${t}: ${clip}"
        n=$(( n + 1 ))
    done < <(gtfobins_lookup "$binary" "$context")

    echo "$acc"
}

# ──────────────────────────────────────────────────────────────
# Attack path generator - exploitability analysis
# ──────────────────────────────────────────────────────────────
generate_attack_paths() {
    local -a paths=()

    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"
        case "$category" in
            kernel)
                [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]] && \
                    paths+=("KERNEL_EXPLOIT:${cve}:${title}")
                ;;
            sudo)
                paths+=("SUDO_ABUSE:${cve}:${title}")
                ;;
            suid)
                paths+=("SUID_EXPLOIT:${cve}:${title}")
                ;;
            capabilities)
                paths+=("CAP_EXPLOIT:${cve}:${title}")
                ;;
        esac
    done

    if [[ ${#paths[@]} -gt 0 ]]; then
        print_section "ATTACK PATHS (Prioritized)"
        local i=1
        for path in "${paths[@]}"; do
            IFS=':' read -r type cve title <<< "$path"
            echo -e "  ${BOLD_WHITE}${i}.${RESET} ${BOLD_YELLOW}[${type}]${RESET} ${title} ${GREY}(${cve})${RESET}"
            i=$(( i + 1 ))
        done
    fi
}
