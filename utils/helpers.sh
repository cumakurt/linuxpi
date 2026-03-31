#!/usr/bin/env bash
# utils/helpers.sh - General utility functions

# ──────────────────────────────────────────────────────────────
# Command existence check
# ──────────────────────────────────────────────────────────────
cmd_exists() { command -v "$1" &>/dev/null; }

require_cmd() {
    local cmd="$1"
    cmd_exists "$cmd" || { print_error "Required command not found: $cmd"; return 1; }
}

# ──────────────────────────────────────────────────────────────
# String helpers
# ──────────────────────────────────────────────────────────────
trim()         { echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
to_lower()     { echo "${1,,}"; }
to_upper()     { echo "${1^^}"; }
strip_color()  { echo "$1" | sed 's/\x1b\[[0-9;]*m//g'; }

# Version string comparison (semver-like)
version_lt() {
    local v1="$1" v2="$2"
    [[ "$(printf '%s\n' "$v1" "$v2" | sort -V | head -n1)" == "$v1" ]] && [[ "$v1" != "$v2" ]]
}

version_lte() { version_lt "$1" "$2" || [[ "$1" == "$2" ]]; }
version_gt()  { version_lt "$2" "$1"; }
version_gte() { version_lte "$2" "$1"; }

# ──────────────────────────────────────────────────────────────
# File and permission helpers
# ──────────────────────────────────────────────────────────────
is_world_writable() {
    local path="$1"
    [[ -e "$path" ]] || return 1
    local perms
    perms=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)
    [[ "${perms: -1}" =~ [2367] ]]
}

is_readable() { [[ -r "$1" ]]; }
is_writable() { [[ -w "$1" ]]; }
is_suid()     { [[ -u "$1" ]]; }
is_sgid()     { [[ -g "$1" ]]; }

file_owner() { stat -c '%U' "$1" 2>/dev/null || stat -f '%Su' "$1" 2>/dev/null; }
file_perms()  { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# ──────────────────────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────────────────────
get_local_ips() {
    if cmd_exists ip; then
        ip -4 addr show 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1
    elif cmd_exists ifconfig; then
        ifconfig 2>/dev/null | awk '/inet / {print $2}' | grep -v '127\.'
    fi
}

is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || [[ "$ip" =~ ^192\.168\. ]]
}

# ──────────────────────────────────────────────────────────────
# Timing
# ──────────────────────────────────────────────────────────────
timestamp_ms() { date +%s%3N 2>/dev/null || echo "0"; }

elapsed_since() {
    local start="$1"
    local now
    now=$(timestamp_ms)
    echo $(( now - start ))
}

format_duration() {
    local ms="$1"
    local seconds=$(( ms / 1000 ))
    local minutes=$(( seconds / 60 ))
    seconds=$(( seconds % 60 ))
    [[ $minutes -gt 0 ]] && echo "${minutes}m ${seconds}s" || echo "${seconds}s"
}

# ──────────────────────────────────────────────────────────────
# Safe command execution (timeout + interrupt aware)
# ──────────────────────────────────────────────────────────────
safe_run() {
    local timeout_sec="${1:-10}"
    shift
    [[ "${_INTERRUPTED:-0}" == "1" ]] && return 130
    if cmd_exists timeout; then
        timeout --signal=KILL "$timeout_sec" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
    local rc=$?
    [[ "${_INTERRUPTED:-0}" == "1" ]] && return 130
    return $rc
}

# ──────────────────────────────────────────────────────────────
# Kernel version parsing
# ──────────────────────────────────────────────────────────────
get_kernel_version() {
    uname -r 2>/dev/null || cat /proc/version 2>/dev/null | awk '{print $3}'
}

parse_kernel_version() {
    local kernel="$1"
    local major minor patch
    major=$(echo "$kernel" | cut -d. -f1)
    minor=$(echo "$kernel" | cut -d. -f2)
    patch=$(echo "$kernel" | cut -d. -f3 | grep -oE '^[0-9]+')
    echo "${major}.${minor}.${patch:-0}"
}

# ──────────────────────────────────────────────────────────────
# Package manager detection
# ──────────────────────────────────────────────────────────────
detect_pkg_manager() {
    if cmd_exists dpkg;   then echo "dpkg";
    elif cmd_exists rpm;  then echo "rpm";
    elif cmd_exists pacman; then echo "pacman";
    elif cmd_exists apk;  then echo "apk";
    elif cmd_exists zypper; then echo "zypper";
    else echo "unknown"; fi
}

pkg_version() {
    local pkg="$1"
    local mgr
    mgr=$(detect_pkg_manager)
    case "$mgr" in
        dpkg)   dpkg -l "$pkg" 2>/dev/null | awk '/^ii/ {print $3}' ;;
        rpm)    rpm -q --queryformat '%{VERSION}' "$pkg" 2>/dev/null ;;
        pacman) pacman -Q "$pkg" 2>/dev/null | awk '{print $2}' ;;
        apk)    apk info "$pkg" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+[^ ]*' ;;
        *)      echo "" ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Findings collector (global array + enrichment maps)
# ──────────────────────────────────────────────────────────────
declare -a FINDINGS=()
declare -i CRITICAL_COUNT=0 HIGH_COUNT=0 MEDIUM_COUNT=0 LOW_COUNT=0 INFO_COUNT=0

declare -gA _FINDING_EVIDENCE=()
declare -gA _FINDING_REMEDIATION=()
declare -gA _FINDING_REFERENCES=()
declare -gA _FINDING_MITRE=()
declare -gA _FINDING_CREDENTIAL_PREVIEW=()

# Redact a single line for safe inclusion in reports.
# Policy: never emit full plaintext secrets, hashes, or tokens in machine or human reports.
_redact_credential_line() {
    local s="$1"
    local depth="${2:-0}"
    s="${s//[$'\r\n\t']/ }"
    s="${s//[[:cntrl:]]/?}"
    [[ $depth -lt 2 ]] && [[ "$s" =~ ^[0-9]+:(.+)$ ]] && {
        local rest="${BASH_REMATCH[1]}"
        local inner
        inner="$(_redact_credential_line "$rest" $(( depth + 1 )))"
        echo "${s%%:*}: ${inner}"
        return
    }
    [[ ${#s} -gt 220 ]] && s="${s:0:220}…"
    if [[ "$s" =~ ^([[:space:]]*)([A-Za-z0-9_.-]{1,72})([[:space:]]*)=([[:space:]]*)(.+)$ ]]; then
        local k="${BASH_REMATCH[2]}"
        local v="${BASH_REMATCH[5]}"
        v="${v## }"
        v="${v%% }"
        local n=${#v}
        echo "${k}=***REDACTED*** (length ${n})"
        return
    fi
    if [[ "$s" =~ ([Aa][Ww][Ss]_[Aa]ccess_[Kk]ey_[Ii][Dd][[:space:]]*=[[:space:]]*)([A-Za-z0-9/+]{16,}) ]]; then
        local pfx="${BASH_REMATCH[1]}"
        local key="${BASH_REMATCH[2]}"
        local tail="${key: -4}"
        echo "${pfx}${key:0:8}…${tail} (masked)"
        return
    fi
    if [[ "$s" =~ ([Aa][Ww][Ss]_[Ss]ecret_[Aa]ccess_[Kk]ey[[:space:]]*=[[:space:]]*)([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}***REDACTED*** (length ${#BASH_REMATCH[2]})"
        return
    fi
    if [[ "$s" =~ ^([[:alpha:]][[:alnum:].+-]*://)([^/@[:space:]]+):([^/@[:space:]]+)@([^[:space:]]+) ]]; then
        echo "${BASH_REMATCH[1]}***:***@${BASH_REMATCH[4]}"
        return
    fi
    # /etc/passwd-style "user:crypt_hash" (legacy shadow-in-passwd; hash may contain $)
    if [[ "$s" =~ ^([^:]+):(.+)$ ]] && [[ "$s" != *:*:* ]]; then
        local _u="${BASH_REMATCH[1]}"
        local _h="${BASH_REMATCH[2]}"
        if [[ ${#_h} -ge 10 && "$_h" != "x" && "$_h" != "*" && "$_h" != "!" && "$_h" =~ ^[[:graph:]]+$ ]]; then
            echo "${_u}: hash prefix ${_h:0:12}… (length ${#_h})"
            return
        fi
    fi
    # Inline key=value for common secret-like keys (anywhere in line)
    if [[ "$s" =~ (^|[[:space:];])([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Pp][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii][-_]?[Kk][Ee][Yy]|[Aa][Uu][Tt][Hh])([[:space:]]*)=([[:space:]]*)([^[:space:];]{4,}) ]]; then
        local _pre="${BASH_REMATCH[1]}"
        local _key="${BASH_REMATCH[2]}"
        local _val="${BASH_REMATCH[5]}"
        echo "${_pre}${_key}${BASH_REMATCH[3]}=${BASH_REMATCH[4]}***REDACTED*** (length ${#_val})"
        return
    fi
    # PostgreSQL .pgpass-style hostname:port:database:user:password
    if [[ "$s" =~ ^([^:]+):([^:]+):([^:]+):([^:]+):(.+)$ ]]; then
        local _pw="${BASH_REMATCH[5]}"
        echo "${BASH_REMATCH[1]}:${BASH_REMATCH[2]}:${BASH_REMATCH[3]}:${BASH_REMATCH[4]}:***REDACTED*** (length ${#_pw})"
        return
    fi
    echo "$s"
}

# Strip control chars and cap length for plaintext credential report lines (unsafe mode).
_sanitize_plaintext_credential_piece() {
    local s="$1"
    local max="${CREDENTIAL_PLAINTEXT_MAX:-4000}"
    s="${s//[$'\r\n\t']/ }"
    s="${s//[[:cntrl:]]/?}"
    [[ ${#s} -gt $max ]] && s="${s:0:max}…(truncated)"
    echo "$s"
}

# Last-pass scrub on stored preview blobs (merged segments).
_scrub_credential_preview_blob() {
    local blob="$1"
    [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]] && { echo "$blob"; return; }
    local out="" seg
    local IFS_bak="$IFS"
    IFS=';'
    for seg in $blob; do
        seg="${seg## }"
        seg="${seg%% }"
        [[ -z "$seg" ]] && continue
        seg="$(_redact_credential_line "$seg" 0)"
        out="${out:+${out} ; }${seg}"
    done
    IFS="$IFS_bak"
    echo "$out"
}

# Append a credential snippet to the finding keyed by title (semicolon-separated).
# Default: redacted. Set REPORT_FULL_SECRETS=1 (--report-full-secrets) for plaintext in reports.
append_credential_preview() {
    local title="$1"
    local piece="$2"
    [[ -z "$title" || -z "$piece" ]] && return
    if [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]]; then
        piece="$(_sanitize_plaintext_credential_piece "$piece")"
    else
        piece="$(_redact_credential_line "$piece")"
    fi
    [[ -z "$piece" ]] && return
    local cur="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
    if [[ -z "$cur" ]]; then
        _FINDING_CREDENTIAL_PREVIEW["$title"]="$piece"
    else
        _FINDING_CREDENTIAL_PREVIEW["$title"]="${cur} ; ${piece}"
    fi
    _FINDING_CREDENTIAL_PREVIEW["$title"]="$(_scrub_credential_preview_blob "${_FINDING_CREDENTIAL_PREVIEW[$title]}")"
}

add_finding() {
    local severity="$1"
    local category="$2"
    local cve="${3:--}"
    local title="$4"
    local detail="${5:-}"
    local exploit="${6:-}"
    local evidence="${7:-}"
    local remediation="${8:-}"
    local references="${9:-}"
    local mitre_id="${10:-}"

    local entry
    entry="${severity}|${category}|${cve}|${title}|${detail}|${exploit}"
    FINDINGS+=("$entry")

    [[ -n "$evidence" ]] && _FINDING_EVIDENCE["$title"]="$evidence"
    [[ -n "$remediation" ]] && _FINDING_REMEDIATION["$title"]="$remediation"
    [[ -n "$references" ]] && _FINDING_REFERENCES["$title"]="$references"
    [[ -n "$mitre_id" ]] && _FINDING_MITRE["$title"]="$mitre_id"

    case "${severity^^}" in
        CRITICAL) CRITICAL_COUNT=$(( CRITICAL_COUNT + 1 )) ;;
        HIGH)     HIGH_COUNT=$(( HIGH_COUNT + 1 )) ;;
        MEDIUM)   MEDIUM_COUNT=$(( MEDIUM_COUNT + 1 )) ;;
        LOW)      LOW_COUNT=$(( LOW_COUNT + 1 )) ;;
        INFO)     INFO_COUNT=$(( INFO_COUNT + 1 )) ;;
    esac

    log_finding "$severity" "$category" "$cve" "$title" "$detail" "$exploit"
}

get_total_findings() {
    echo $(( CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + INFO_COUNT ))
}

# ──────────────────────────────────────────────────────────────
# Advanced findings deduplication + EPSS/CVSS scoring + sort
# ──────────────────────────────────────────────────────────────
_severity_weight() {
    case "${1^^}" in
        CRITICAL) echo 0 ;; HIGH) echo 1 ;; MEDIUM) echo 2 ;;
        LOW) echo 3 ;; INFO) echo 4 ;; *) echo 5 ;;
    esac
}

_severity_rank() {
    case "${1^^}" in
        CRITICAL) echo 5 ;; HIGH) echo 4 ;; MEDIUM) echo 3 ;;
        LOW) echo 2 ;; INFO) echo 1 ;; *) echo 0 ;;
    esac
}

_higher_severity() {
    local a_rank b_rank
    a_rank=$(_severity_rank "$1")
    b_rank=$(_severity_rank "$2")
    [[ $a_rank -ge $b_rank ]] && echo "$1" || echo "$2"
}

_normalize_title() {
    local title="${1,,}"
    title="${title##confirmed: }"
    title="${title##vulnerable: }"
    title="${title#non-standard }"
    title="${title//[[:space:]]/ }"
    title="${title## }"
    title="${title%% }"
    echo "$title"
}

_extract_cve_from_title() {
    local title="$1"
    echo "$title" | grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' | head -1
}

_sort_findings() {
    [[ ${#FINDINGS[@]} -le 1 ]] && return

    # EPSS cache loaded externally before this call

    # --- Phase 1: CVE-based cross-module merge ---
    declare -A _cve_best_idx=()
    declare -A _cve_merged_detail=()
    declare -A _cve_merged_exploit=()
    local -a phase1=()
    local idx=0

    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"

        local effective_cve="$cve"
        [[ "$effective_cve" == "-" || -z "$effective_cve" ]] && \
            effective_cve=$(_extract_cve_from_title "$title")
        [[ -z "$effective_cve" ]] && effective_cve="-"

        if [[ "$effective_cve" != "-" && -n "${_cve_best_idx[$effective_cve]+x}" ]]; then
            local prev_idx="${_cve_best_idx[$effective_cve]}"
            local prev="${phase1[$prev_idx]}"
            IFS='|' read -r prev_sev prev_cat prev_cve prev_title prev_detail prev_exploit <<< "$prev"

            local merged_sev
            merged_sev=$(_higher_severity "$severity" "$prev_sev")

            local merged_detail="$prev_detail"
            if [[ -n "$detail" && "$detail" != "$prev_detail" ]]; then
                merged_detail="${prev_detail} ; ${detail}"
            fi

            local merged_exploit="$prev_exploit"
            if [[ -n "$exploit" && "$exploit" != "-" && "$exploit" != "$prev_exploit" ]]; then
                if [[ -z "$prev_exploit" || "$prev_exploit" == "-" ]]; then
                    merged_exploit="$exploit"
                fi
            fi

            local merged_title="$prev_title"
            [[ "$merged_sev" == "$severity" && "$severity" != "$prev_sev" ]] && merged_title="$title"

            # Merge enrichment data (evidence, remediation, references, mitre)
            local _old_ev="${_FINDING_EVIDENCE[$prev_title]:-}"
            local _new_ev="${_FINDING_EVIDENCE[$title]:-}"
            [[ -n "$_new_ev" && "$_new_ev" != "$_old_ev" ]] && \
                _FINDING_EVIDENCE["$merged_title"]="${_old_ev:+${_old_ev} ; }${_new_ev}"

            local _old_rem="${_FINDING_REMEDIATION[$prev_title]:-}"
            local _new_rem="${_FINDING_REMEDIATION[$title]:-}"
            if [[ -n "$_new_rem" && -z "$_old_rem" ]]; then
                _FINDING_REMEDIATION["$merged_title"]="$_new_rem"
            elif [[ -n "$_old_rem" ]]; then
                _FINDING_REMEDIATION["$merged_title"]="$_old_rem"
            fi

            local _old_ref="${_FINDING_REFERENCES[$prev_title]:-}"
            local _new_ref="${_FINDING_REFERENCES[$title]:-}"
            [[ -n "$_new_ref" && "$_new_ref" != "$_old_ref" ]] && \
                _FINDING_REFERENCES["$merged_title"]="${_old_ref:+${_old_ref} ; }${_new_ref}"

            local _old_m="${_FINDING_MITRE[$prev_title]:-}"
            local _new_m="${_FINDING_MITRE[$title]:-}"
            [[ -n "$_new_m" && -z "$_old_m" ]] && _FINDING_MITRE["$merged_title"]="$_new_m"

            local _old_cp="${_FINDING_CREDENTIAL_PREVIEW[$prev_title]:-}"
            local _new_cp="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
            if [[ -n "$_old_cp" || -n "$_new_cp" ]]; then
                _FINDING_CREDENTIAL_PREVIEW["$merged_title"]="${_old_cp:+${_old_cp} ; }${_new_cp}"
                [[ "${REPORT_FULL_SECRETS:-0}" != "1" ]] && \
                    _FINDING_CREDENTIAL_PREVIEW["$merged_title"]="$(_scrub_credential_preview_blob "${_FINDING_CREDENTIAL_PREVIEW[$merged_title]}")"
                unset '_FINDING_CREDENTIAL_PREVIEW[$prev_title]'
                [[ "$title" != "$prev_title" ]] && unset '_FINDING_CREDENTIAL_PREVIEW[$title]'
            fi

            phase1[$prev_idx]="${merged_sev}|${prev_cat}|${effective_cve}|${merged_title}|${merged_detail}|${merged_exploit}"
            _cve_merged_detail["$effective_cve"]="$merged_detail"
            _cve_merged_exploit["$effective_cve"]="$merged_exploit"
        else
            _cve_best_idx["$effective_cve"]=$idx
            phase1+=("${severity}|${category}|${effective_cve}|${title}|${detail}|${exploit}")
            idx=$(( idx + 1 ))
        fi
    done

    # --- Phase 2: Title similarity dedup ---
    declare -A _seen_normalized=()
    local -a phase2=()

    for finding in "${phase1[@]}"; do
        [[ -z "$finding" ]] && continue
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"

        local norm_key
        norm_key=$(_normalize_title "$title")

        if [[ -n "${_seen_normalized[$norm_key]+x}" ]]; then
            local prev_p2_idx="${_seen_normalized[$norm_key]}"
            local prev2="${phase2[$prev_p2_idx]}"
            IFS='|' read -r prev2_sev prev2_cat prev2_cve prev2_title prev2_detail prev2_exploit <<< "$prev2"

            local keep_sev
            keep_sev=$(_higher_severity "$severity" "$prev2_sev")

            local _cp2_prev="${_FINDING_CREDENTIAL_PREVIEW[$prev2_title]:-}"
            local _cp2_new="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"

            if [[ "$keep_sev" == "$severity" && "$severity" != "$prev2_sev" ]]; then
                phase2[$prev_p2_idx]="$finding"
                if [[ -n "$_cp2_prev" || -n "$_cp2_new" ]]; then
                    _FINDING_CREDENTIAL_PREVIEW["$title"]="${_cp2_prev:+${_cp2_prev} ; }${_cp2_new}"
                    [[ "${REPORT_FULL_SECRETS:-0}" != "1" ]] && \
                        _FINDING_CREDENTIAL_PREVIEW["$title"]="$(_scrub_credential_preview_blob "${_FINDING_CREDENTIAL_PREVIEW[$title]}")"
                    [[ "$prev2_title" != "$title" ]] && unset '_FINDING_CREDENTIAL_PREVIEW[$prev2_title]'
                fi
            else
                if [[ -n "$_cp2_prev" || -n "$_cp2_new" ]]; then
                    _FINDING_CREDENTIAL_PREVIEW["$prev2_title"]="${_cp2_prev:+${_cp2_prev} ; }${_cp2_new}"
                    [[ "${REPORT_FULL_SECRETS:-0}" != "1" ]] && \
                        _FINDING_CREDENTIAL_PREVIEW["$prev2_title"]="$(_scrub_credential_preview_blob "${_FINDING_CREDENTIAL_PREVIEW[$prev2_title]}")"
                    [[ "$title" != "$prev2_title" ]] && unset '_FINDING_CREDENTIAL_PREVIEW[$title]'
                fi
            fi
        else
            _seen_normalized["$norm_key"]=${#phase2[@]}
            phase2+=("$finding")
        fi
    done

    # --- Phase 3: Compute priority scores inline (no subshells) ---
    local -a scored=()
    for finding in "${phase2[@]}"; do
        [[ -z "$finding" ]] && continue
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"

        local srank=0
        case "${severity^^}" in
            CRITICAL) srank=5 ;; HIGH) srank=4 ;; MEDIUM) srank=3 ;;
            LOW) srank=2 ;; INFO) srank=1 ;; *) srank=0 ;;
        esac

        local pscore="0"
        local has_exploit=0
        [[ -n "$exploit" && "$exploit" != "-" ]] && has_exploit=1

        local cvss_val="0"
        local epss_val="0"
        if [[ -n "$cve" && "$cve" != "-" && ${#_CVSS_CACHE[@]} -gt 0 ]]; then
            cvss_val="${_CVSS_CACHE[$cve]:-0}"
            epss_val="${_EPSS_CACHE[$cve]:-0}"
            # Sanitize: strip non-numeric chars except dot
            cvss_val="${cvss_val//[^0-9.]/}"
            epss_val="${epss_val//[^0-9.]/}"
            [[ -z "$cvss_val" ]] && cvss_val="0"
            [[ -z "$epss_val" ]] && epss_val="0"
        fi

        local cvss_int="${cvss_val%%.*}"
        local epss_int="${epss_val%%.*}"
        [[ -z "$cvss_int" ]] && cvss_int=0
        [[ -z "$epss_int" ]] && epss_int=0

        if [[ $cvss_int -gt 0 || $epss_int -gt 0 ]]; then
            local expl_bonus=0
            [[ $has_exploit -eq 1 ]] && expl_bonus=25
            pscore=$(( cvss_int * 35 + epss_int * 400 + expl_bonus ))
            [[ $pscore -gt 1000 ]] && pscore=1000
        else
            case "${severity^^}" in
                CRITICAL) pscore=100 ;; HIGH) pscore=60 ;; MEDIUM) pscore=30 ;;
                LOW) pscore=10 ;; *) pscore=0 ;;
            esac
        fi

        scored+=("${srank}:${pscore}:${finding}")
    done

    # --- Phase 4: Bucket sort by severity, then by score within bucket ---
    local -a crit=() high=() med=() low=() inf=()
    for entry in "${scored[@]}"; do
        local srank="${entry%%:*}"
        case "$srank" in
            5) crit+=("$entry") ;; 4) high+=("$entry") ;;
            3) med+=("$entry")  ;; 2) low+=("$entry")  ;;
            *) inf+=("$entry")  ;;
        esac
    done

    FINDINGS=()
    local bucket
    for bucket in "${crit[@]}" "${high[@]}" "${med[@]}" "${low[@]}" "${inf[@]}"; do
        [[ -z "$bucket" ]] && continue
        local stripped="${bucket#*:}"
        stripped="${stripped#*:}"
        FINDINGS+=("$stripped")
    done

    CRITICAL_COUNT=0; HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0; INFO_COUNT=0
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity _ <<< "$finding"
        case "${severity^^}" in
            CRITICAL) CRITICAL_COUNT=$(( CRITICAL_COUNT + 1 )) ;;
            HIGH)     HIGH_COUNT=$(( HIGH_COUNT + 1 )) ;;
            MEDIUM)   MEDIUM_COUNT=$(( MEDIUM_COUNT + 1 )) ;;
            LOW)      LOW_COUNT=$(( LOW_COUNT + 1 )) ;;
            *)        INFO_COUNT=$(( INFO_COUNT + 1 )) ;;
        esac
    done
}

# ──────────────────────────────────────────────────────────────
# User confirmation prompt (before exploitation)
# ──────────────────────────────────────────────────────────────
confirm_action() {
    local prompt="$1"
    local risk="${2:-MEDIUM}"
    local color
    color=$(color_for_severity "$risk")

    echo -e "\n  ${color}[!] ${prompt}${RESET}"
    echo -e "  ${BOLD_YELLOW}Risk Level: ${risk}${RESET}"
    echo -ne "  Continue? [y/N]: "
    read -r -t 30 answer
    [[ "${answer,,}" == "y" ]]
}

# ──────────────────────────────────────────────────────────────
# Checksum and hash helpers
# ──────────────────────────────────────────────────────────────
sha256sum_file() {
    local file="$1"
    if cmd_exists sha256sum; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    elif cmd_exists shasum; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    fi
}

# ──────────────────────────────────────────────────────────────
# Pseudo-random ID generator (log correlation)
# ──────────────────────────────────────────────────────────────
gen_id() {
    local len="${1:-8}"
    tr -dc 'a-f0-9' < /dev/urandom 2>/dev/null | head -c "$len" || date +%s | sha256sum | head -c "$len"
}
