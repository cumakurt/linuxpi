#!/usr/bin/env bash
# core/reporter.sh - Multi-format report generation (text/json/html/xml/markdown)

# ──────────────────────────────────────────────────────────────
# Inline scoring helpers (avoids subshell spawning in report loops)
# ──────────────────────────────────────────────────────────────
_compute_priority_inline() {
    local cve="$1" severity="$2" exploit="$3"
    local cvss_val="${_CVSS_CACHE[$cve]:-0.0}"
    local epss_val="${_EPSS_CACHE[$cve]:-0.0}"
    cvss_val="${cvss_val//[^0-9.]/}"; [[ -z "$cvss_val" ]] && cvss_val="0.0"
    epss_val="${epss_val//[^0-9.]/}"; [[ -z "$epss_val" ]] && epss_val="0.0"
    local has_expl=0
    [[ -n "$exploit" && "$exploit" != "-" ]] && has_expl=1
    local cvss_i="${cvss_val%%.*}"; [[ -z "$cvss_i" ]] && cvss_i=0
    local epss_i="${epss_val%%.*}"; [[ -z "$epss_i" ]] && epss_i=0

    if [[ $cvss_i -gt 0 || $epss_i -gt 0 ]]; then
        local eb=0; [[ $has_expl -eq 1 ]] && eb=25
        local raw=$(( cvss_i * 35 + epss_i * 400 + eb ))
        [[ $raw -gt 1000 ]] && raw=1000
        local whole=$(( raw / 10 ))
        local frac=$(( raw % 10 ))
        echo "${whole}.${frac}"
    else
        local sw=0
        case "${severity^^}" in
            CRITICAL) sw=100 ;; HIGH) sw=60 ;; MEDIUM) sw=30 ;;
            LOW) sw=10 ;; *) sw=0 ;;
        esac
        local whole=$(( sw / 10 ))
        local frac=$(( sw % 10 ))
        echo "${whole}.${frac}"
    fi
}

_compute_tier_inline() {
    local score="$1"
    local int_part="${score%%.*}"
    [[ -z "$int_part" ]] && int_part=0
    if [[ $int_part -ge 8 ]]; then echo "IMMINENT"
    elif [[ $int_part -ge 6 ]]; then echo "LIKELY"
    elif [[ $int_part -ge 4 ]]; then echo "POSSIBLE"
    elif [[ $int_part -ge 2 ]]; then echo "UNLIKELY"
    else echo "MINIMAL"; fi
}

_cred_block_heading() {
    [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]] && echo "Credential capture (plaintext — UNSAFE)" || echo "Credential hints (redacted)"
}

# ──────────────────────────────────────────────────────────────
# Report entry point
# ──────────────────────────────────────────────────────────────
generate_report() {
    local format="${OUTPUT_FORMAT:-text}"
    local output_file="${OUTPUT_FILE:-}"
    local scan_end
    scan_end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    case "$format" in
        text)     report_text ;;
        json)     report_json "$scan_end" ;;
        html)     report_html "$scan_end" ;;
        xml)      report_xml "$scan_end" ;;
        markdown) report_markdown "$scan_end" ;;
        *)        report_text ;;
    # With -o/--output: write only to the file (no tee — avoids dumping HTML/JSON/XML to the TTY).
    esac | if [[ -n "$output_file" ]]; then
        cat > "$output_file"
        print_good "Report saved: $output_file" >&2
    else
        cat
    fi
}

# ──────────────────────────────────────────────────────────────
# TEXT report (default terminal output)
# ──────────────────────────────────────────────────────────────
report_text() {
    print_section "SCAN SUMMARY"

    echo -e "  ${BOLD_WHITE}Target:${RESET}       ${SYSTEM_HOSTNAME} (${SYSTEM_DISTRO} ${SYSTEM_DISTRO_VER})"
    echo -e "  ${BOLD_WHITE}Kernel:${RESET}       ${SYSTEM_KERNEL}"
    echo -e "  ${BOLD_WHITE}User:${RESET}         ${SYSTEM_USER} (UID=${SYSTEM_UID})"
    echo -e "  ${BOLD_WHITE}Scan Time:${RESET}    $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo -e "  ${BOLD_RED}CRITICAL: ${CRITICAL_COUNT}${RESET}  ${BOLD_RED}HIGH: ${HIGH_COUNT}${RESET}  ${BOLD_YELLOW}MEDIUM: ${MEDIUM_COUNT}${RESET}  ${BOLD_CYAN}LOW: ${LOW_COUNT}${RESET}  ${CYAN}INFO: ${INFO_COUNT}${RESET}"
    echo ""
    echo -e "  ${GREY}Developed by ${TOOL_AUTHOR_NAME} <${TOOL_AUTHOR_EMAIL}>${RESET}"
    echo -e "  ${GREY}${TOOL_AUTHOR_LINKEDIN}${RESET}"
    echo ""

    if [[ $(get_total_findings) -eq 0 ]]; then
        print_good "No privilege escalation vectors found."
        return
    fi

    print_section "FINDINGS"

    local current_severity=""
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"

        if [[ "$severity" != "$current_severity" ]]; then
            current_severity="$severity"
            local color
            color=$(color_for_severity "$severity")
            echo -e "\n  ${color}━━━ ${severity} ━━━${RESET}"
        fi

        print_finding "$severity" "$title" "$detail"

        local f_evidence="${_FINDING_EVIDENCE[$title]:-}"
        local f_cred_preview="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
        local f_remediation="${_FINDING_REMEDIATION[$title]:-}"
        local f_references="${_FINDING_REFERENCES[$title]:-}"
        local f_mitre="${_FINDING_MITRE[$title]:-}"

        echo -e "         ${GREY}Category: ${category}${RESET}"

        if [[ -n "$f_mitre" ]]; then
            echo -e "         ${GREY}MITRE ATT&CK: ${f_mitre}${RESET}"
        fi

        if [[ -n "$cve" && "$cve" != "-" ]]; then
            local r_epss="${_EPSS_CACHE[$cve]:-0.0}"
            local r_cvss="${_CVSS_CACHE[$cve]:-0.0}"
            local r_vec="${_CVSS_VECTOR_CACHE[$cve]:--}"

            local r_pscore r_ptier
            r_pscore=$(_compute_priority_inline "$cve" "$severity" "$exploit")
            r_ptier=$(_compute_tier_inline "$r_pscore")

            echo -e "         ${GREY}CVE: ${cve}${RESET}"

            local score_line="         ${GREY}CVSS: ${r_cvss}"
            [[ "$r_vec" != "-" ]] && score_line+="  Vector: ${r_vec}"
            score_line+="${RESET}"
            echo -e "$score_line"

            local epss_color="${GREY}"
            local epss_int="${r_epss%%.*}"
            [[ -z "$epss_int" ]] && epss_int=0
            [[ $epss_int -ge 1 ]] && epss_color="${BOLD_RED}"

            local tier_color="${GREY}"
            case "$r_ptier" in
                IMMINENT) tier_color="${BOLD_RED}" ;;
                LIKELY)   tier_color="${BOLD_YELLOW}" ;;
                POSSIBLE) tier_color="${YELLOW}" ;;
            esac

            echo -e "         ${epss_color}EPSS: ${r_epss} (probability of exploitation)${RESET}"
            echo -e "         ${tier_color}Priority: ${r_pscore}/10.0 [${r_ptier}]${RESET}"
        fi

        if [[ -n "$f_evidence" ]]; then
            echo -e "         ${BOLD_CYAN}Evidence:${RESET}"
            local IFS_bak="$IFS"
            IFS=';'
            for ev_item in $f_evidence; do
                ev_item="${ev_item## }"
                ev_item="${ev_item%% }"
                [[ -n "$ev_item" ]] && echo -e "           ${GREY}• ${ev_item}${RESET}"
            done
            IFS="$IFS_bak"
        fi

        if [[ -n "$f_cred_preview" ]]; then
            echo -e "         ${BOLD_MAGENTA}$(_cred_block_heading):${RESET}"
            local IFS_bak2="$IFS"
            IFS=';'
            for cp_item in $f_cred_preview; do
                cp_item="${cp_item## }"
                cp_item="${cp_item%% }"
                [[ -n "$cp_item" ]] && echo -e "           ${GREY}• ${cp_item}${RESET}"
            done
            IFS="$IFS_bak2"
        fi

        if [[ "${SUGGEST_EXPLOITS:-1}" == "1" && -n "$exploit" && "$exploit" != "-" ]]; then
            echo -e "         ${BOLD_GREEN}Exploit:${RESET} ${exploit}"
        fi

        if [[ -n "$f_remediation" ]]; then
            echo -e "         ${BOLD_YELLOW}Remediation:${RESET} ${f_remediation}"
        fi

        if [[ -n "$f_references" ]]; then
            echo -e "         ${GREY}References: ${f_references}${RESET}"
        fi
    done

    echo ""
    generate_attack_paths
}

# ──────────────────────────────────────────────────────────────
# JSON report (machine-readable)
# ──────────────────────────────────────────────────────────────
report_json() {
    local scan_end="$1"

    local total
    total=$(get_total_findings)

    printf '{\n'
    printf '  "metadata": {\n'
    printf '    "tool": "linuxpi",\n'
    printf '    "version": "%s",\n' "$(json_str "${TOOL_VERSION:-1.0.0}")"
    printf '    "scan_time": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '    "target": "%s",\n' "$SYSTEM_HOSTNAME"
    printf '    "report_full_secrets": %s,\n' "$( [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]] && echo true || echo false )"
    printf '    "developer": {\n'
    printf '      "name": "%s",\n' "$(json_str "${TOOL_AUTHOR_NAME:-}")"
    printf '      "email": "%s",\n' "$(json_str "${TOOL_AUTHOR_EMAIL:-}")"
    printf '      "linkedin": "%s"\n' "$(json_str "${TOOL_AUTHOR_LINKEDIN:-}")"
    printf '    }\n'
    printf '  },\n'

    printf '  "system": {\n'
    printf '    "hostname": "%s",\n' "$SYSTEM_HOSTNAME"
    printf '    "distro": "%s",\n' "$SYSTEM_DISTRO"
    printf '    "distro_version": "%s",\n' "$SYSTEM_DISTRO_VER"
    printf '    "kernel": "%s",\n' "$SYSTEM_KERNEL"
    printf '    "arch": "%s",\n' "$SYSTEM_ARCH"
    printf '    "current_user": "%s",\n' "$SYSTEM_USER"
    printf '    "uid": %s,\n' "$SYSTEM_UID"
    printf '    "is_container": %s,\n' "$( [[ "$SYSTEM_IS_CONTAINER" == "1" ]] && echo true || echo false )"
    printf '    "container_type": "%s",\n' "${SYSTEM_CONTAINER_TYPE:-}"
    printf '    "is_cloud": %s,\n' "$( [[ "$SYSTEM_IS_CLOUD" == "1" ]] && echo true || echo false )"
    printf '    "cloud_provider": "%s"\n' "${SYSTEM_CLOUD_PROVIDER:-}"
    printf '  },\n'

    printf '  "summary": {\n'
    printf '    "total": %d,\n' "$total"
    printf '    "critical": %d,\n' "$CRITICAL_COUNT"
    printf '    "high": %d,\n' "$HIGH_COUNT"
    printf '    "medium": %d,\n' "$MEDIUM_COUNT"
    printf '    "low": %d,\n' "$LOW_COUNT"
    printf '    "info": %d\n' "$INFO_COUNT"
    printf '  },\n'

    printf '  "findings": [\n'
    local i=0
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"
        [[ $i -gt 0 ]] && printf ',\n'

        local f_epss="${_EPSS_CACHE[$cve]:-0.0}"
        local f_cvss="${_CVSS_CACHE[$cve]:-0.0}"
        local f_cvss_vec="${_CVSS_VECTOR_CACHE[$cve]:--}"
        f_epss="${f_epss//[^0-9.]/}"; [[ -z "$f_epss" ]] && f_epss="0.0"
        f_cvss="${f_cvss//[^0-9.]/}"; [[ -z "$f_cvss" ]] && f_cvss="0.0"
        local f_pscore f_ptier
        f_pscore=$(_compute_priority_inline "$cve" "$severity" "$exploit")
        f_ptier=$(_compute_tier_inline "$f_pscore")

        local j_evidence="${_FINDING_EVIDENCE[$title]:-}"
        local j_cred_preview="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
        local j_remediation="${_FINDING_REMEDIATION[$title]:-}"
        local j_references="${_FINDING_REFERENCES[$title]:-}"
        local j_mitre="${_FINDING_MITRE[$title]:-}"

        printf '    {\n'
        printf '      "id": %d,\n' "$((i+1))"
        printf '      "severity": "%s",\n' "$severity"
        printf '      "category": "%s",\n' "$category"
        printf '      "cve": "%s",\n' "$(json_str "$cve")"
        printf '      "title": "%s",\n' "$(json_str "$title")"
        printf '      "detail": "%s",\n' "$(json_str "$detail")"
        printf '      "exploit": "%s",\n' "$(json_str "$exploit")"
        printf '      "evidence": "%s",\n' "$(json_str "$j_evidence")"
        printf '      "credentials_redacted": "%s",\n' "$(json_str "$j_cred_preview")"
        printf '      "remediation": "%s",\n' "$(json_str "$j_remediation")"
        printf '      "references": "%s",\n' "$(json_str "$j_references")"
        printf '      "mitre_attack": "%s",\n' "$(json_str "$j_mitre")"
        printf '      "scoring": {\n'
        printf '        "cvss_base": %s,\n' "$f_cvss"
        printf '        "cvss_vector": "%s",\n' "$(json_str "$f_cvss_vec")"
        printf '        "epss_score": %s,\n' "$f_epss"
        printf '        "priority_score": %s,\n' "$f_pscore"
        printf '        "priority_tier": "%s"\n' "$f_ptier"
        printf '      }\n'
        printf '    }'
        i=$(( i + 1 ))
    done
    printf '\n  ]\n'
    printf '}\n'
}

json_str() {
    local s="$1"
    # Strip control characters so JSON stays valid and secrets cannot hide in \u0000 etc.
    s="$(printf '%s' "$s" | sed 's/[[:cntrl:]]/ /g')"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    echo -n "$s"
}

# ──────────────────────────────────────────────────────────────
# HTML report
# ──────────────────────────────────────────────────────────────
report_html() {
    local scan_end="$1"
    local tpl="${SCRIPT_DIR}/output/templates/html_report.tpl"

    if [[ -f "$tpl" ]]; then
        _render_html_template "$tpl" "$scan_end"
    else
        _generate_html_inline "$scan_end"
    fi
}

_render_html_template() {
    local tpl_file="$1"
    local scan_end="$2"
    local total
    total=$(get_total_findings)

    local risk_score=0
    (( risk_score = CRITICAL_COUNT * 10 + HIGH_COUNT * 7 + MEDIUM_COUNT * 4 + LOW_COUNT * 1 ))
    [[ $risk_score -gt 100 ]] && risk_score=100

    local risk_class="low"
    [[ $risk_score -ge 15 ]] && risk_class="medium"
    [[ $risk_score -ge 40 ]] && risk_class="high"
    [[ $risk_score -ge 70 ]] && risk_class="critical"

    local max_count=$total
    [[ $max_count -lt 1 ]] && max_count=1
    local crit_pct=$(( CRITICAL_COUNT * 100 / max_count ))
    local high_pct=$(( HIGH_COUNT * 100 / max_count ))
    local med_pct=$(( MEDIUM_COUNT * 100 / max_count ))
    local low_pct=$(( LOW_COUNT * 100 / max_count ))
    local info_pct=$(( INFO_COUNT * 100 / max_count ))
    [[ $crit_pct -lt 5 && $CRITICAL_COUNT -gt 0 ]] && crit_pct=5
    [[ $high_pct -lt 5 && $HIGH_COUNT -gt 0 ]] && high_pct=5
    [[ $med_pct -lt 5 && $MEDIUM_COUNT -gt 0 ]] && med_pct=5
    [[ $low_pct -lt 5 && $LOW_COUNT -gt 0 ]] && low_pct=5
    [[ $info_pct -lt 5 && $INFO_COUNT -gt 0 ]] && info_pct=5

    local findings_html=""
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"
        local cve_html=""
        [[ -n "$cve" && "$cve" != "-" ]] && cve_html="<span class=\"cve-tag\">${cve}</span>"

        local exploit_html=""
        if [[ -n "$exploit" && "$exploit" != "-" ]]; then
            exploit_html="<div class=\"finding-exploit\">$(html_escape "$exploit")</div>"
        fi

        local scoring_tpl_html=""
        if [[ -n "$cve" && "$cve" != "-" ]]; then
            local t_epss="${_EPSS_CACHE[$cve]:-0.0}"
            local t_cvss="${_CVSS_CACHE[$cve]:-0.0}"
            t_epss="${t_epss//[^0-9.]/}"; [[ -z "$t_epss" ]] && t_epss="0.0"
            t_cvss="${t_cvss//[^0-9.]/}"; [[ -z "$t_cvss" ]] && t_cvss="0.0"
            local t_pscore t_ptier
            t_pscore=$(_compute_priority_inline "$cve" "$severity" "$exploit")
            t_ptier=$(_compute_tier_inline "$t_pscore")
            scoring_tpl_html="<div class=\"finding-scoring\">CVSS:${t_cvss} | EPSS:${t_epss} | Priority:${t_pscore}/10 [${t_ptier}]</div>"
        fi

        local t_mitre="${_FINDING_MITRE[$title]:-}"
        local mitre_tpl=""
        [[ -n "$t_mitre" ]] && mitre_tpl="<span class=\"mitre-tag\">${t_mitre}</span>"

        local t_evidence="${_FINDING_EVIDENCE[$title]:-}"
        local evidence_tpl=""
        if [[ -n "$t_evidence" ]]; then
            evidence_tpl="<div class=\"evidence\"><div class=\"evidence-title\">Evidence</div><ul>"
            local IFS_bak="$IFS"; IFS=';'
            for ev in $t_evidence; do
                ev="${ev## }"; ev="${ev%% }"
                [[ -n "$ev" ]] && evidence_tpl+="<li>$(html_escape "$ev")</li>"
            done
            IFS="$IFS_bak"
            evidence_tpl+="</ul></div>"
        fi

        local t_cred_preview="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
        local cred_preview_tpl=""
        if [[ -n "$t_cred_preview" ]]; then
            cred_preview_tpl="<div class=\"cred-preview\"><div class=\"cred-preview-title\">$(_cred_block_heading)</div><ul>"
            local IFS_bakc="$IFS"; IFS=';'
            for cp in $t_cred_preview; do
                cp="${cp## }"; cp="${cp%% }"
                [[ -n "$cp" ]] && cred_preview_tpl+="<li>$(html_escape "$cp")</li>"
            done
            IFS="$IFS_bakc"
            cred_preview_tpl+="</ul></div>"
        fi

        local t_remediation="${_FINDING_REMEDIATION[$title]:-}"
        local remediation_tpl=""
        [[ -n "$t_remediation" ]] && remediation_tpl="<div class=\"remediation\"><div class=\"remediation-title\">Remediation</div><div class=\"remediation-text\">$(html_escape "$t_remediation")</div></div>"

        local t_references="${_FINDING_REFERENCES[$title]:-}"
        local references_tpl=""
        if [[ -n "$t_references" ]]; then
            references_tpl="<div class=\"references\">Ref: $(html_escape "$t_references")</div>"
        fi

        findings_html+="<div class=\"finding ${severity}\"><div class=\"finding-header\">"
        findings_html+="<span class=\"sev-badge badge-${severity}\">${severity}</span>"
        findings_html+="<span class=\"cat-badge\">${category}</span>"
        findings_html+="${cve_html}${mitre_tpl}"
        findings_html+="<span class=\"finding-title\">$(html_escape "$title")</span>"
        findings_html+="</div>"
        [[ -n "$detail" ]] && findings_html+="<div class=\"finding-detail\">$(html_escape "$detail")</div>"
        findings_html+="${scoring_tpl_html}"
        findings_html+="${evidence_tpl}"
        findings_html+="${cred_preview_tpl}"
        findings_html+="${exploit_html}"
        findings_html+="${remediation_tpl}"
        findings_html+="${references_tpl}</div>"
    done

    local container_val="N/A"
    [[ "$SYSTEM_IS_CONTAINER" == "1" ]] && container_val="${SYSTEM_CONTAINER_TYPE}"
    local cloud_val="N/A"
    [[ "$SYSTEM_IS_CLOUD" == "1" ]] && cloud_val="${SYSTEM_CLOUD_PROVIDER}"

    local output
    output=$(<"$tpl_file")
    output="${output//\{\{HOSTNAME\}\}/$SYSTEM_HOSTNAME}"
    output="${output//\{\{DISTRO\}\}/$SYSTEM_DISTRO}"
    output="${output//\{\{DISTRO_VER\}\}/$SYSTEM_DISTRO_VER}"
    output="${output//\{\{KERNEL\}\}/$SYSTEM_KERNEL}"
    output="${output//\{\{ARCH\}\}/$SYSTEM_ARCH}"
    output="${output//\{\{CURRENT_USER\}\}/$SYSTEM_USER}"
    output="${output//\{\{UID\}\}/$SYSTEM_UID}"
    output="${output//\{\{GID\}\}/$SYSTEM_GID}"
    output="${output//\{\{SHELL\}\}/$SYSTEM_SHELL}"
    output="${output//\{\{INIT_SYSTEM\}\}/$SYSTEM_INIT}"
    output="${output//\{\{CONTAINER_TYPE\}\}/$container_val}"
    output="${output//\{\{CLOUD_PROVIDER\}\}/$cloud_val}"
    output="${output//\{\{SCAN_TIME\}\}/$scan_end}"
    output="${output//\{\{RISK_SCORE\}\}/$risk_score}"
    output="${output//\{\{RISK_CLASS\}\}/$risk_class}"
    output="${output//\{\{TOTAL_COUNT\}\}/$total}"
    output="${output//\{\{CRITICAL_COUNT\}\}/$CRITICAL_COUNT}"
    output="${output//\{\{HIGH_COUNT\}\}/$HIGH_COUNT}"
    output="${output//\{\{MEDIUM_COUNT\}\}/$MEDIUM_COUNT}"
    output="${output//\{\{LOW_COUNT\}\}/$LOW_COUNT}"
    output="${output//\{\{INFO_COUNT\}\}/$INFO_COUNT}"
    output="${output//\{\{CRITICAL_PCT\}\}/$crit_pct}"
    output="${output//\{\{HIGH_PCT\}\}/$high_pct}"
    output="${output//\{\{MEDIUM_PCT\}\}/$med_pct}"
    output="${output//\{\{LOW_PCT\}\}/$low_pct}"
    output="${output//\{\{INFO_PCT\}\}/$info_pct}"
    output="${output//\{\{FINDINGS_HTML\}\}/$findings_html}"
    output="${output//\{\{TOOL_VERSION\}\}/${TOOL_VERSION}}"
    output="${output//\{\{AUTHOR_NAME\}\}/${TOOL_AUTHOR_NAME}}"
    output="${output//\{\{AUTHOR_EMAIL\}\}/${TOOL_AUTHOR_EMAIL}}"
    output="${output//\{\{AUTHOR_LINKEDIN\}\}/${TOOL_AUTHOR_LINKEDIN}}"

    echo "$output"
}

_generate_html_inline() {
    local scan_end="$1"
    local total
    total=$(get_total_findings)

    cat << HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LinuxPi Report - ${SYSTEM_HOSTNAME}</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #111827; --surface2: #1a2234;
    --border: #1e2d40; --text: #e2e8f0; --text-dim: #64748b;
    --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --info: #06b6d4; --success: #22c55e;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; }
  .header { background: linear-gradient(135deg, #0f172a, #1e1b4b); padding: 2rem; border-bottom: 1px solid var(--border); }
  .header h1 { color: var(--critical); font-size: 1.8rem; letter-spacing: 0.1em; }
  .header .subtitle { color: var(--text-dim); margin-top: 0.5rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 2rem 0; }
  .summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; }
  .summary-card .count { font-size: 2.5rem; font-weight: bold; }
  .summary-card .label { color: var(--text-dim); font-size: 0.8rem; margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 0.1em; }
  .critical .count { color: var(--critical); }
  .high .count     { color: var(--high); }
  .medium .count   { color: var(--medium); }
  .low .count      { color: var(--low); }
  .info-c .count   { color: var(--info); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.5rem; margin: 0.8rem 0; border-left: 4px solid; }
  .finding.CRITICAL { border-left-color: var(--critical); }
  .finding.HIGH     { border-left-color: var(--high); }
  .finding.MEDIUM   { border-left-color: var(--medium); }
  .finding.LOW      { border-left-color: var(--low); }
  .finding.INFO     { border-left-color: var(--info); }
  .finding .sev-badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 0.5rem; }
  .finding .title { font-size: 1rem; font-weight: bold; }
  .finding .detail { color: var(--text-dim); font-size: 0.85rem; margin-top: 0.5rem; }
  .finding .exploit { background: var(--surface2); border-radius: 4px; padding: 0.5rem; margin-top: 0.5rem; font-size: 0.8rem; color: var(--success); }
  .finding .cve-tag { display: inline-block; background: rgba(239,68,68,0.1); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); border-radius: 4px; padding: 0.1rem 0.4rem; font-size: 0.75rem; margin-left: 0.5rem; }
  .finding .mitre-tag { display: inline-block; background: rgba(59,130,246,0.1); color: var(--low); border: 1px solid rgba(59,130,246,0.3); border-radius: 4px; padding: 0.1rem 0.4rem; font-size: 0.75rem; margin-left: 0.3rem; }
  .finding .scoring { background: var(--surface2); border-radius: 4px; padding: 0.4rem 0.6rem; margin-top: 0.5rem; font-size: 0.8rem; color: var(--info); font-family: monospace; letter-spacing: 0.03em; }
  .finding .evidence { background: rgba(6,182,212,0.05); border: 1px solid rgba(6,182,212,0.15); border-radius: 4px; padding: 0.5rem 0.7rem; margin-top: 0.5rem; font-size: 0.8rem; color: var(--info); }
  .finding .evidence-title { font-weight: bold; color: var(--info); margin-bottom: 0.3rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .finding .evidence ul { list-style: none; padding-left: 0; margin: 0; }
  .finding .evidence li { padding: 0.15rem 0; color: var(--text-dim); }
  .finding .evidence li::before { content: "▸ "; color: var(--info); }
  .finding .cred-preview { background: rgba(168,85,247,0.06); border: 1px solid rgba(168,85,247,0.2); border-radius: 4px; padding: 0.5rem 0.7rem; margin-top: 0.5rem; font-size: 0.8rem; color: #c4b5fd; }
  .finding .cred-preview-title { font-weight: bold; color: #a78bfa; margin-bottom: 0.3rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .finding .cred-preview ul { list-style: none; padding-left: 0; margin: 0; }
  .finding .cred-preview li { padding: 0.15rem 0; color: var(--text-dim); }
  .finding .cred-preview li::before { content: "▸ "; color: #a78bfa; }
  .finding .remediation { background: rgba(34,197,94,0.05); border: 1px solid rgba(34,197,94,0.15); border-radius: 4px; padding: 0.5rem 0.7rem; margin-top: 0.5rem; font-size: 0.8rem; }
  .finding .remediation-title { font-weight: bold; color: var(--success); margin-bottom: 0.2rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .finding .remediation-text { color: var(--text-dim); }
  .finding .references { margin-top: 0.4rem; font-size: 0.75rem; color: var(--text-dim); }
  .finding .references a { color: var(--low); text-decoration: none; }
  .finding .references a:hover { text-decoration: underline; }
  .system-info { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin: 1.5rem 0; }
  .system-info table { width: 100%; border-collapse: collapse; }
  .system-info td { padding: 0.4rem 1rem; border-bottom: 1px solid var(--border); }
  .system-info td:first-child { color: var(--text-dim); width: 180px; }
  .section-title { font-size: 1.3rem; font-weight: bold; color: var(--low); margin: 2rem 0 1rem; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .badge-CRITICAL { background: rgba(239,68,68,0.2); color: var(--critical); }
  .badge-HIGH     { background: rgba(249,115,22,0.2); color: var(--high); }
  .badge-MEDIUM   { background: rgba(234,179,8,0.2); color: var(--medium); }
  .badge-LOW      { background: rgba(59,130,246,0.2); color: var(--low); }
  .badge-INFO     { background: rgba(6,182,212,0.2); color: var(--info); }
  footer { text-align: center; color: var(--text-dim); padding: 2rem; font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 3rem; }
</style>
</head>
<body>
<div class="header">
  <h1>⚡ π LinuxPi — REPORT</h1>
  <div class="subtitle">Linux Privilege Escalation Framework v${TOOL_VERSION} | $(date '+%Y-%m-%d %H:%M:%S UTC') | Developed by ${TOOL_AUTHOR_NAME}</div>
</div>
<div class="container">
  <div class="section-title">SYSTEM INFORMATION</div>
  <div class="system-info">
    <table>
      <tr><td>Hostname</td><td>$(html_escape "$SYSTEM_HOSTNAME")</td></tr>
      <tr><td>OS</td><td>$(html_escape "$SYSTEM_DISTRO $SYSTEM_DISTRO_VER")</td></tr>
      <tr><td>Kernel</td><td>$(html_escape "$SYSTEM_KERNEL")</td></tr>
      <tr><td>Architecture</td><td>$(html_escape "$SYSTEM_ARCH")</td></tr>
      <tr><td>Current User</td><td>$(html_escape "$SYSTEM_USER") (UID=${SYSTEM_UID})</td></tr>
      <tr><td>Environment</td><td>$(
        [[ "$SYSTEM_IS_CONTAINER" == "1" ]] && echo "Container (${SYSTEM_CONTAINER_TYPE})" || echo "Physical/VM"
      )</td></tr>
    </table>
  </div>

  <div class="section-title">FINDING SUMMARY</div>
  <div class="summary-grid">
    <div class="summary-card critical"><div class="count">${CRITICAL_COUNT}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="count">${HIGH_COUNT}</div><div class="label">High</div></div>
    <div class="summary-card medium"><div class="count">${MEDIUM_COUNT}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="count">${LOW_COUNT}</div><div class="label">Low</div></div>
    <div class="summary-card info-c"><div class="count">${INFO_COUNT}</div><div class="label">Info</div></div>
  </div>

  <div class="section-title">FINDINGS</div>
HTML

    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"
        local cve_tag=""
        [[ -n "$cve" && "$cve" != "-" ]] && cve_tag="<span class=\"cve-tag\">${cve}</span>"

        local h_mitre="${_FINDING_MITRE[$title]:-}"
        local mitre_tag=""
        [[ -n "$h_mitre" ]] && mitre_tag="<span class=\"mitre-tag\">${h_mitre}</span>"

        local scoring_html=""
        if [[ -n "$cve" && "$cve" != "-" ]]; then
            local h_epss="${_EPSS_CACHE[$cve]:-0.0}"
            local h_cvss="${_CVSS_CACHE[$cve]:-0.0}"
            h_epss="${h_epss//[^0-9.]/}"; [[ -z "$h_epss" ]] && h_epss="0.0"
            h_cvss="${h_cvss//[^0-9.]/}"; [[ -z "$h_cvss" ]] && h_cvss="0.0"
            local h_pscore h_ptier
            h_pscore=$(_compute_priority_inline "$cve" "$severity" "$exploit")
            h_ptier=$(_compute_tier_inline "$h_pscore")
            scoring_html="<div class=\"scoring\">CVSS:${h_cvss} | EPSS:${h_epss} | Priority:${h_pscore}/10 [${h_ptier}]</div>"
        fi

        local h_evidence="${_FINDING_EVIDENCE[$title]:-}"
        local evidence_html=""
        if [[ -n "$h_evidence" ]]; then
            evidence_html="<div class=\"evidence\"><div class=\"evidence-title\">Evidence</div><ul>"
            local IFS_bak="$IFS"
            IFS=';'
            for ev_item in $h_evidence; do
                ev_item="${ev_item## }"; ev_item="${ev_item%% }"
                [[ -n "$ev_item" ]] && evidence_html+="<li>$(html_escape "$ev_item")</li>"
            done
            IFS="$IFS_bak"
            evidence_html+="</ul></div>"
        fi

        local h_cred_preview="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
        local cred_preview_html=""
        if [[ -n "$h_cred_preview" ]]; then
            cred_preview_html="<div class=\"cred-preview\"><div class=\"cred-preview-title\">$(_cred_block_heading)</div><ul>"
            local IFS_bakc2="$IFS"; IFS=';'
            for cp_item in $h_cred_preview; do
                cp_item="${cp_item## }"; cp_item="${cp_item%% }"
                [[ -n "$cp_item" ]] && cred_preview_html+="<li>$(html_escape "$cp_item")</li>"
            done
            IFS="$IFS_bakc2"
            cred_preview_html+="</ul></div>"
        fi

        local h_remediation="${_FINDING_REMEDIATION[$title]:-}"
        local remediation_html=""
        [[ -n "$h_remediation" ]] && remediation_html="<div class=\"remediation\"><div class=\"remediation-title\">Remediation</div><div class=\"remediation-text\">$(html_escape "$h_remediation")</div></div>"

        local h_references="${_FINDING_REFERENCES[$title]:-}"
        local references_html=""
        if [[ -n "$h_references" ]]; then
            references_html="<div class=\"references\">Ref: "
            local IFS_bak="$IFS"
            IFS=';'
            for ref_item in $h_references; do
                ref_item="${ref_item## }"; ref_item="${ref_item%% }"
                if [[ "$ref_item" =~ ^https?:// ]]; then
                    references_html+="<a href=\"$(html_escape "$ref_item")\" target=\"_blank\">$(html_escape "$ref_item")</a> "
                else
                    [[ -n "$ref_item" ]] && references_html+="$(html_escape "$ref_item") "
                fi
            done
            IFS="$IFS_bak"
            references_html+="</div>"
        fi

        cat << FINDING
  <div class="finding ${severity}">
    <span class="sev-badge badge-${severity}">${severity}</span>
    <span class="title">$(html_escape "$title")</span>${cve_tag}${mitre_tag}
    $([ -n "$detail" ] && echo "<div class=\"detail\">$(html_escape "$detail")</div>")
    ${scoring_html}
    ${evidence_html}
    ${cred_preview_html}
    $([ -n "$exploit" ] && [ "$exploit" != "-" ] && echo "<div class=\"exploit\">$(html_escape "$exploit")</div>")
    ${remediation_html}
    ${references_html}
  </div>
FINDING
    done

    cat << HTML
</div>
<footer>LinuxPi v${TOOL_VERSION} | Developed by ${TOOL_AUTHOR_NAME} &lt;${TOOL_AUTHOR_EMAIL}&gt; | <a href="${TOOL_AUTHOR_LINKEDIN}">LinkedIn</a> | For authorized security assessments only</footer>
</body>
</html>
HTML
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo -n "$s"
}

# ──────────────────────────────────────────────────────────────
# Markdown report
# ──────────────────────────────────────────────────────────────
report_markdown() {
    local scan_end="$1"

    echo "# LinuxPi Report"
    echo ""
    echo "> Generated: $(date '+%Y-%m-%d %H:%M:%S') | Tool: linuxpi v${TOOL_VERSION}"
    echo ""
    echo "**Developer:** ${TOOL_AUTHOR_NAME} <${TOOL_AUTHOR_EMAIL}>"
    echo ""
    echo "**LinkedIn:** [${TOOL_AUTHOR_NAME}](${TOOL_AUTHOR_LINKEDIN})"
    echo ""
    echo "## System Information"
    echo ""
    echo "| Field | Value |"
    echo "|-------|-------|"
    echo "| Hostname | \`${SYSTEM_HOSTNAME}\` |"
    echo "| OS | ${SYSTEM_DISTRO} ${SYSTEM_DISTRO_VER} |"
    echo "| Kernel | \`${SYSTEM_KERNEL}\` |"
    echo "| Architecture | ${SYSTEM_ARCH} |"
    echo "| User | ${SYSTEM_USER} (UID=${SYSTEM_UID}) |"
    echo ""
    echo "## Summary"
    echo ""
    echo "| Severity | Count |"
    echo "|----------|-------|"
    echo "| 🔴 Critical | **${CRITICAL_COUNT}** |"
    echo "| 🟠 High | **${HIGH_COUNT}** |"
    echo "| 🟡 Medium | **${MEDIUM_COUNT}** |"
    echo "| 🔵 Low | **${LOW_COUNT}** |"
    echo "| ℹ️ Info | **${INFO_COUNT}** |"
    echo ""
    echo "## Findings"
    echo ""

    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"
        local icon="ℹ️"
        case "$severity" in
            CRITICAL) icon="🔴" ;;
            HIGH)     icon="🟠" ;;
            MEDIUM)   icon="🟡" ;;
            LOW)      icon="🔵" ;;
        esac

        local md_mitre="${_FINDING_MITRE[$title]:-}"
        local md_evidence="${_FINDING_EVIDENCE[$title]:-}"
        local md_cred_preview="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
        local md_remediation="${_FINDING_REMEDIATION[$title]:-}"
        local md_refs="${_FINDING_REFERENCES[$title]:-}"

        echo "### ${icon} ${title}"
        echo ""
        echo "- **Severity:** ${severity}"
        echo "- **Category:** ${category}"
        [[ -n "$md_mitre" ]] && echo "- **MITRE ATT&CK:** \`${md_mitre}\`"

        if [[ -n "$cve" && "$cve" != "-" ]]; then
            echo "- **CVE:** [${cve}](https://nvd.nist.gov/vuln/detail/${cve})"

            local md_epss="${_EPSS_CACHE[$cve]:-0.0}"
            local md_cvss="${_CVSS_CACHE[$cve]:-0.0}"
            local md_vec="${_CVSS_VECTOR_CACHE[$cve]:--}"
            md_epss="${md_epss//[^0-9.]/}"; [[ -z "$md_epss" ]] && md_epss="0.0"
            md_cvss="${md_cvss//[^0-9.]/}"; [[ -z "$md_cvss" ]] && md_cvss="0.0"
            local md_pscore md_ptier
            md_pscore=$(_compute_priority_inline "$cve" "$severity" "$exploit")
            md_ptier=$(_compute_tier_inline "$md_pscore")

            echo ""
            echo "| Metric | Value |"
            echo "|--------|-------|"
            echo "| CVSS Base | **${md_cvss}** |"
            [[ "$md_vec" != "-" ]] && echo "| CVSS Vector | \`${md_vec}\` |"
            echo "| EPSS Score | **${md_epss}** |"
            echo "| Priority | **${md_pscore}/10.0** [${md_ptier}] |"
        fi

        [[ -n "$detail" ]] && echo "- **Detail:** ${detail}"

        if [[ -n "$md_evidence" ]]; then
            echo ""
            echo "**Evidence:**"
            local IFS_bak="$IFS"; IFS=';'
            for ev in $md_evidence; do
                ev="${ev## }"; ev="${ev%% }"
                [[ -n "$ev" ]] && echo "- \`${ev}\`"
            done
            IFS="$IFS_bak"
        fi

        if [[ -n "$md_cred_preview" ]]; then
            echo ""
            echo "**$(_cred_block_heading):**"
            local IFS_bak3="$IFS"; IFS=';'
            for cp in $md_cred_preview; do
                cp="${cp## }"; cp="${cp%% }"
                [[ -n "$cp" ]] && echo "- \`${cp}\`"
            done
            IFS="$IFS_bak3"
        fi

        if [[ -n "$exploit" && "$exploit" != "-" ]]; then
            echo ""
            echo "**Exploit:**"
            echo '```bash'
            echo "$exploit"
            echo '```'
        fi

        if [[ -n "$md_remediation" ]]; then
            echo ""
            echo "> **Remediation:** ${md_remediation}"
        fi

        if [[ -n "$md_refs" ]]; then
            echo ""
            echo "**References:** ${md_refs}"
        fi

        echo ""
    done
}

# ──────────────────────────────────────────────────────────────
# XML report
# ──────────────────────────────────────────────────────────────
report_xml() {
    local scan_end="$1"

    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<linuxpi-report version="1.0">'
    echo "  <metadata>"
    echo "    <tool>linuxpi</tool>"
    echo "    <version>${TOOL_VERSION}</version>"
    echo "    <scan-time>$(date -u +%Y-%m-%dT%H:%M:%SZ)</scan-time>"
    echo "    <report-full-secrets>$( [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]] && echo true || echo false )</report-full-secrets>"
    echo "    <developer>"
    echo "      <name><![CDATA[${TOOL_AUTHOR_NAME}]]></name>"
    echo "      <email><![CDATA[${TOOL_AUTHOR_EMAIL}]]></email>"
    echo "      <linkedin><![CDATA[${TOOL_AUTHOR_LINKEDIN}]]></linkedin>"
    echo "    </developer>"
    echo "  </metadata>"
    echo "  <system>"
    echo "    <hostname><![CDATA[${SYSTEM_HOSTNAME}]]></hostname>"
    echo "    <distro><![CDATA[${SYSTEM_DISTRO} ${SYSTEM_DISTRO_VER}]]></distro>"
    echo "    <kernel><![CDATA[${SYSTEM_KERNEL}]]></kernel>"
    echo "    <arch>${SYSTEM_ARCH}</arch>"
    echo "    <user><![CDATA[${SYSTEM_USER}]]></user>"
    echo "    <uid>${SYSTEM_UID}</uid>"
    echo "  </system>"
    echo "  <summary>"
    echo "    <critical>${CRITICAL_COUNT}</critical>"
    echo "    <high>${HIGH_COUNT}</high>"
    echo "    <medium>${MEDIUM_COUNT}</medium>"
    echo "    <low>${LOW_COUNT}</low>"
    echo "    <info>${INFO_COUNT}</info>"
    echo "  </summary>"
    echo "  <findings>"

    local i=1
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity category cve title detail exploit <<< "$finding"

        local x_epss="${_EPSS_CACHE[$cve]:-0.0}"
        local x_cvss="${_CVSS_CACHE[$cve]:-0.0}"
        local x_cvss_vec="${_CVSS_VECTOR_CACHE[$cve]:--}"
        x_epss="${x_epss//[^0-9.]/}"; [[ -z "$x_epss" ]] && x_epss="0.0"
        x_cvss="${x_cvss//[^0-9.]/}"; [[ -z "$x_cvss" ]] && x_cvss="0.0"
        local x_pscore x_ptier
        x_pscore=$(_compute_priority_inline "$cve" "$severity" "$exploit")
        x_ptier=$(_compute_tier_inline "$x_pscore")

        local x_evidence="${_FINDING_EVIDENCE[$title]:-}"
        local x_cred_preview="${_FINDING_CREDENTIAL_PREVIEW[$title]:-}"
        local x_remediation="${_FINDING_REMEDIATION[$title]:-}"
        local x_references="${_FINDING_REFERENCES[$title]:-}"
        local x_mitre="${_FINDING_MITRE[$title]:-}"

        echo "    <finding id=\"${i}\">"
        echo "      <severity>${severity}</severity>"
        echo "      <category>${category}</category>"
        echo "      <cve>${cve}</cve>"
        echo "      <title><![CDATA[${title}]]></title>"
        echo "      <detail><![CDATA[${detail}]]></detail>"
        echo "      <exploit><![CDATA[${exploit}]]></exploit>"
        echo "      <evidence><![CDATA[${x_evidence}]]></evidence>"
        echo "      <credentials-redacted><![CDATA[${x_cred_preview}]]></credentials-redacted>"
        echo "      <remediation><![CDATA[${x_remediation}]]></remediation>"
        echo "      <references><![CDATA[${x_references}]]></references>"
        echo "      <mitre-attack>${x_mitre}</mitre-attack>"
        echo "      <scoring>"
        echo "        <cvss-base>${x_cvss}</cvss-base>"
        echo "        <cvss-vector>${x_cvss_vec}</cvss-vector>"
        echo "        <epss-score>${x_epss}</epss-score>"
        echo "        <priority-score>${x_pscore}</priority-score>"
        echo "        <priority-tier>${x_ptier}</priority-tier>"
        echo "      </scoring>"
        echo "    </finding>"
        i=$(( i + 1 ))
    done

    echo "  </findings>"
    echo "</linuxpi-report>"
}
