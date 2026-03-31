#!/usr/bin/env bash
# modules/sudo/sudo_enum.sh - Sudo configuration analysis and CVE matching

run_sudo_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "SUDO ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    if [[ "${QUIET_MODE:-0}" == "0" ]]; then
        echo -e "  ${GREY}[i] GTFOBins (https://gtfobins.org/): sudo rule matches list documented abuse patterns (shell, file read/write, …) in findings.${RESET}"
    fi

    _check_sudo_version
    _check_sudo_privileges
    _check_sudo_cves
    _check_sudo_defaults
    _check_sudoers_files

    log_timing "sudo_enum" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# Sudo version detection
# ──────────────────────────────────────────────────────────────
_check_sudo_version() {
    print_subsection "Sudo Version"

    if ! cmd_exists sudo; then
        print_info "sudo not found"
        return
    fi

    SUDO_VERSION=$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9a-z]+p?[0-9]*' | head -1)
    SUDO_VERSION="${SUDO_VERSION:-unknown}"

    echo -e "  ${BOLD_WHITE}sudo version:${RESET} ${SUDO_VERSION}"
    log_info "sudo version: $SUDO_VERSION"
}

# ──────────────────────────────────────────────────────────────
# Sudo -l parse
# ──────────────────────────────────────────────────────────────
_check_sudo_privileges() {
    print_subsection "Sudo Privileges (sudo -l)"

    local sudo_output
    sudo_output=$(sudo -n -l 2>/dev/null)

    if [[ -z "$sudo_output" ]]; then
        print_info "No sudo privileges or password required (non-interactive check)"
        return
    fi

    echo -e "${GREY}${sudo_output}${RESET}" | while IFS= read -r line; do
        echo -e "  $line"
    done

    # NOPASSWD analysis
    if echo "$sudo_output" | grep -qi "NOPASSWD"; then
        local nopasswd_lines
        nopasswd_lines=$(echo "$sudo_output" | grep -i "NOPASSWD")
        print_warn "NOPASSWD entries found!"

        while IFS= read -r line; do
            _analyze_sudo_rule "$line" "NOPASSWD"
        done <<< "$nopasswd_lines"
    fi

    # ALL check
    if echo "$sudo_output" | grep -qE "\(ALL.*ALL\)|ALL=\(ALL\)"; then
        add_finding "CRITICAL" "sudo" "-" "Full sudo access: ALL=(ALL)" \
            "User has unrestricted sudo access - can run any command as root" \
            "sudo su -" \
            "sudo -l output: user has (ALL : ALL) ALL" \
            "Remove unrestricted sudo. Use granular sudoers rules with specific commands. Apply principle of least privilege." \
            "https://attack.mitre.org/techniques/T1548/003/" \
            "T1548.003"
    fi

    # Parse sudo binaries for GTFOBins lookup (deduplicated)
    local has_partial_sudo=0
    if echo "$sudo_output" | grep -qE "\(ALL\)" && ! echo "$sudo_output" | grep -qE "ALL=\(ALL\) ALL"; then
        has_partial_sudo=1
    fi
    if echo "$sudo_output" | grep -qE "\(root\)"; then
        has_partial_sudo=1
    fi
    [[ "$has_partial_sudo" == "1" ]] && _parse_sudo_binaries "$sudo_output"
}

# ──────────────────────────────────────────────────────────────
# Sudo rule analysis
# ──────────────────────────────────────────────────────────────
_analyze_sudo_rule() {
    local rule="$1"
    local rule_type="$2"

    # Extract binaries for GTFOBins lookup
    local binaries
    binaries=$(echo "$rule" | grep -oE '/[a-zA-Z0-9_/.-]+' | sort -u)

    while IFS= read -r binary; do
        local binary_name
        binary_name=$(basename "$binary")

        local gtfo_result
        gtfo_result=$(gtfobins_lookup "$binary_name" "sudo")

        if [[ -n "$gtfo_result" ]]; then
            local exploit_cmd exploit_type gtfo_page ev_extra
            exploit_type=$(echo "$gtfo_result" | head -1 | cut -d'|' -f1)
            exploit_cmd=$(echo "$gtfo_result" | head -1 | cut -d'|' -f2)
            gtfo_page="$(gtfobins_binary_url "$binary_name")$(gtfobins_function_anchor "$exploit_type")"
            ev_extra="$(gtfobins_techniques_evidence "$binary_name" "sudo" 6)"

            add_finding "HIGH" "sudo" "-" "GTFOBins: sudo ${binary_name} (${rule_type})" \
                "sudo allows '${binary_name}'; GTFOBins (https://gtfobins.org/) documents how this binary can keep elevated privileges for shell, file read/write, and related abuse." \
                "$exploit_cmd" \
                "Binary: ${binary} ; sudo rule: ${rule} ; Primary function: ${exploit_type} ; Documented techniques: ${ev_extra}" \
                "Tighten sudoers: remove NOPASSWD, use absolute paths, forbid SETENV where possible, and apply command arguments allowlists. See GTFOBins for binary-specific patterns." \
                "${gtfo_page} ; https://gtfobins.org/ ; https://attack.mitre.org/techniques/T1548/003/" \
                "T1548.003"
        fi
    done <<< "$binaries"
}

# ──────────────────────────────────────────────────────────────
# Sudo binary parsing
# ──────────────────────────────────────────────────────────────
_parse_sudo_binaries() {
    local sudo_output="$1"

    while IFS= read -r line; do
        echo "$line" | grep -qiE "(NOPASSWD|SETENV)" || continue
        _analyze_sudo_rule "$line" "$(echo "$line" | grep -oiE 'NOPASSWD|SETENV' | head -1)"
    done <<< "$sudo_output"
}

# ──────────────────────────────────────────────────────────────
# Sudo CVE check
# ──────────────────────────────────────────────────────────────
_check_sudo_cves() {
    print_subsection "Sudo CVE Matching"

    [[ -z "${SUDO_VERSION:-}" ]] && return
    [[ "$SUDO_VERSION" == "unknown" ]] && return

    local found_count=0

    while IFS='|' read -r cve_id name min_ver max_ver severity cvss exploit_avail desc; do
        [[ "$cve_id" =~ ^# ]] && continue
        [[ -z "$cve_id" ]] && continue

        local clean_min="${min_ver// /}"
        local clean_max="${max_ver// /}"

        # Semver-like comparison for sudo version
        local sudo_num
        sudo_num=$(echo "$SUDO_VERSION" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
        [[ -z "$sudo_num" ]] && continue

        if version_lte "$clean_min" "$sudo_num" && version_lte "$sudo_num" "$clean_max"; then
            print_finding "$severity" "${cve_id}: ${name}" "$desc"
            echo -e "         ${GREY}CVSS: ${cvss} | Exploit: ${exploit_avail}${RESET}"

            add_finding "$severity" "sudo" "$cve_id" "${cve_id}: ${name}" \
                "sudo ${SUDO_VERSION} is vulnerable. ${desc}" \
                "$([ "$exploit_avail" == "true" ] && echo "https://www.exploit-db.com/search?cve=${cve_id}" || echo "-")" \
                "sudo version: ${SUDO_VERSION} ; Affected range: ${clean_min} - ${clean_max}" \
                "Update sudo to latest patched version." \
                "https://nvd.nist.gov/vuln/detail/${cve_id}" \
                "T1068"

            found_count=$(( found_count + 1 ))
        fi
    done < "${SCRIPT_DIR}/modules/sudo/sudo_exploits.db"

    [[ $found_count -eq 0 ]] && print_good "No known sudo CVEs for version ${SUDO_VERSION}"

    # Baron Samedit specific check
    _check_baron_samedit

    # CVE-2019-14287 specific check
    _check_sudo_uid_bypass
}

# ──────────────────────────────────────────────────────────────
# Baron Samedit (CVE-2021-3156) - sudoedit -s check
# ──────────────────────────────────────────────────────────────
_check_baron_samedit() {
    [[ -z "${SUDO_VERSION:-}" ]] && return

    local sudo_num
    sudo_num=$(echo "$SUDO_VERSION" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
    [[ -z "$sudo_num" ]] && return

    if version_lte "1.8.2" "$sudo_num" && version_lte "$sudo_num" "1.9.5"; then
        local test_result=""
        if cmd_exists perl; then
            test_result=$(timeout 3 sudoedit -s '\' "$(perl -e 'print "A" x 65536')" 2>&1 || true)
        elif cmd_exists python3; then
            test_result=$(timeout 3 sudoedit -s '\' "$(python3 -c 'print("A"*65536)')" 2>&1 || true)
        fi

        if echo "$test_result" | grep -qi "malloc\|double free\|corrupted"; then
            add_finding "CRITICAL" "sudo" "CVE-2021-3156" "CONFIRMED: Baron Samedit (CVE-2021-3156)" \
                "sudo ${SUDO_VERSION} is CONFIRMED vulnerable to heap overflow via sudoedit -s" \
                "sudoedit -s '\\\\' \$(python3 -c 'print(\"A\"*65536)') | Full root exploit available" \
                "sudo version: ${SUDO_VERSION} ; Heap overflow confirmed via sudoedit -s" \
                "Update sudo to >= 1.9.5p2 immediately. This is an actively exploited vulnerability." \
                "https://nvd.nist.gov/vuln/detail/CVE-2021-3156" \
                "T1068"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# CVE-2019-14287 - sudo -u#-1 bypass
# ──────────────────────────────────────────────────────────────
_check_sudo_uid_bypass() {
    local sudo_l_output
    sudo_l_output=$(sudo -n -l 2>/dev/null)

    [[ -z "$sudo_l_output" ]] && return

    # Runas check - whether it contains (ALL)
    if echo "$sudo_l_output" | grep -qE "\(ALL\)|\(ALL : ALL\)"; then
        local sudo_num
        sudo_num=$(echo "${SUDO_VERSION:-0}" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')

        if version_lt "$sudo_num" "1.8.28" 2>/dev/null; then
            add_finding "HIGH" "sudo" "CVE-2019-14287" "Sudo -1 UID bypass (CVE-2019-14287)" \
                "sudo ${SUDO_VERSION} allows bypassing runas restrictions with -u#-1" \
                "sudo -u#-1 /bin/bash  OR  sudo -u#4294967295 /bin/bash" \
                "sudo version: ${SUDO_VERSION:-0} ; User has (ALL) runas spec" \
                "Update sudo to >= 1.8.28." \
                "https://nvd.nist.gov/vuln/detail/CVE-2019-14287" \
                "T1548.003"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Sudo defaults analysis
# ──────────────────────────────────────────────────────────────
_check_sudo_defaults() {
    print_subsection "Sudo Configuration Checks"

    local sudo_l_output
    sudo_l_output=$(sudo -n -l 2>/dev/null)

    [[ -z "$sudo_l_output" ]] && return

    # env_keep check - credential leak potential
    if echo "$sudo_l_output" | grep -qi "env_keep"; then
        local kept_vars
        kept_vars=$(echo "$sudo_l_output" | grep -i "env_keep" | head -3)
        print_warn "sudo env_keep configured:"
        echo -e "  ${GREY}${kept_vars}${RESET}"

        if echo "$kept_vars" | grep -qiE "LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB"; then
            add_finding "CRITICAL" "sudo" "-" "sudo env_keep with dangerous env variables" \
                "sudo preserves environment variables that can be used for library injection" \
                "sudo LD_PRELOAD=/tmp/evil.so /allowed/command" \
                "Preserved vars: ${kept_vars}" \
                "Remove LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, PERL5LIB from env_keep in sudoers." \
                "https://attack.mitre.org/techniques/T1574/006/" \
                "T1574.006"
        fi
    fi

    # SETENV check
    if echo "$sudo_l_output" | grep -qi "SETENV"; then
        add_finding "HIGH" "sudo" "-" "sudo SETENV allowed" \
            "SETENV allows users to set environment variables when running sudo" \
            "sudo SETENV /path/to/binary LD_PRELOAD=/tmp/malicious.so" \
            "sudo -l output contains SETENV" \
            "Remove SETENV from sudoers rules. Use env_reset default." \
            "https://attack.mitre.org/techniques/T1574/006/" \
            "T1574.006"
    fi

    # pwfeedback check (CVE-2019-18634)
    if echo "$sudo_l_output" | grep -qi "pwfeedback"; then
        local sudo_num
        sudo_num=$(echo "${SUDO_VERSION:-0}" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')

        if version_lt "$sudo_num" "1.8.31" 2>/dev/null; then
            add_finding "HIGH" "sudo" "CVE-2019-18634" "sudo pwfeedback stack overflow" \
                "sudo ${SUDO_VERSION} with pwfeedback enabled - stack overflow vulnerability" \
                "perl -e 'print(\"A\" x 1000)' | sudo -S -k id" \
                "sudo version: ${SUDO_VERSION} ; pwfeedback enabled in defaults" \
                "Update sudo to >= 1.8.31 or disable pwfeedback in sudoers." \
                "https://nvd.nist.gov/vuln/detail/CVE-2019-18634" \
                "T1068"
        fi
    fi

    # timestamp_timeout = 0 (password required for each command)
    if echo "$sudo_l_output" | grep -qi "timestamp_timeout=0"; then
        print_info "sudo timestamp_timeout=0 - password required for each command"
    fi
}

# ──────────────────────────────────────────────────────────────
# Sudoers file analysis
# ──────────────────────────────────────────────────────────────
_check_sudoers_files() {
    print_subsection "Sudoers Files"

    local sudoers_files=("/etc/sudoers" "/etc/sudoers.d/")
    local found_writable=0

    for sudoers in "${sudoers_files[@]}"; do
        if [[ -d "$sudoers" ]]; then
            while IFS= read -r f; do
                _analyze_sudoers_file "$f"
                if is_writable "$f"; then
                    local _wr_sudoers_perms
                    _wr_sudoers_perms=$(file_perms "$f" 2>/dev/null)
                    add_finding "CRITICAL" "sudo" "-" "Writable sudoers file: ${f}" \
                        "The sudoers file ${f} is writable by current user" \
                        "echo '$(id -un) ALL=(ALL) NOPASSWD:ALL' >> ${f}" \
                        "File: ${f} (permissions: ${_wr_sudoers_perms}, owner: $(file_owner "$f" 2>/dev/null))" \
                        "Set sudoers permissions to 440 owned by root:root. Use visudo for editing." \
                        "https://attack.mitre.org/techniques/T1548/003/" \
                        "T1548.003"
                    found_writable=1
                fi
            done < <(find "$sudoers" -type f 2>/dev/null | head -20)
        elif [[ -f "$sudoers" ]]; then
            if is_readable "$sudoers"; then
                _analyze_sudoers_file "$sudoers"
            fi
            if is_writable "$sudoers"; then
                local _wr_etc_sudoers_perms
                _wr_etc_sudoers_perms=$(file_perms "$sudoers" 2>/dev/null)
                add_finding "CRITICAL" "sudo" "-" "Writable /etc/sudoers" \
                    "/etc/sudoers is writable - trivial root escalation" \
                    "echo '$(id -un) ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers" \
                    "File: /etc/sudoers (permissions: ${_wr_etc_sudoers_perms}, owner: $(file_owner "$sudoers" 2>/dev/null))" \
                    "Set sudoers permissions to 440 owned by root:root. Use visudo for editing." \
                    "https://attack.mitre.org/techniques/T1548/003/" \
                    "T1548.003"
                found_writable=1
            fi
        fi
    done

    [[ $found_writable -eq 0 ]] && [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_good "No writable sudoers files found"
}

_analyze_sudoers_file() {
    local sudoers_file="$1"

    [[ -r "$sudoers_file" ]] || return

    [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${GREY}Reading: ${sudoers_file}${RESET}"

    # #includedir analysis
    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "${line// /}" ]] && continue

        # Dangerous patterns
        if echo "$line" | grep -qE "ALL\s*=\s*\(ALL\)\s*NOPASSWD\s*:\s*ALL"; then
            print_warn "Unrestricted NOPASSWD entry in ${sudoers_file}"
        fi

        if echo "$line" | grep -qiE "LD_PRELOAD|LD_LIBRARY_PATH" && echo "$line" | grep -qi "env_keep"; then
            print_warn "Dangerous env_keep in ${sudoers_file}: ${line}"
        fi
    done < "$sudoers_file"
}
