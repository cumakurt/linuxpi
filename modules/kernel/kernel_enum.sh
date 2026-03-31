#!/usr/bin/env bash
# modules/kernel/kernel_enum.sh - Kernel information gathering and CVE matching

# Advanced research: CONFIG/sysfs/capability narratives (also prepended in standalone build)
if ! declare -F _run_kernel_advanced_research &>/dev/null; then
    # shellcheck source=kernel_research.sh
    [[ -n "${SCRIPT_DIR:-}" && -f "${SCRIPT_DIR}/modules/kernel/kernel_research.sh" ]] && source "${SCRIPT_DIR}/modules/kernel/kernel_research.sh"
fi

run_kernel_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "KERNEL ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    local kernel="$SYSTEM_KERNEL"
    local kernel_short="$SYSTEM_KERNEL_SHORT"
    local arch="$SYSTEM_ARCH"

    [[ -z "$kernel" ]] && { log_warn "Could not determine kernel version"; return 1; }

    print_subsection "Kernel Information"
    echo -e "  ${BOLD_WHITE}Kernel:${RESET}   $kernel"
    echo -e "  ${BOLD_WHITE}Parsed:${RESET}   $kernel_short"
    echo -e "  ${BOLD_WHITE}Arch:${RESET}     $arch"

    _enum_kernel_modules
    _enum_sysctl_security
    _match_kernel_cves "$kernel_short"
    _check_special_kernel_features
    _run_kernel_advanced_research

    log_timing "kernel_enum" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# Loaded kernel modules
# ──────────────────────────────────────────────────────────────
_enum_kernel_modules() {
    print_subsection "Loaded Kernel Modules"

    local dangerous_modules=(
        "udf" "vfat" "fuse" "autofs" "isofs"
        "bluetooth" "bnep" "l2tp_core"
        "nf_tables" "xt_socket"
        "ip_tables" "ip6_tables"
        "wireguard" "openvpn"
    )

    if [[ -r /proc/modules ]]; then
        local loaded_count
        loaded_count=$(wc -l < /proc/modules)
        echo -e "  ${GREY}Total loaded modules: ${loaded_count}${RESET}"

        for mod in "${dangerous_modules[@]}"; do
            if grep -q "^${mod} " /proc/modules 2>/dev/null; then
                print_info "Potentially dangerous module loaded: ${mod}"
                log_info "Kernel module loaded: $mod"
            fi
        done

        if grep -q "^nf_tables " /proc/modules 2>/dev/null; then
            add_finding "MEDIUM" "kernel" "-" "nf_tables module loaded" \
                "nf_tables is loaded and accessible - several CVEs target this module" \
                "Check: CVE-2024-1086, CVE-2023-35001, CVE-2022-34918" \
                "Module: nf_tables (loaded in /proc/modules) ; Total loaded modules: ${loaded_count}" \
                "Unload nf_tables if not required: rmmod nf_tables. Use iptables-legacy instead. Keep kernel patched." \
                "https://attack.mitre.org/techniques/T1068/" \
                "T1068"
        fi
    else
        print_info "Cannot read /proc/modules (permission denied)"
    fi
}

# ──────────────────────────────────────────────────────────────
# Security sysctl checks
# ──────────────────────────────────────────────────────────────
_enum_sysctl_security() {
    print_subsection "Kernel Security Settings"

    declare -A sysctl_checks=(
        ["kernel.dmesg_restrict"]="1"
        ["kernel.kptr_restrict"]="2"
        ["kernel.unprivileged_bpf_disabled"]="1"
        ["kernel.unprivileged_userns_clone"]="0"
        ["net.core.bpf_jit_enable"]="0"
        ["kernel.yama.ptrace_scope"]="2"
        ["kernel.perf_event_paranoid"]="3"
        ["vm.unprivileged_userfaultfd"]="0"
        ["kernel.randomize_va_space"]="2"
        ["fs.protected_symlinks"]="1"
        ["fs.protected_hardlinks"]="1"
    )

    declare -A sysctl_names=(
        ["kernel.dmesg_restrict"]="dmesg access restriction"
        ["kernel.kptr_restrict"]="kernel pointer restriction"
        ["kernel.unprivileged_bpf_disabled"]="unprivileged eBPF disabled"
        ["kernel.unprivileged_userns_clone"]="unprivileged user namespace"
        ["net.core.bpf_jit_enable"]="BPF JIT hardening"
        ["kernel.yama.ptrace_scope"]="ptrace scope"
        ["kernel.perf_event_paranoid"]="perf event paranoid"
        ["vm.unprivileged_userfaultfd"]="unprivileged userfaultfd"
        ["kernel.randomize_va_space"]="ASLR"
        ["fs.protected_symlinks"]="symlink protection"
        ["fs.protected_hardlinks"]="hardlink protection"
    )

    local sysctl_cmd=""
    cmd_exists sysctl && sysctl_cmd="sysctl"

    for param in "${!sysctl_checks[@]}"; do
        local expected="${sysctl_checks[$param]}"
        local name="${sysctl_names[$param]}"
        local current=""

        if [[ -n "$sysctl_cmd" ]]; then
            current=$(safe_run 3 sysctl -n "$param" 2>/dev/null)
        else
            local proc_path="/proc/sys/${param//./\/}"
            [[ -r "$proc_path" ]] && current=$(cat "$proc_path" 2>/dev/null)
        fi

        if [[ -z "$current" ]]; then
            print_debug "sysctl $param: not available"
            continue
        fi

        if [[ "$current" == "$expected" ]]; then
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_good "$name: $current (secure)"
        else
            print_warn "$name: $current (expected: $expected)"

            case "$param" in
                "kernel.unprivileged_bpf_disabled")
                    if [[ "$current" == "0" ]]; then
                        add_finding "HIGH" "kernel" "-" "Unprivileged eBPF enabled" \
                            "kernel.unprivileged_bpf_disabled=0 - Unprivileged users can use eBPF" \
                            "May allow kernel exploitation via eBPF verifier vulnerabilities" \
                            "Sysctl: ${param}=${current} (expected: ${expected})" \
                            "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-hardening.conf and run sysctl --system" \
                            "https://attack.mitre.org/techniques/T1068/" \
                            "T1068"
                    fi
                    ;;
                "kernel.unprivileged_userns_clone")
                    if [[ "$current" == "1" ]]; then
                        add_finding "MEDIUM" "kernel" "-" "Unprivileged user namespaces enabled" \
                            "Allows unprivileged users to create user namespaces - widens attack surface" \
                            "Required for many kernel exploits" \
                            "Sysctl: ${param}=${current} (expected: ${expected})" \
                            "Set kernel.unprivileged_userns_clone=0 in /etc/sysctl.d/99-hardening.conf. Some apps (Chrome, Flatpak) may need user namespaces." \
                            "https://attack.mitre.org/techniques/T1068/" \
                            "T1068"
                    fi
                    ;;
                "kernel.yama.ptrace_scope")
                    if [[ "$current" == "0" ]]; then
                        add_finding "LOW" "kernel" "-" "ptrace unrestricted (scope=0)" \
                            "Any process can ptrace any other process owned by the same user" \
                            "Classic ptrace privilege escalation may be possible" \
                            "Sysctl: ${param}=${current} (expected: ${expected})" \
                            "Set kernel.yama.ptrace_scope=2 to restrict ptrace to root-only." \
                            "https://attack.mitre.org/techniques/T1055/" \
                            "T1055"
                    fi
                    ;;
                "kernel.randomize_va_space")
                    if [[ "$current" == "0" ]]; then
                        add_finding "HIGH" "kernel" "-" "ASLR disabled (randomize_va_space=0)" \
                            "Address Space Layout Randomization is disabled - exploit reliability increased" \
                            "Kernel exploit payloads have higher success rate" \
                            "Sysctl: ${param}=${current} (expected: ${expected})" \
                            "Set kernel.randomize_va_space=2 for full ASLR. Verify in /etc/sysctl.d/." \
                            "https://attack.mitre.org/techniques/T1068/" \
                            "T1068"
                    fi
                    ;;
                "kernel.dmesg_restrict")
                    if [[ "$current" == "0" ]]; then
                        add_finding "LOW" "kernel" "-" "dmesg unrestricted" \
                            "Unprivileged users can read kernel messages - potential info leak" \
                            "dmesg | grep -i 'address\\|ptr\\|key'" \
                            "Sysctl: ${param}=${current} (expected: ${expected})" \
                            "Set kernel.dmesg_restrict=1 to prevent unprivileged users from reading kernel logs." \
                            "https://attack.mitre.org/techniques/T1082/" \
                            "T1082"
                    fi
                    ;;
            esac
        fi
    done

    # KASLR check
    local kaslr_status
    if grep -q 'nokaslr' /proc/cmdline 2>/dev/null; then
        add_finding "HIGH" "kernel" "-" "KASLR disabled (nokaslr boot param)" \
            "Kernel Address Space Layout Randomization is disabled" \
            "Kernel base address is predictable - improves exploit success" \
            "Boot cmdline contains: nokaslr" \
            "Remove 'nokaslr' from kernel boot parameters in GRUB config and regenerate grub.cfg." \
            "https://attack.mitre.org/techniques/T1068/" \
            "T1068"
    fi

    # Secure Boot
    if cmd_exists mokutil; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null)
        if echo "$sb_state" | grep -qi "disabled"; then
            print_info "Secure Boot: DISABLED"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# CVE Matching
# ──────────────────────────────────────────────────────────────
_match_kernel_cves() {
    local kernel="$1"

    print_subsection "Kernel CVE Matching"
    echo -e "  ${GREY}Checking kernel ${kernel} against vulnerability database...${RESET}"

    local found_count=0

    local kernel_db="${SCRIPT_DIR}/modules/kernel/kernel_exploits.db"
    if [[ ! -f "$kernel_db" ]]; then
        print_error "kernel_exploits.db not found at ${kernel_db}"
        return
    fi

    # Match CVEs from database
    while IFS='|' read -r cve_id name min_kernel max_kernel severity cvss exploit_avail desc; do
        [[ "$cve_id" =~ ^# ]] && continue
        [[ -z "$cve_id" ]] && continue

        local clean_min
        clean_min=$(echo "$min_kernel" | tr -d ' ')
        local clean_max
        clean_max=$(echo "$max_kernel" | tr -d ' ')

        if version_lte "$clean_min" "$kernel" && version_lte "$kernel" "$clean_max"; then
            local exploit_note=""
            [[ "$exploit_avail" == "true" ]] && exploit_note="${BOLD_GREEN}[Exploit Available]${RESET}" || exploit_note="${YELLOW}[No Public Exploit]${RESET}"

            local color
            color=$(color_for_severity "$severity")

            echo -e "  ${color}[${severity:0:4}]${RESET} ${BOLD_WHITE}${cve_id}${RESET} - ${name}"
            echo -e "         ${GREY}${desc}${RESET}"
            echo -e "         CVSS: ${cvss} | ${exploit_note}"

            local exploit_cmd="-"
            [[ "$exploit_avail" == "true" ]] && exploit_cmd="https://www.exploit-db.com/search?cve=${cve_id}"

            add_finding "$severity" "kernel" "$cve_id" "${cve_id}: ${name}" \
                "Kernel ${kernel} is vulnerable. ${desc}" \
                "$exploit_cmd" \
                "Kernel: ${kernel} (${SYSTEM_ARCH}) ; Affected range: ${clean_min} - ${clean_max} ; CVSS: ${cvss} ; Exploit available: ${exploit_avail}" \
                "Update kernel to latest patched version. Apply vendor security patches." \
                "https://nvd.nist.gov/vuln/detail/${cve_id}" \
                "T1068"

            found_count=$(( found_count + 1 ))
        fi
    done < "$kernel_db"

    if [[ $found_count -eq 0 ]]; then
        print_good "No known kernel CVEs matched for $kernel"
    else
        echo -e "\n  ${BOLD_RED}Total kernel CVEs matched: ${found_count}${RESET}"
    fi

    # Polkit check
    _check_polkit

    # glibc check
    _check_glibc

    # snapd check
    _check_snapd

    # runc check
    _check_runc

    # OpenSSH regreSSHion check
    _check_openssh_regresshion
}

# ──────────────────────────────────────────────────────────────
# Polkit/pkexec CVE-2021-4034 PwnKit check
# ──────────────────────────────────────────────────────────────
_check_polkit() {
    local polkit_bin
    polkit_bin=$(command -v pkexec 2>/dev/null || command -v polkitd 2>/dev/null)

    [[ -z "$polkit_bin" ]] && return

    local polkit_ver=""

    if cmd_exists pkexec; then
        polkit_ver=$(pkexec --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
    fi

    if [[ -n "$polkit_ver" ]]; then
        echo -e "  ${CYAN}[INFO]${RESET} polkit version: ${polkit_ver}"

        if version_lt "$polkit_ver" "0.121"; then
            add_finding "HIGH" "kernel" "CVE-2021-4034" "PwnKit: Polkit pkexec LPE" \
                "polkit ${polkit_ver} < 0.121 is vulnerable to CVE-2021-4034 (PwnKit)" \
                "https://github.com/arthepsy/CVE-2021-4034 | Reliability: ~99%" \
                "Binary: ${polkit_bin} ; polkit version: ${polkit_ver} ; SUID: $(is_suid "$polkit_bin" && echo yes || echo no)" \
                "Update polkit to >= 0.121. Remove SUID bit from pkexec if not needed: chmod u-s $(command -v pkexec 2>/dev/null)" \
                "https://nvd.nist.gov/vuln/detail/CVE-2021-4034" \
                "T1068"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# glibc Looney Tunables check (CVE-2023-4911)
# ──────────────────────────────────────────────────────────────
_check_glibc() {
    local glibc_ver=""

    if cmd_exists ldd; then
        glibc_ver=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | tail -1)
    fi

    [[ -z "$glibc_ver" ]] && return

    [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${CYAN}[INFO]${RESET} glibc version: ${glibc_ver}"

    if version_gte "$glibc_ver" "2.34" && version_lte "$glibc_ver" "2.38"; then
        add_finding "HIGH" "kernel" "CVE-2023-4911" "Looney Tunables: glibc GLIBC_TUNABLES LPE" \
            "glibc ${glibc_ver} is vulnerable to buffer overflow via GLIBC_TUNABLES env variable" \
            "GLIBC_TUNABLES=glibc.malloc.mxfast=... ./vulnerable_binary | Reliability: ~85%" \
            "glibc version: ${glibc_ver} ; Affected range: 2.34 - 2.38" \
            "Update glibc to latest patched version (>= 2.39 or vendor backport)." \
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4911" \
            "T1068"
    fi
}

# ──────────────────────────────────────────────────────────────
# snapd Dirty Sock check (CVE-2019-7304)
# ──────────────────────────────────────────────────────────────
_check_snapd() {
    cmd_exists snap || [[ -S /run/snapd.socket ]] || return

    local snapd_ver=""
    snapd_ver=$(snap version 2>/dev/null | grep snapd | awk '{print $2}')

    [[ -z "$snapd_ver" ]] && return

    echo -e "  ${CYAN}[INFO]${RESET} snapd version: ${snapd_ver}"

    if version_lt "$snapd_ver" "2.37.2"; then
        add_finding "HIGH" "kernel" "CVE-2019-7304" "Dirty Sock: snapd socket LPE" \
            "snapd ${snapd_ver} < 2.37.2 is vulnerable - snap socket can be abused for root" \
            "https://github.com/initstring/dirty_sock | Reliability: ~90%" \
            "snapd version: ${snapd_ver} ; Socket: /run/snapd.socket" \
            "Update snapd to >= 2.37.2. Restrict snap socket access." \
            "https://nvd.nist.gov/vuln/detail/CVE-2019-7304" \
            "T1068"
    fi
}

# ──────────────────────────────────────────────────────────────
# runc version check (CVE-2019-5736, CVE-2024-21626)
# ──────────────────────────────────────────────────────────────
_check_runc() {
    cmd_exists runc || return

    local runc_ver=""
    runc_ver=$(runc --version 2>/dev/null | grep runc | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

    [[ -z "$runc_ver" ]] && return

    echo -e "  ${CYAN}[INFO]${RESET} runc version: ${runc_ver}"

    if version_lt "$runc_ver" "1.0.0-rc7"; then
        add_finding "HIGH" "containers" "CVE-2019-5736" "runc container escape" \
            "runc ${runc_ver} is vulnerable to CVE-2019-5736 - container escape possible" \
            "https://github.com/Frichetten/CVE-2019-5736-PoC | Requires container execution" \
            "runc version: ${runc_ver} ; Binary: $(command -v runc 2>/dev/null)" \
            "Update runc to >= 1.0.0-rc7. Use read-only containers where possible." \
            "https://nvd.nist.gov/vuln/detail/CVE-2019-5736" \
            "T1611"
    fi

    if version_lt "$runc_ver" "1.1.12"; then
        add_finding "HIGH" "containers" "CVE-2024-21626" "runc Leaky Vessels container escape" \
            "runc ${runc_ver} < 1.1.12 is vulnerable to CVE-2024-21626 - file descriptor leak" \
            "Host filesystem access possible via runc process.cwd" \
            "runc version: ${runc_ver} ; Binary: $(command -v runc 2>/dev/null)" \
            "Update runc to >= 1.1.12. Update container runtime (Docker/containerd)." \
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21626" \
            "T1611"
    fi
}

# ──────────────────────────────────────────────────────────────
# OpenSSH CVE-2024-6387 regreSSHion check
# ──────────────────────────────────────────────────────────────
_check_openssh_regresshion() {
    cmd_exists ssh || cmd_exists sshd || return

    local ssh_ver=""
    if cmd_exists sshd; then
        ssh_ver=$(sshd -V 2>&1 | grep -oiE 'OpenSSH_[0-9]+\.[0-9]+[p0-9]*' | head -1 | sed 's/OpenSSH_//')
    fi
    [[ -z "$ssh_ver" ]] && ssh_ver=$(ssh -V 2>&1 | grep -oiE 'OpenSSH_[0-9]+\.[0-9]+[p0-9]*' | head -1 | sed 's/OpenSSH_//')
    [[ -z "$ssh_ver" ]] && return

    local major minor
    major=$(echo "$ssh_ver" | cut -d. -f1)
    minor=$(echo "$ssh_ver" | cut -d. -f2 | grep -oE '^[0-9]+')

    # Vulnerable: 8.5p1 <= version < 9.8p1
    if [[ "$major" -eq 8 && "$minor" -ge 5 ]] || [[ "$major" -eq 9 && "$minor" -lt 8 ]]; then
        add_finding "CRITICAL" "kernel" "CVE-2024-6387" "OpenSSH regreSSHion (${ssh_ver})" \
            "OpenSSH ${ssh_ver} is vulnerable to CVE-2024-6387 - sshd race condition RCE" \
            "https://www.exploit-db.com/search?cve=CVE-2024-6387" \
            "OpenSSH version: ${ssh_ver} ; Affected range: 8.5p1 - 9.7p1 ; Binary: $(command -v sshd 2>/dev/null || echo 'N/A')" \
            "Update OpenSSH to >= 9.8p1. As a workaround, set LoginGraceTime=0 in sshd_config (has DoS implications)." \
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387" \
            "T1210"
    fi
}

# ──────────────────────────────────────────────────────────────
# Special kernel feature checks
# ──────────────────────────────────────────────────────────────
_check_special_kernel_features() {
    print_subsection "Special Kernel Features"

    # io_uring
    if [[ -e /proc/sys/kernel/io_uring_disabled ]]; then
        local iou
        iou=$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null)
        if [[ "$iou" == "0" ]]; then
            print_info "io_uring: enabled (multiple CVEs exist)"
            add_finding "LOW" "kernel" "-" "io_uring enabled" \
                "io_uring is enabled - multiple UAF vulnerabilities target this subsystem (CVE-2022-3910, CVE-2023-2598)" \
                "" \
                "Sysctl: kernel.io_uring_disabled=${iou}" \
                "Disable io_uring for unprivileged users: sysctl -w kernel.io_uring_disabled=2" \
                "https://attack.mitre.org/techniques/T1068/" \
                "T1068"
        fi
    fi

    # eBPF
    local bpf_disabled
    bpf_disabled=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)
    if [[ "$bpf_disabled" == "0" ]]; then
        print_warn "eBPF unprivileged: enabled"
    fi

    # User namespaces
    if [[ -r /proc/sys/user/max_user_namespaces ]]; then
        local max_ns
        max_ns=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)
        if [[ "${max_ns:-0}" -gt 0 ]]; then
            print_info "User namespaces: enabled (limit: ${max_ns})"
        fi
    fi

    # SMEP/SMAP/KPTI (x86)
    if [[ "$SYSTEM_ARCH" =~ x86 ]]; then
        if grep -q smep /proc/cpuinfo 2>/dev/null; then
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_good "SMEP: enabled (hardware)"
        fi
        if grep -q smap /proc/cpuinfo 2>/dev/null; then
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_good "SMAP: enabled (hardware)"
        fi
    fi
}
