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
        "af_alg" "algif_aead" "esp4" "esp6" "rxrpc" "cifs"
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
# Kernel CVE helper functions
# ──────────────────────────────────────────────────────────────
_kernel_db_stream() {
    local kernel_db="$1"

    if [[ -f "$kernel_db" ]]; then
        cat "$kernel_db"
        return 0
    fi

    # Standalone builds embed the DB in KERNEL_DB_CONTENT instead of shipping
    # modules/kernel/kernel_exploits.db next to the generated script.
    if [[ -n "${KERNEL_DB_CONTENT:-}" ]]; then
        printf '%s\n' "$KERNEL_DB_CONTENT"
        return 0
    fi

    return 1
}

_kernel_version_in_affected_range() {
    local kernel="$1"
    local min_kernel="$2"
    local max_kernel="$3"

    min_kernel="$(trim "$min_kernel")"
    max_kernel="$(trim "$max_kernel")"

    [[ -z "$kernel" || -z "$min_kernel" || -z "$max_kernel" ]] && return 1
    [[ "$min_kernel" == "-" || "$max_kernel" == "-" ]] && return 1

    version_lte "$min_kernel" "$kernel" && version_lte "$kernel" "$max_kernel"
}

_kernel_sysctl_value() {
    local param="$1"
    local proc_path="/proc/sys/${param//./\/}"

    if cmd_exists sysctl; then
        sysctl -n "$param" 2>/dev/null && return 0
    fi
    [[ -r "$proc_path" ]] && cat "$proc_path" 2>/dev/null
}

_kernel_module_state() {
    local mod="$1"

    if [[ -d "/sys/module/${mod}" ]] || grep -q "^${mod} " /proc/modules 2>/dev/null; then
        echo "loaded"
        return
    fi

    if cmd_exists modinfo && safe_run 2 modinfo "$mod" &>/dev/null; then
        echo "available"
        return
    fi

    echo "absent"
}

_kernel_proc_crypto_contains() {
    local pattern="$1"
    [[ -r /proc/crypto ]] && grep -qi "$pattern" /proc/crypto 2>/dev/null && echo "yes" || echo "no"
}

_kernel_cmdline_blacklists() {
    local initcall="$1"
    grep -q "initcall_blacklist=[^ ]*${initcall}" /proc/cmdline 2>/dev/null && echo "yes" || echo "no"
}

_kernel_config_state() {
    local sym="$1"
    if declare -F _kernel_research_load_config &>/dev/null && declare -F _kernel_research_config_sym &>/dev/null; then
        _kernel_research_load_config &>/dev/null || { echo "unknown"; return; }
        _kernel_research_config_sym "$sym"
        return
    fi
    echo "unknown"
}

_kernel_userns_context() {
    local clone max_ns
    clone="$(_kernel_sysctl_value kernel.unprivileged_userns_clone)"
    max_ns="$(_kernel_sysctl_value user.max_user_namespaces)"
    echo "kernel.unprivileged_userns_clone=${clone:-n/a}; user.max_user_namespaces=${max_ns:-n/a}"
}

_kernel_setuid_helper_summary() {
    local helpers=()
    local candidate

    for candidate in \
        /usr/bin/chage \
        /usr/bin/pkexec \
        /usr/lib/openssh/ssh-keysign \
        /usr/libexec/openssh/ssh-keysign \
        /usr/lib/accountsservice/accounts-daemon \
        /usr/libexec/accountsservice/accounts-daemon; do
        [[ -e "$candidate" ]] || continue
        if is_suid "$candidate"; then
            helpers+=("$(basename "$candidate"):suid")
        elif [[ "$candidate" == *accounts-daemon && -x "$candidate" ]]; then
            helpers+=("$(basename "$candidate"):root-helper")
        fi
    done

    if [[ ${#helpers[@]} -gt 0 ]]; then
        local IFS=','
        echo "${helpers[*]}"
    else
        echo "none-observed"
    fi
}

_kernel_request_key_rule_state() {
    local f

    for f in /etc/request-key.conf /etc/request-key.d/*.conf /usr/lib/request-key.d/*.conf /lib/request-key.d/*.conf; do
        [[ -r "$f" ]] || continue
        if grep -q 'cifs\.spnego' "$f" 2>/dev/null; then
            echo "present:${f}"
            return
        fi
    done

    echo "absent"
}

_kernel_cve_exploit_reference() {
    case "$1" in
        CVE-2026-31431) echo "https://github.com/theori-io/copy-fail-CVE-2026-31431" ;;
        CVE-2026-46243) echo "https://github.com/manizada/CIFSwitch" ;;
        CVE-2026-31635) echo "https://github.com/v12-security/pocs/tree/main/dirtydecrypt" ;;
        *)              echo "https://www.exploit-db.com/search?cve=$1" ;;
    esac
}

_kernel_recent_cve_evidence() {
    local cve_id="$1"
    local kernel="$2"
    local ev=""

    case "$cve_id" in
        CVE-2026-31431)
            ev="CopyFail context: af_alg=$(_kernel_module_state af_alg), algif_aead=$(_kernel_module_state algif_aead), authenc_in_proc_crypto=$(_kernel_proc_crypto_contains 'authenc'), initcall_blacklist_algif_aead=$(_kernel_cmdline_blacklists algif_aead_init), initcall_blacklist_af_alg=$(_kernel_cmdline_blacklists af_alg_init)"
            ;;
        CVE-2026-43284)
            ev="Dirty Frag ESP context: esp4=$(_kernel_module_state esp4), esp6=$(_kernel_module_state esp6), CONFIG_XFRM=$(_kernel_config_state CONFIG_XFRM), $(_kernel_userns_context)"
            ;;
        CVE-2026-43500)
            ev="Dirty Frag RxRPC context: rxrpc=$(_kernel_module_state rxrpc), CONFIG_RXRPC=$(_kernel_config_state CONFIG_RXRPC), CONFIG_AF_RXRPC=$(_kernel_config_state CONFIG_AF_RXRPC), $(_kernel_userns_context)"
            ;;
        CVE-2026-46300)
            ev="Fragnesia XFRM context: esp4=$(_kernel_module_state esp4), esp6=$(_kernel_module_state esp6), xfrm_user=$(_kernel_module_state xfrm_user), CONFIG_XFRM=$(_kernel_config_state CONFIG_XFRM), $(_kernel_userns_context)"
            ;;
        CVE-2026-46333)
            local ptrace_scope pidfd_likely
            ptrace_scope="$(_kernel_sysctl_value kernel.yama.ptrace_scope)"
            version_gte "$kernel" "5.6.0" && pidfd_likely="yes" || pidfd_likely="no-or-backport-dependent"
            ev="ssh-keysign-pwn context: ptrace_scope=${ptrace_scope:-n/a}, pidfd_getfd_likely=${pidfd_likely}, setuid_or_root_helpers=$(_kernel_setuid_helper_summary)"
            ;;
        CVE-2026-31635)
            ev="DirtyDecrypt RxGK context: rxrpc=$(_kernel_module_state rxrpc), CONFIG_RXGK=$(_kernel_config_state CONFIG_RXGK), CONFIG_AF_RXRPC=$(_kernel_config_state CONFIG_AF_RXRPC)"
            ;;
    esac

    [[ -n "$ev" ]] && echo "; ${ev}"
}

_kernel_recent_cve_remediation() {
    case "$1" in
        CVE-2026-31431)
            echo " If patching is delayed, evaluate vendor-supported AF_ALG/algif_aead initcall blacklist mitigations; validate crypto workload impact."
            ;;
        CVE-2026-43284|CVE-2026-46300)
            echo " If patching is delayed, block/unload esp4 and esp6 where IPsec is not required; otherwise disable unprivileged user namespaces per vendor guidance."
            ;;
        CVE-2026-43500)
            echo " If patching is delayed, block/unload rxrpc where AFS/RxRPC is not required and disable unprivileged user namespaces where operationally safe."
            ;;
        CVE-2026-46333)
            echo " If patching is delayed, set kernel.yama.ptrace_scope=2 or stricter and rotate SSH host keys/secrets if untrusted local users had access."
            ;;
        CVE-2026-31635)
            echo " If CONFIG_RXGK/RxRPC is enabled and not required, disable the feature or unload rxrpc until the vendor kernel is patched."
            ;;
        *) echo "" ;;
    esac
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
    if ! _kernel_db_stream "$kernel_db" >/dev/null 2>&1; then
        print_error "kernel_exploits.db not found at ${kernel_db} and no embedded database is available"
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

        if _kernel_version_in_affected_range "$kernel" "$clean_min" "$clean_max"; then
            local exploit_note=""
            [[ "$exploit_avail" == "true" ]] && exploit_note="${BOLD_GREEN}[Exploit Available]${RESET}" || exploit_note="${YELLOW}[No Public Exploit]${RESET}"

            local color
            color=$(color_for_severity "$severity")

            echo -e "  ${color}[${severity:0:4}]${RESET} ${BOLD_WHITE}${cve_id}${RESET} - ${name}"
            echo -e "         ${GREY}${desc}${RESET}"
            echo -e "         CVSS: ${cvss} | ${exploit_note}"

            local exploit_cmd="-"
            [[ "$exploit_avail" == "true" ]] && exploit_cmd="$(_kernel_cve_exploit_reference "$cve_id")"

            local recent_evidence recent_remediation
            recent_evidence="$(_kernel_recent_cve_evidence "$cve_id" "$kernel")"
            recent_remediation="$(_kernel_recent_cve_remediation "$cve_id")"

            add_finding "$severity" "kernel" "$cve_id" "${cve_id}: ${name}" \
                "Kernel ${kernel} is vulnerable. ${desc}" \
                "$exploit_cmd" \
                "Kernel: ${kernel} (${SYSTEM_ARCH}) ; Affected range: ${clean_min} - ${clean_max} ; CVSS: ${cvss} ; Exploit available: ${exploit_avail}${recent_evidence}" \
                "Update kernel to latest patched version. Apply vendor security patches.${recent_remediation}" \
                "https://nvd.nist.gov/vuln/detail/${cve_id}" \
                "T1068"

            found_count=$(( found_count + 1 ))
        fi
    done < <(_kernel_db_stream "$kernel_db")

    if [[ $found_count -eq 0 ]]; then
        print_good "No known kernel CVEs matched for $kernel"
    else
        echo -e "\n  ${BOLD_RED}Total kernel CVEs matched: ${found_count}${RESET}"
    fi

    # CIFSwitch requires a component chain rather than a reliable kernel-only
    # version range while NVD enrichment is still pending.
    _check_cifswitch

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
# CIFSwitch CVE-2026-46243: CIFS cifs.spnego upcall LPE chain
# ──────────────────────────────────────────────────────────────
_check_cifswitch() {
    local cifs_state upcall req_rule keyctl_state cifs_utils_ver userns_clone max_userns

    cifs_state="$(_kernel_module_state cifs)"
    upcall="$(command -v cifs.upcall 2>/dev/null || true)"
    [[ -z "$upcall" && -x /usr/sbin/cifs.upcall ]] && upcall="/usr/sbin/cifs.upcall"
    [[ -z "$upcall" && -x /sbin/cifs.upcall ]] && upcall="/sbin/cifs.upcall"

    req_rule="$(_kernel_request_key_rule_state)"
    cmd_exists keyctl && keyctl_state="present" || keyctl_state="absent"
    cifs_utils_ver="$(pkg_version cifs-utils 2>/dev/null | head -1)"
    [[ -z "$cifs_utils_ver" && -n "$upcall" ]] && cifs_utils_ver="installed-version-unknown"
    userns_clone="$(_kernel_sysctl_value kernel.unprivileged_userns_clone)"
    max_userns="$(_kernel_sysctl_value user.max_user_namespaces)"

    [[ "$cifs_state" == "absent" || -z "$upcall" || "$req_rule" == "absent" ]] && return

    local severity="HIGH"
    if [[ "${userns_clone:-}" == "0" ]] && [[ "${max_userns:-0}" =~ ^[0-9]+$ ]] && [[ "${max_userns:-0}" -eq 0 ]]; then
        severity="MEDIUM"
    fi

    add_finding "$severity" "kernel" "CVE-2026-46243" "CIFSwitch: CIFS cifs.spnego upcall LPE chain present" \
        "CIFS kernel support, cifs.upcall, and a cifs.spnego request-key rule are present. This matches the known CVE-2026-46243 attack chain for root command execution via forged cifs.spnego key descriptions." \
        "https://github.com/manizada/CIFSwitch" \
        "cifs_module=${cifs_state} ; cifs.upcall=${upcall} ; cifs_utils=${cifs_utils_ver:-unknown} ; request_key_rule=${req_rule} ; keyctl=${keyctl_state} ; kernel.unprivileged_userns_clone=${userns_clone:-n/a} ; user.max_user_namespaces=${max_userns:-n/a}" \
        "Apply the vendor kernel fix. If SMB/CIFS client access is not required, blocklist/unload cifs, remove cifs-utils, or disable the cifs.spnego request-key rule; keep SELinux/AppArmor enforcing and restrict local shell access." \
        "https://access.redhat.com/security/vulnerabilities/RHSB-2026-005 ; https://nvd.nist.gov/vuln/detail/CVE-2026-46243" \
        "T1068"
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
