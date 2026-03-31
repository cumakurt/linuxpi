#!/usr/bin/env bash
# core/enumerator.sh - Enumeration orchestrator managing all modules

# ──────────────────────────────────────────────────────────────
# User/permission analysis (runs before all modules)
# ──────────────────────────────────────────────────────────────
run_user_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "USER & PRIVILEGE ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    _check_current_user
    _check_group_memberships
    _check_home_permissions
    _check_privilege_tokens

    log_timing "user_enum" "$(elapsed_since "$start_ms")"
}

_check_current_user() {
    print_subsection "Current User Context"

    local uid="$SYSTEM_UID"
    local user="$SYSTEM_USER"

    # Already root?
    if [[ "$uid" == "0" ]]; then
        add_finding "INFO" "user" "-" "Running as root" \
            "Already running as root - no privilege escalation needed" "" \
            "uid=0 user=${user} id_output=$(id 2>/dev/null | head -c 200)" \
            "Ensure session is expected; apply least privilege for automation; rotate credentials used on this host." \
            "https://attack.mitre.org/techniques/T1078/" \
            "T1078"
        print_good "Already running as ROOT"
        return
    fi

    # Sudo group membership
    if id 2>/dev/null | grep -qiE "sudo|wheel|admin"; then
        print_warn "User is member of sudo/admin group"
        add_finding "HIGH" "user" "-" "Member of privileged group (sudo/wheel)" \
            "User ${user} is in sudo/wheel/admin group - may have password-based sudo access. Try: sudo -l; sudo su - (password may be required)." \
            "-" \
            "user=${user} groups=$(id -nG 2>/dev/null | tr ' ' ',')" \
            "Require MFA for sudo where available; use sudoers defaults targetpw; audit sudoers; remove users from wheel/sudo when not needed." \
            "https://attack.mitre.org/techniques/T1078/" \
            "T1078"
    fi

    echo -e "  ${BOLD_WHITE}User:${RESET}    ${user} (UID=${uid})"
    echo -e "  ${BOLD_WHITE}Groups:${RESET}  $(id 2>/dev/null)"
}

_check_group_memberships() {
    print_subsection "Group Memberships"

    declare -A interesting_groups=(
        ["docker"]="CRITICAL:Can escape to host via: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        ["lxd"]="CRITICAL:Can escape via: lxc image import... && lxc init... && lxc config device add..."
        ["disk"]="CRITICAL:Direct disk access: debugfs /dev/sda1 then read files"
        ["shadow"]="CRITICAL:Can read /etc/shadow: cat /etc/shadow"
        ["sudo"]="HIGH:May have sudo access: sudo -l"
        ["wheel"]="HIGH:May have sudo access: sudo -l"
        ["adm"]="HIGH:Can read system logs: cat /var/log/auth.log"
        ["staff"]="HIGH:Can install packages in /usr/local"
        ["root"]="CRITICAL:Directly in root group"
        ["kmem"]="HIGH:Can read kernel memory"
        ["tape"]="MEDIUM:Access to tape devices"
        ["video"]="LOW:Access to video devices"
        ["audio"]="LOW:Access to audio devices (potential eavesdrop)"
        ["plugdev"]="LOW:Can mount removable devices"
        ["netdev"]="MEDIUM:Can manage network devices"
        ["kvm"]="HIGH:Can manage VMs - possible escape"
        ["systemd-journal"]="MEDIUM:Can read all system journal logs"
        ["ssl-cert"]="HIGH:Can access SSL private keys in /etc/ssl/private"
        ["wireshark"]="MEDIUM:Can capture network traffic"
        ["crontab"]="MEDIUM:Can modify crontabs"
    )

    local user_groups
    user_groups=$(id 2>/dev/null | grep -oE '\([a-z_][a-z0-9_-]*\)' | tr -d '()')

    while IFS= read -r grp; do
        if [[ -n "${interesting_groups[$grp]:-}" ]]; then
            IFS=: read -r sev exploit <<< "${interesting_groups[$grp]}"
            print_finding "$sev" "Group membership: ${grp}" "$exploit"
            add_finding "$sev" "user" "-" "Interesting group membership: ${grp}" \
                "User is member of ${grp} group" "$exploit" \
                "user=${SYSTEM_USER} group=${grp} gid_list=$(id -G 2>/dev/null | tr ' ' ',')" \
                "Review whether membership is required; apply group-based ACLs on docker.sock, disks, and shadow; use separate service accounts." \
                "https://attack.mitre.org/techniques/T1078/" \
                "T1078"
        fi
    done <<< "$user_groups"
}

_check_home_permissions() {
    print_subsection "Home Directory Permissions"

    local home="$SYSTEM_HOME"
    [[ -d "$home" ]] || return

    local home_perms
    home_perms=$(file_perms "$home")

    # World readable home
    if [[ "${home_perms: -1}" =~ [4-7] ]]; then
        print_warn "Home directory is world-readable: ${home} (${home_perms})"
        add_finding "MEDIUM" "user" "-" "World-readable home directory" \
            "${home} is world-readable (${home_perms}) - may expose sensitive files" \
            "ls -la ${home}/.ssh ${home}/.bash_history ${home}/.profile" \
            "home=${home} perms=${home_perms} owner=$(file_owner "$home" 2>/dev/null)" \
            "chmod 750 or 700 on home directories; ensure dotfiles are not group/world readable; use autofs with proper umask." \
            "https://attack.mitre.org/techniques/T1222/002/" \
            "T1222.002"
    fi
}

_check_privilege_tokens() {
    print_subsection "Authentication Tokens"

    # Sudo credential cache (recent sudo)
    if [[ -d /run/sudo/ts ]] || [[ -d /var/lib/sudo/lectured ]]; then
        local ts_files
        ts_files=$(ls /run/sudo/ts/ 2>/dev/null)
        if [[ -n "$ts_files" ]]; then
            print_info "Active sudo timestamp tokens found"
        fi
    fi

    # Polkit active sessions
    if cmd_exists pkttyagent; then
        print_debug "Polkit agent present"
    fi
}

# ──────────────────────────────────────────────────────────────
# Filesystem scan
# ──────────────────────────────────────────────────────────────
run_filesystem_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "FILESYSTEM ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    _check_world_writable
    _check_sensitive_files
    _check_mounted_filesystems
    _check_disk_files

    log_timing "filesystem_enum" "$(elapsed_since "$start_ms")"
}

_check_world_writable() {
    print_subsection "World-Writable Directories"

    local ww_dirs
    ww_dirs=$(safe_run 30 find / \
        -not \( -path /proc -prune \) \
        -not \( -path /sys -prune \) \
        -not \( -path /dev -prune \) \
        -not \( -path /run -prune \) \
        -perm -0002 -type d 2>/dev/null | grep -v "^/tmp\|^/var/tmp\|^/run/user" | head -30)

    if [[ -n "$ww_dirs" ]]; then
        while IFS= read -r dir; do
            [[ -z "$dir" ]] && continue
            echo -e "  ${BOLD_YELLOW}[WW]${RESET} ${dir}"
            add_finding "LOW" "filesystem" "-" "World-writable directory: ${dir}" \
                "Directory ${dir} is world-writable" "" \
                "path=${dir} perms=$(file_perms "$dir" 2>/dev/null) owner=$(file_owner "$dir" 2>/dev/null)" \
                "Remove world-writable bit or use sticky + controlled group ownership; relocate shared data to dedicated volumes with ACLs." \
                "https://attack.mitre.org/techniques/T1222/002/" \
                "T1222.002"
        done <<< "$ww_dirs"
    else
        [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_good "No unexpected world-writable directories"
    fi
}

_check_sensitive_files() {
    print_subsection "Sensitive File Permissions"

    declare -A sensitive_files=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/sudoers"]="440"
        ["/etc/crontab"]="600"
        ["/etc/ssh/sshd_config"]="600"
        ["/root/.ssh/authorized_keys"]="600"
        ["/boot/grub/grub.cfg"]="600"
    )

    for filepath in "${!sensitive_files[@]}"; do
        [[ -e "$filepath" ]] || continue
        local expected_perms="${sensitive_files[$filepath]}"
        local actual_perms
        actual_perms=$(file_perms "$filepath")

        if [[ -z "$actual_perms" ]]; then continue; fi

        # Overly permissive file permissions
        local actual_int
        actual_int=$(printf '%d' "0$actual_perms" 2>/dev/null)
        local expected_int
        expected_int=$(printf '%d' "0$expected_perms" 2>/dev/null)

        if [[ "$actual_int" -gt "$expected_int" ]]; then
            print_warn "${filepath}: ${actual_perms} (expected: ≤${expected_perms})"
        fi

        # Readable sensitive files
        if [[ "$filepath" == "/etc/shadow" ]] && is_readable "$filepath"; then
            add_finding "CRITICAL" "filesystem" "-" "/etc/shadow readable" \
                "/etc/shadow has permissions ${actual_perms} and is readable" \
                "cat /etc/shadow | cut -d: -f1,2 | grep -v '*\\|!'" \
                "file=/etc/shadow perms=${actual_perms} owner=$(file_owner /etc/shadow 2>/dev/null)" \
                "chmod 640, chown root:shadow; ensure no ACLs grant extra read; audit pam/unix auth configuration." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
        fi
    done
}

_check_mounted_filesystems() {
    print_subsection "Mounted Filesystems"

    if [[ -r /proc/mounts ]]; then
        while IFS= read -r mount_line; do
            echo -e "  ${GREY}${mount_line}${RESET}"

            # noexec bypass possibilities
            if echo "$mount_line" | grep -q "exec" && ! echo "$mount_line" | grep -q "noexec"; then
                local mount_point
                mount_point=$(echo "$mount_line" | awk '{print $2}')
                if [[ "$mount_point" == "/tmp" ]] || [[ "$mount_point" == "/var/tmp" ]]; then
                    add_finding "INFO" "filesystem" "-" "Executable /tmp or /var/tmp" \
                        "${mount_point} is mounted without noexec - binaries can be executed from here" \
                        "Compile and run exploits from ${mount_point}" \
                        "mount_point=${mount_point} mount_line=$(echo "$mount_line" | head -c 220)" \
                        "Add noexec,nosuid,nodev to /tmp and /var/tmp in fstab or systemd; remount; provide alternate paths for legitimate binaries if needed." \
                        "https://attack.mitre.org/techniques/T1562/001/" \
                        "T1562.001"
                fi
            fi
        done < <(cat /proc/mounts 2>/dev/null | head -20)
    fi
}

_check_disk_files() {
    print_subsection "Disk & Backup Files"

    local disk_patterns=("*.tar.gz" "*.tar.bz2" "*.zip" "*.sql" "*.dump" "*.bak" "*.old")

    for pattern in "${disk_patterns[@]}"; do
        while IFS= read -r found; do
            echo -e "  ${CYAN}[FILE]${RESET} ${found}"
            add_finding "LOW" "filesystem" "-" "Backup/archive file: ${found}" \
                "Backup file may contain sensitive information" "cat/extract ${found}" \
                "path=${found} perms=$(file_perms "$found" 2>/dev/null) owner=$(file_owner "$found" 2>/dev/null)" \
                "Move backups to encrypted, access-controlled storage; delete stale artifacts from shared paths; scan with DLP before distribution." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
        done < <(safe_run 20 find /tmp /var /opt /home -maxdepth 4 -name "$pattern" -type f 2>/dev/null | head -10)
    done
}

# ──────────────────────────────────────────────────────────────
# Main enumeration orchestrator
# ──────────────────────────────────────────────────────────────
run_all_enumerations() {
    local _mod_start _mod_end _mod_idx=0

    local -a _module_list=(
        "user:run_user_enum"
        "kernel:run_kernel_enum"
        "sudo:run_sudo_enum"
        "suid:run_suid_enum"
        "capabilities:run_capabilities_enum"
        "cron:run_cron_enum"
        "credentials:run_cred_enum"
        "network:run_network_enum"
        "containers:run_container_enum"
        "services:run_service_enum"
        "filesystem:run_filesystem_enum"
        "security:run_security_enum"
    )

    local _active_count=0
    for entry in "${_module_list[@]}"; do
        IFS=: read -r mod_name _ <<< "$entry"
        is_module_active "$mod_name" && _active_count=$(( _active_count + 1 ))
    done

    for entry in "${_module_list[@]}"; do
        [[ "${_INTERRUPTED:-0}" == "1" ]] && break

        IFS=: read -r mod_name mod_func <<< "$entry"
        is_module_active "$mod_name" || continue

        _mod_idx=$(( _mod_idx + 1 ))
        [[ "${QUIET_MODE:-0}" == "0" ]] && [[ "${STEALTH_MODE:-0}" == "0" ]] && \
            print_progress "$_mod_idx" "$_active_count" "$mod_name"

        _mod_start=$(timestamp_ms)
        "$mod_func"
        [[ "${_INTERRUPTED:-0}" == "1" ]] && break
        _mod_end=$(timestamp_ms)
        _track_module_time "$mod_name" "$(( _mod_end - _mod_start ))"
    done
}
