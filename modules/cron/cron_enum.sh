#!/usr/bin/env bash
# modules/cron/cron_enum.sh - Cron/timer based privilege escalation vectors

run_cron_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "CRON & SCHEDULED TASKS"

    local start_ms
    start_ms=$(timestamp_ms)

    _enum_system_crons
    _enum_user_crons
    _enum_systemd_timers
    _enum_at_jobs
    _check_cron_scripts

    log_timing "cron_enum" "$(elapsed_since "$start_ms")"
}

_enum_system_crons() {
    print_subsection "System Cron Jobs"

    local cron_dirs=(
        "/etc/crontab"
        "/etc/cron.d/"
        "/etc/cron.daily/"
        "/etc/cron.hourly/"
        "/etc/cron.weekly/"
        "/etc/cron.monthly/"
    )

    for cron_path in "${cron_dirs[@]}"; do
        if [[ -f "$cron_path" ]]; then
            _analyze_cron_file "$cron_path"
        elif [[ -d "$cron_path" ]]; then
            while IFS= read -r f; do
                _analyze_cron_file "$f"
            done < <(find "$cron_path" -type f 2>/dev/null)
        fi
    done
}

_analyze_cron_file() {
    local cron_file="$1"
    [[ -r "$cron_file" ]] || return

    [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${GREY}Analyzing: ${cron_file}${RESET}"

    # Writable cron file
    if is_writable "$cron_file"; then
        add_finding "CRITICAL" "cron" "-" "Writable cron file: ${cron_file}" \
            "Current user can modify cron file ${cron_file}" \
            "echo '* * * * * root chmod +s /bin/bash' >> ${cron_file}" \
            "file=${cron_file} perms=$(file_perms "$cron_file" 2>/dev/null) owner=$(file_owner "$cron_file" 2>/dev/null)" \
            "Set ownership to root and mode 600/644 per distribution baseline; remove world/group write; audit entries and use immutable attributes only after review." \
            "https://attack.mitre.org/techniques/T1053/003/" \
            "T1053.003"
    fi

    # Script analysis
    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "${line// /}" ]] && continue

        # Extract first executable path from cron command portion
        local script_path
        script_path=$(echo "$line" | awk '{
            i=1;
            while(i<=NF && $i~/^[0-9*,\/-]+$/) i++;
            if(i<=NF && $i!~/^\//) i++;
            for(j=i;j<=NF;j++) if($j~/^\// && $j!~/^\/dev\/null/) {print $j; exit}
        }')

        # Also check for relative-path commands (PATH hijacking)
        local rel_cmd
        rel_cmd=$(echo "$line" | awk '{
            i=1;
            while(i<=NF && $i~/^[0-9*,\/-]+$/) i++;
            if(i<=NF && $i!~/^\//) i++;
            for(j=i;j<=NF;j++) if($j!~/^\// && $j!~/^[0-9*,\/-]+$/ && $j!~/^>/ && length($j)>1) {print $j; exit}
        }')

        if [[ -n "$rel_cmd" ]] && ! command -v "$rel_cmd" &>/dev/null; then
            add_finding "HIGH" "cron" "-" "Relative path in cron: ${rel_cmd}" \
                "Cron job uses relative path '${rel_cmd}' - PATH hijacking possible" \
                "-" \
                "source_file=${cron_file} command_token=${rel_cmd} cron_line_sample=$(echo "$line" | head -c 200)" \
                "Use absolute paths for all cron commands; set a minimal explicit PATH in crontab; ensure PATH directories are root-owned and not group/world-writable." \
                "https://attack.mitre.org/techniques/T1574/007/" \
                "T1574.007"
        fi

        [[ -z "$script_path" ]] && continue

        # Writable script
        if [[ -f "$script_path" ]] && is_writable "$script_path"; then
            add_finding "CRITICAL" "cron" "-" "Writable cron script: ${script_path}" \
                "Cron script ${script_path} is writable by current user" \
                "echo 'chmod +s /bin/bash' >> ${script_path}" \
                "script=${script_path} perms=$(file_perms "$script_path" 2>/dev/null) owner=$(file_owner "$script_path" 2>/dev/null) referenced_from=${cron_file}" \
                "Chown to root, chmod 750/700; move scripts to root-only locations; deploy change control on scheduler content." \
                "https://attack.mitre.org/techniques/T1053/003/" \
                "T1053.003"
        fi

        # Writable parent dir (can create missing script)
        if [[ ! -f "$script_path" ]]; then
            local script_dir
            script_dir=$(dirname "$script_path")
            if [[ -d "$script_dir" ]] && is_writable "$script_dir"; then
                add_finding "HIGH" "cron" "-" "Writable dir for missing cron script: ${script_path}" \
                    "Cron references non-existent ${script_path} in writable directory" \
                    "echo '#!/bin/bash\nchmod +s /bin/bash' > ${script_path} && chmod +x ${script_path}" \
                    "expected_script=${script_path} parent_dir=${script_dir} dir_perms=$(file_perms "$script_dir" 2>/dev/null) dir_owner=$(file_owner "$script_dir" 2>/dev/null) cron_ref=${cron_file}" \
                    "Create the script as root with correct permissions, or fix the cron entry; harden parent directory to root:root and mode 755 without group/world write." \
                    "https://attack.mitre.org/techniques/T1053/003/" \
                    "T1053.003"
            fi
        fi

        # Wildcard injection - extract only the command portion (after time fields + user)
        local cron_cmd
        cron_cmd=$(echo "$line" | awk '{
            i=1;
            while(i<=NF && $i~/^[0-9*,\/-]+$/) i++;
            if(i<=NF && $i!~/^\//) i++;
            cmd=""; for(j=i;j<=NF;j++) cmd=cmd" "$j;
            print cmd
        }')
        if echo "$cron_cmd" | grep -qE '\*' && echo "$cron_cmd" | grep -qiE "tar|rsync|chown|chmod"; then
            add_finding "HIGH" "cron" "-" "Wildcard injection in cron: ${cron_file}" \
                "Cron job uses wildcards with tar/rsync/chown - wildcard injection possible" \
                "touch -- '--checkpoint=1' && touch -- '--checkpoint-action=exec=sh linuxpi-payload.sh'" \
                "file=${cron_file} perms=$(file_perms "$cron_file" 2>/dev/null) owner=$(file_owner "$cron_file" 2>/dev/null) command_artifact=$(echo "$cron_cmd" | tr -s ' ' | head -c 240)" \
                "Replace globbing with explicit file lists, use --wildcard=no or equivalent, run jobs from dedicated non-writable directories, and quote paths." \
                "https://attack.mitre.org/techniques/T1053/003/" \
                "T1053.003"
        fi

    done < "$cron_file"
}

_enum_user_crons() {
    print_subsection "User Cron Jobs"

    local current_user
    current_user="$SYSTEM_USER"

    # Current user's crontab
    local user_crontab
    user_crontab=$(crontab -l 2>/dev/null)
    if [[ -n "$user_crontab" ]]; then
        echo -e "  ${CYAN}[INFO]${RESET} Current user crontab:"
        echo "$user_crontab" | while read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    fi

    # /var/spool/cron/crontabs/ - other users
    if [[ -d /var/spool/cron/crontabs ]]; then
        while IFS= read -r cron_file; do
            local cron_user
            cron_user=$(basename "$cron_file")
            if [[ "$cron_user" != "$current_user" ]] && is_readable "$cron_file"; then
                echo -e "  ${BOLD_YELLOW}[READABLE]${RESET} Other user crontab: ${cron_file}"
                _analyze_cron_file "$cron_file"
            fi
        done < <(find /var/spool/cron/crontabs/ -type f 2>/dev/null)
    fi
}

_enum_systemd_timers() {
    print_subsection "Systemd Timers"

    cmd_exists systemctl || return

    local timers
    timers=$(safe_run 5 systemctl list-timers --all --no-pager 2>/dev/null)

    [[ -z "$timers" ]] && return

    echo "$timers" | head -20 | while read -r line; do
        echo -e "  ${GREY}${line}${RESET}"
    done

    # Check timer unit files
    local timer_units
    timer_units=$(safe_run 5 systemctl list-unit-files --type=timer --no-pager 2>/dev/null | grep enabled)

    while IFS= read -r timer_line; do
        local timer_name
        timer_name=$(echo "$timer_line" | awk '{print $1}')
        [[ -z "$timer_name" ]] && continue

        local service_name="${timer_name%.timer}.service"
        local unit_file
        unit_file=$(safe_run 3 systemctl show "$service_name" --property=FragmentPath 2>/dev/null | cut -d= -f2)

        if [[ -n "$unit_file" ]] && [[ -f "$unit_file" ]]; then
            if is_writable "$unit_file"; then
                add_finding "CRITICAL" "cron" "-" "Writable systemd service: ${unit_file}" \
                    "Systemd service unit file is writable - modify ExecStart for privilege escalation" \
                    "echo -e '[Service]\\nExecStart=/bin/bash -c \"chmod +s /bin/bash\"' >> ${unit_file}" \
                    "unit=${unit_file} perms=$(file_perms "$unit_file" 2>/dev/null) owner=$(file_owner "$unit_file" 2>/dev/null) timer=${timer_name} service=${service_name}" \
                    "Restore root ownership and 644 on unit files; use systemd drop-ins in /etc with correct permissions; enable integrity monitoring on /etc/systemd and package-managed units." \
                    "https://attack.mitre.org/techniques/T1543/002/" \
                    "T1543.002"
            fi

            # ExecStart script check
            local exec_start
            exec_start=$(grep -E "^ExecStart=" "$unit_file" 2>/dev/null | head -1 | cut -d= -f2-)
            if [[ -n "$exec_start" ]]; then
                local exec_bin
                exec_bin=$(echo "$exec_start" | awk '{print $1}')
                if [[ -f "$exec_bin" ]] && is_writable "$exec_bin"; then
                    add_finding "HIGH" "cron" "-" "Writable systemd ExecStart: ${exec_bin}" \
                        "Binary executed by systemd service is writable" \
                        "echo 'chmod +s /bin/bash' >> ${exec_bin}" \
                        "exec_target=${exec_bin} perms=$(file_perms "$exec_bin" 2>/dev/null) owner=$(file_owner "$exec_bin" 2>/dev/null) unit=${unit_file} ExecStart_sample=$(echo "$exec_start" | head -c 200)" \
                        "Replace binaries with root-owned immutable copies from packages; point ExecStart to managed scripts in root-only paths; restrict write on interpreter and library paths." \
                        "https://attack.mitre.org/techniques/T1543/002/" \
                        "T1543.002"
                fi
            fi
        fi
    done <<< "$timer_units"
}

_enum_at_jobs() {
    print_subsection "AT Jobs"

    cmd_exists atq || return

    local at_jobs
    at_jobs=$(atq 2>/dev/null)

    if [[ -n "$at_jobs" ]]; then
        echo -e "  ${YELLOW}[WARN]${RESET} Pending AT jobs:"
        echo "$at_jobs" | while read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    else
        [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_info "No pending AT jobs"
    fi

    # at.allow / at.deny
    if [[ -f /etc/at.allow ]]; then
        echo -e "  ${CYAN}[INFO]${RESET} /etc/at.allow:"
        cat /etc/at.allow 2>/dev/null | while read -r line; do
            echo -e "  ${GREY}  ${line}${RESET}"
        done
    fi
}

_check_cron_scripts() {
    print_subsection "Cron Script Security"

    # PATH in cron
    local cron_path
    cron_path=$(grep -hE "^PATH=" /etc/crontab /etc/cron.d/* 2>/dev/null | head -1)
    if [[ -n "$cron_path" ]]; then
        echo -e "  ${CYAN}[INFO]${RESET} Cron PATH: ${cron_path}"

        # Writable directories in cron PATH
        local path_val
        path_val=$(echo "$cron_path" | cut -d= -f2)
        IFS=: read -ra path_dirs <<< "$path_val"

        for path_dir in "${path_dirs[@]}"; do
            if [[ -d "$path_dir" ]] && is_writable "$path_dir"; then
                add_finding "HIGH" "cron" "-" "Writable directory in cron PATH: ${path_dir}" \
                    "Directory ${path_dir} is in cron's PATH and writable" \
                    "Create malicious binary in ${path_dir} with the same name as a cron script" \
                    "path_dir=${path_dir} perms=$(file_perms "$path_dir" 2>/dev/null) owner=$(file_owner "$path_dir" 2>/dev/null) cron_PATH_line=${cron_path}" \
                    "Remove writable non-standard entries from cron PATH; use root-only directories; deploy filesystem integrity checks on PATH components used by cron." \
                    "https://attack.mitre.org/techniques/T1574/007/" \
                    "T1574.007"
            fi
        done
    fi
}
