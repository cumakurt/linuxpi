#!/usr/bin/env bash
# modules/services/service_enum.sh - Running services and process analysis

run_service_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "SERVICES & PROCESSES"

    local start_ms
    start_ms=$(timestamp_ms)

    _enum_running_processes
    _enum_running_services
    _check_writable_service_files
    _check_process_credentials
    _enum_installed_software
    _check_packagekit_pack2theroot

    log_timing "service_enum" "$(elapsed_since "$start_ms")"
}

_enum_running_processes() {
    print_subsection "Running Processes"

    local ps_output
    if cmd_exists ps; then
        ps_output=$(ps auxww 2>/dev/null || ps -ef 2>/dev/null)
    else
        ps_output=$(cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ')
    fi

    [[ -z "$ps_output" ]] && return

    # Interesting root processes
    local root_procs
    root_procs=$(echo "$ps_output" | grep "^root " | grep -vE "^\s*(PID|ps |grep )" | head -20)

    if [[ -n "$root_procs" ]] && [[ "${VERBOSE_MODE:-0}" == "1" ]]; then
        echo -e "  ${GREY}Root processes (first 20):${RESET}"
        echo "$root_procs" | while IFS= read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    fi

    # Process arguments that may expose credentials
    local cred_procs
    cred_procs=$(echo "$ps_output" | grep -iE "\-p\s+[^\s]+|\-\-password[= ][^\s]+|password=[^\s]+" | grep -v "^root.*ssh\|^root.*grep")

    if [[ -n "$cred_procs" ]]; then
        add_finding "HIGH" "services" "-" "Credentials visible in process arguments" \
            "Running processes expose credentials in command line arguments" \
            "ps auxww | grep -iE 'password|passwd|secret'" \
            "sample_proc_lines=$(echo "$cred_procs" | head -3 | tr '\n' '; ' | head -c 400)" \
            "Pass secrets via files, FDs, or secret managers; clear argv in wrappers; use systemd credentials; rotate any exposed credentials; audit apps for CLI password flags." \
            "https://attack.mitre.org/techniques/T1057/" \
            "T1057"
        echo -e "  ${BOLD_YELLOW}[HIGH]${RESET} Credentials in process args:"
        echo "$cred_procs" | head -5 | while IFS= read -r line; do
            echo -e "  ${GREY}${line:0:120}${RESET}"
        done
    fi

    # /proc/[pid]/cmdline - comprehensive scan
    _check_proc_cmdlines
}

_check_proc_cmdlines() {
    local patterns=("password" "passwd" "secret" "token" "api.key" "mysql.*-p" "psql.*-U")

    for pid_dir in /proc/[0-9]*/; do
        local pid
        pid=$(basename "$pid_dir")
        local cmdline_file="${pid_dir}cmdline"

        [[ -r "$cmdline_file" ]] || continue

        local cmdline
        cmdline=$(tr '\0' ' ' < "$cmdline_file" 2>/dev/null)

        for pattern in "${patterns[@]}"; do
            if echo "$cmdline" | grep -qi "$pattern"; then
                local proc_user
                proc_user=$(stat -c '%U' "$pid_dir" 2>/dev/null)
                echo -e "  ${BOLD_YELLOW}[CRED]${RESET} PID ${pid} (${proc_user}): ${cmdline:0:100}"
                break
            fi
        done
    done
}

_enum_running_services() {
    print_subsection "Running Services"

    if cmd_exists systemctl; then
        local services
        services=$(safe_run 5 systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30)
        if [[ -n "$services" ]]; then
            echo -e "  ${GREY}Active services:${RESET}"
            echo "$services" | head -20 | while IFS= read -r line; do
                echo -e "  ${GREY}${line}${RESET}"
            done
        fi
    fi

    # Known vulnerable services
    _check_vulnerable_services
}

_check_vulnerable_services() {
    declare -A vulnerable_services=(
        ["mysql"]="Check for: anonymous auth, weak passwords, UDF injection"
        ["mysqld"]="Check for: anonymous auth, weak passwords, UDF injection"
        ["postgres"]="Check for: trust auth in pg_hba.conf"
        ["postgresql"]="Check for: trust auth in pg_hba.conf"
        ["redis-server"]="Check for: no auth (redis-cli INFO)"
        ["mongodb"]="Check for: no auth enabled"
        ["memcached"]="Check for: no SASL auth, stats slabs"
        ["docker"]="Check for: socket access, API exposure"
        ["kubelet"]="Check for: anonymous API access port 10250"
        ["etcd"]="Check for: unauthenticated access port 2379"
        ["smtp"]="Check for: open relay, VRFY/EXPN enabled"
        ["ftpd"]="Check for: anonymous FTP, writable dirs"
        ["vsftpd"]="Check for: CVE-2011-2523 backdoor (2.3.4)"
        ["apache2"]="Check for: server-status, outdated modules"
        ["nginx"]="Check for: path traversal, outdated version"
        ["tomcat"]="Check for: manager app default creds, PUT upload"
        ["jenkins"]="Check for: anonymous auth, script console"
        ["elasticsearch"]="Check for: no auth (default)"
        ["kibana"]="Check for: no auth, SSRF"
        ["consul"]="Check for: ACL bypass, RCE via exec"
        ["vault"]="Check for: unsealed without auth"
    )

    local ps_output
    ps_output=$(ps aux 2>/dev/null || ps -ef 2>/dev/null)

    for service in "${!vulnerable_services[@]}"; do
        if echo "$ps_output" | grep -qi "/$service\b\|/$service " || pgrep -x "$service" &>/dev/null; then
            local advice="${vulnerable_services[$service]}"
            echo -e "  ${BOLD_CYAN}[SVC]${RESET} ${service} is running"
            print_info "$advice"
            add_finding "INFO" "services" "-" "Service running: ${service}" "$advice" "" \
                "process_match=${service} note=${advice}" \
                "Harden default configs, patch, enable auth, restrict bind addresses, and follow vendor hardening guides for ${service}." \
                "https://attack.mitre.org/techniques/T1007/" \
                "T1007"
        fi
    done
}

_check_writable_service_files() {
    print_subsection "Writable Service Files"

    local service_dirs=(
        "/etc/systemd/system"
        "/lib/systemd/system"
        "/usr/lib/systemd/system"
        "/etc/init.d"
        "/etc/rc.d/init.d"
        "/etc/init"
    )

    for service_dir in "${service_dirs[@]}"; do
        [[ -d "$service_dir" ]] || continue

        while IFS= read -r service_file; do
            if is_writable "$service_file"; then
                add_finding "CRITICAL" "services" "-" "Writable service file: ${service_file}" \
                    "System service file is writable - modify to run arbitrary commands as root" \
                    "sed -i 's/ExecStart=.*/ExecStart=\\/bin\\/bash -c \"chmod +s \\/bin\\/bash\"/' ${service_file} && systemctl daemon-reload && systemctl restart SERVICE" \
                    "file=${service_file} perms=$(file_perms "$service_file" 2>/dev/null) owner=$(file_owner "$service_file" 2>/dev/null) scan_dir=${service_dir}" \
                    "Restore root ownership and 644 on unit files; use systemd drop-ins under /etc; enable package manager integrity checks; monitor /etc/systemd/system for changes." \
                    "https://attack.mitre.org/techniques/T1543/002/" \
                    "T1543.002"
                echo -e "  ${BOLD_RED}[CRIT]${RESET} Writable service: ${service_file}"
            fi
        done < <(find "$service_dir" -type f \( -name "*.service" -o -name "*.sh" \) 2>/dev/null | head -50)
    done
}

_check_process_credentials() {
    print_subsection "Process Memory Credentials"

    # Check memory-mapped credential files via /proc/$pid/maps
    if [[ "$SYSTEM_UID" == "0" ]] || ls /proc/*/mem &>/dev/null; then
        for pid_dir in /proc/[0-9]*/; do
            local maps_file="${pid_dir}maps"
            [[ -r "$maps_file" ]] || continue

            if grep -qiE "\.env|credentials|secrets" "$maps_file" 2>/dev/null; then
                local pid
                pid=$(basename "$pid_dir")
                local proc_name
                proc_name=$(cat "${pid_dir}comm" 2>/dev/null)
                print_info "Process ${pid} (${proc_name}) has credential files mapped"
            fi
        done
    fi
}

_enum_installed_software() {
    print_subsection "Installed Software (Security-Relevant)"

    local interesting_pkgs=(
        "gcc" "g++" "cc" "make"
        "python" "python2" "python3"
        "perl" "ruby" "php" "lua"
        "nodejs" "npm" "go"
        "git" "svn" "wget" "curl" "fetch"
        "nmap" "netcat" "nc" "ncat"
        "socat" "netcat-traditional"
        "wireshark" "tcpdump" "tshark"
        "gdb" "ltrace" "strace"
        "docker" "podman" "lxc" "lxd"
        "ansible" "puppet" "chef" "salt"
        "screen" "tmux"
        "vim" "nano" "emacs"
        "awk" "sed" "cut"
    )

    local found_pkgs=()
    for pkg in "${interesting_pkgs[@]}"; do
        if cmd_exists "$pkg"; then
            local version
            version=$("$pkg" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            found_pkgs+=("${pkg}:${version:-?}")
        fi
    done

    if [[ ${#found_pkgs[@]} -gt 0 ]]; then
        echo -e "  ${GREY}Available tools:${RESET}"
        local cols=0
        for pkg_ver in "${found_pkgs[@]}"; do
            printf "  ${CYAN}%-20s${RESET}" "$pkg_ver"
            cols=$(( cols + 1 ))
            [[ $((cols % 4)) -eq 0 ]] && echo ""
        done
        [[ $((cols % 4)) -ne 0 ]] && echo ""

        # Compile capability - exploit compilation
        if cmd_exists gcc || cmd_exists g++ || cmd_exists cc; then
            local _cc_path _cc_ver
            _cc_path=$(command -v gcc 2>/dev/null || command -v g++ 2>/dev/null || command -v cc 2>/dev/null)
            _cc_ver=$({ gcc --version || g++ --version || cc --version; } 2>/dev/null | head -1 | head -c 120)
            add_finding "INFO" "services" "-" "C compiler available (exploit compilation possible)" \
                "gcc/cc is installed - can compile kernel exploits locally" \
                "gcc exploit.c -o exploit && ./exploit" \
                "compiler_path=${_cc_path:-unknown} version_line=${_cc_ver:-n/a}" \
                "Remove build toolchains from production images; use read-only root and image signing; restrict compiler execution with SELinux/AppArmor or capability drops." \
                "https://attack.mitre.org/techniques/T1027/004/" \
                "T1027.004"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# PackageKit CVE-2026-41651 Pack2TheRoot check
# ──────────────────────────────────────────────────────────────
_normalize_pkg_semver() {
    local out
    out="$(echo "$1" | grep -oE '[0-9]+(\.[0-9]+){1,2}' | head -1 || true)"
    echo "$out"
}

_packagekit_version() {
    local raw=""

    if cmd_exists packagekitd; then
        raw="$(packagekitd --version 2>/dev/null | head -1)"
        raw="$(_normalize_pkg_semver "$raw")"
        [[ -n "$raw" ]] && { echo "$raw"; return; }
    fi

    if cmd_exists pkcon; then
        raw="$(pkcon --version 2>/dev/null | head -1)"
        raw="$(_normalize_pkg_semver "$raw")"
        [[ -n "$raw" ]] && { echo "$raw"; return; }
    fi

    for pkg in PackageKit packagekit; do
        raw="$(pkg_version "$pkg" 2>/dev/null | head -1)"
        raw="$(_normalize_pkg_semver "$raw")"
        [[ -n "$raw" ]] && { echo "$raw"; return; }
    done
}

_check_packagekit_pack2theroot() {
    cmd_exists packagekitd || cmd_exists pkcon || [[ -d /usr/share/PackageKit ]] || [[ -f /usr/lib/systemd/system/packagekit.service ]] || return

    print_subsection "PackageKit Security"

    local pk_ver service_state pkcon_path daemon_path
    pk_ver="$(_packagekit_version)"
    pkcon_path="$(command -v pkcon 2>/dev/null || echo n/a)"
    daemon_path="$(command -v packagekitd 2>/dev/null || echo n/a)"

    if cmd_exists systemctl; then
        service_state="$(systemctl is-active packagekit.service 2>/dev/null || echo inactive)"
    else
        service_state="unknown"
    fi

    [[ -z "$pk_ver" ]] && {
        add_finding "INFO" "services" "CVE-2026-41651" "PackageKit installed but version unknown" \
            "PackageKit artifacts are present, but the scanner could not determine the version for CVE-2026-41651 assessment." \
            "pkcon --version; packagekitd --version" \
            "packagekitd=${daemon_path} ; pkcon=${pkcon_path} ; packagekit.service=${service_state}" \
            "Check the vendor advisory and package changelog for CVE-2026-41651 fixes; prefer PackageKit >= 1.3.5 or vendor backport." \
            "https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv ; https://nvd.nist.gov/vuln/detail/CVE-2026-41651" \
            "T1068"
        return
    }

    echo -e "  ${CYAN}[INFO]${RESET} PackageKit version: ${pk_ver}"

    if version_gte "$pk_ver" "1.0.2" && version_lt "$pk_ver" "1.3.5"; then
        add_finding "HIGH" "services" "CVE-2026-41651" "Pack2TheRoot: PackageKit local privilege escalation (${pk_ver})" \
            "PackageKit ${pk_ver} is in the vulnerable upstream range for CVE-2026-41651, a D-Bus authorization flaw that can allow local users to install or alter packages as root." \
            "pkcon install-local ./malicious-package.rpm" \
            "PackageKit version=${pk_ver} ; packagekitd=${daemon_path} ; pkcon=${pkcon_path} ; packagekit.service=${service_state}" \
            "Update PackageKit to >= 1.3.5 or a vendor package with the CVE-2026-41651 backport. If PackageKit is not required, disable packagekit.service and restrict local D-Bus policy." \
            "https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv ; https://nvd.nist.gov/vuln/detail/CVE-2026-41651" \
            "T1068"
    fi
}
