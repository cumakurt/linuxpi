#!/usr/bin/env bash
# modules/containers/container_detect.sh - Container escape detection and analysis

run_container_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "CONTAINER ANALYSIS"

    local start_ms
    start_ms=$(timestamp_ms)

    if [[ "$SYSTEM_IS_CONTAINER" != "1" ]]; then
        if [[ "${CONTAINER_MODE:-0}" != "1" ]]; then
            print_info "Not running inside a container (use --container-mode to force)"
            return
        fi
    fi

    print_info "Container type: ${SYSTEM_CONTAINER_TYPE:-detected}"

    _check_docker_socket
    _check_privileged_container
    _check_container_capabilities
    _check_container_mounts
    _check_container_namespace
    _check_writable_host_paths
    _check_kubernetes_secrets
    _check_container_env_credentials

    log_timing "container_enum" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# Docker socket check
# ──────────────────────────────────────────────────────────────
_check_docker_socket() {
    print_subsection "Docker Socket"

    local docker_sockets=(
        "/var/run/docker.sock"
        "/run/docker.sock"
        "/tmp/docker.sock"
    )

    for sock in "${docker_sockets[@]}"; do
        [[ -S "$sock" ]] || continue

        echo -e "  ${BOLD_RED}[CRIT]${RESET} Docker socket found: ${sock}"

        if is_readable "$sock" || is_writable "$sock"; then
            local _ds_r _ds_w
            [[ -r "$sock" ]] && _ds_r=yes || _ds_r=no
            [[ -w "$sock" ]] && _ds_w=yes || _ds_w=no
            add_finding "CRITICAL" "containers" "-" "Docker socket accessible: ${sock}" \
                "Docker socket is accessible - trivial host escape via container creation" \
                "docker -H unix://${sock} run -v /:/mnt --rm -it alpine chroot /mnt sh" \
                "socket=${sock} perms=$(file_perms "$sock" 2>/dev/null) owner=$(file_owner "$sock" 2>/dev/null) user_read=${_ds_r} user_write=${_ds_w}" \
                "Do not mount docker.sock into workloads; restrict socket to root/docker group; use rootless Docker or remote API with TLS and auth; enforce PodSecurity policies." \
                "https://attack.mitre.org/techniques/T1611/" \
                "T1611"

            # Docker daemon version bilgisi
            if cmd_exists docker; then
                local docker_ver
                docker_ver=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
                [[ -n "$docker_ver" ]] && echo -e "  ${GREY}Docker version: ${docker_ver}${RESET}"
            fi
        fi
    done
}

# ──────────────────────────────────────────────────────────────
# Privileged container check
# ──────────────────────────────────────────────────────────────
_check_privileged_container() {
    print_subsection "Container Privileges"

    # CapEff check - all capabilities present = privileged container
    local cap_eff
    cap_eff=$(cat /proc/self/status 2>/dev/null | grep CapEff | awk '{print $2}')

    if [[ -n "$cap_eff" ]]; then
        local cap_decimal
        cap_decimal=$(printf '%d' "0x${cap_eff}" 2>/dev/null)

        if [[ "$cap_eff" == "0000003fffffffff" ]] || [[ "$cap_eff" == "000001ffffffffff" ]]; then
            add_finding "CRITICAL" "containers" "-" "Privileged container detected" \
                "Container has full capabilities (privileged=true) - host escape trivial" \
                "nsenter --mount=/proc/1/ns/mnt -- /bin/bash  OR  mount /dev/sda1 /mnt && chroot /mnt" \
                "/proc/self/status CapEff=${cap_eff} CapEff_decimal=${cap_decimal:-n/a} matches_privileged_mask=yes" \
                "Run containers without --privileged; drop capabilities with cap-drop; use securityContext.capabilities in Kubernetes; apply seccomp and AppArmor/SELinux profiles." \
                "https://attack.mitre.org/techniques/T1611/" \
                "T1611"
            print_finding "CRITICAL" "Privileged container" "All capabilities granted - full host access"
        fi
    fi

    # --pid=host check
    local pid_ns_host
    pid_ns_host=$(readlink /proc/self/ns/pid 2>/dev/null)
    local pid_ns_init
    pid_ns_init=$(readlink /proc/1/ns/pid 2>/dev/null)
    if [[ -n "$pid_ns_host" ]] && [[ "$pid_ns_host" == "$pid_ns_init" ]]; then
        add_finding "HIGH" "containers" "-" "PID namespace shared with host" \
            "Container shares PID namespace with host - can manipulate host processes" \
            "nsenter -t 1 -m -u -i -n -p -- bash" \
            "self_pid_ns=${pid_ns_host} init_pid_ns=${pid_ns_init} proc_link=/proc/self/ns/pid" \
            "Avoid --pid=host; use isolated PID namespaces; enforce admission policies blocking hostPID in Kubernetes." \
            "https://attack.mitre.org/techniques/T1611/" \
            "T1611"
    fi

    # --net=host check
    local net_ns
    net_ns=$(readlink /proc/self/ns/net 2>/dev/null)
    local init_net_ns
    init_net_ns=$(readlink /proc/1/ns/net 2>/dev/null)
    if [[ -n "$net_ns" ]] && [[ "$net_ns" == "$init_net_ns" ]]; then
        add_finding "MEDIUM" "containers" "-" "Network namespace shared with host" \
            "Container shares network namespace with host" \
            "Network traffic sniffing and manipulation possible" \
            "self_net_ns=${net_ns} init_net_ns=${init_net_ns}" \
            "Avoid --network host; require dedicated network namespaces; segment sensitive services from container workloads." \
            "https://attack.mitre.org/techniques/T1611/" \
            "T1611"
    fi
}

# ──────────────────────────────────────────────────────────────
# Container capabilities
# ──────────────────────────────────────────────────────────────
_check_container_capabilities() {
    print_subsection "Container Capabilities"

    local status_file="/proc/self/status"
    [[ -r "$status_file" ]] || return

    local dangerous_caps=(
        "CAP_SYS_ADMIN:CRITICAL:load kernel modules, mount, etc - near root"
        "CAP_SYS_PTRACE:HIGH:ptrace any process including host processes"
        "CAP_SYS_MODULE:CRITICAL:load/unload kernel modules"
        "CAP_NET_ADMIN:MEDIUM:configure network - ARP spoofing, packet injection"
        "CAP_DAC_READ_SEARCH:HIGH:bypass file read permissions - read any file"
        "CAP_DAC_OVERRIDE:HIGH:bypass file write permissions"
        "CAP_CHOWN:MEDIUM:change file ownership including /etc/shadow"
        "CAP_SETUID:CRITICAL:can call setuid to escalate to root"
        "CAP_SETGID:CRITICAL:can call setgid for group escalation"
        "CAP_SYS_RAWIO:HIGH:raw disk access"
        "CAP_MKNOD:MEDIUM:create device files"
    )

    local cap_bnd
    cap_bnd=$(grep CapBnd "$status_file" 2>/dev/null | awk '{print $2}')

    [[ -z "$cap_bnd" ]] && return

    for cap_entry in "${dangerous_caps[@]}"; do
        IFS=: read -r cap_name sev desc <<< "$cap_entry"

        # Calculate and check capability bit
        local cap_bit
        cap_bit=$(_cap_name_to_bit "$cap_name")
        [[ -z "$cap_bit" ]] && continue

        if (( (16#$cap_bnd >> cap_bit) & 1 )); then
            echo -e "  $(color_for_severity "$sev")[${sev:0:4}]${RESET} ${cap_name}: ${desc}"
            add_finding "$sev" "containers" "-" "Container has ${cap_name}" \
                "Container has ${cap_name} capability: ${desc}" \
                "_See: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#${cap_name,,}" \
                "CapBnd=$(grep CapBnd "$status_file" 2>/dev/null | awk '{print $2}') cap_name=${cap_name} bit=${cap_bit}" \
                "Drop unnecessary capabilities (cap-drop ALL, add only required); use Kubernetes securityContext; prefer non-root UIDs and seccomp; audit images for capability needs." \
                "https://attack.mitre.org/techniques/T1611/" \
                "T1611"
        fi
    done
}

_cap_name_to_bit() {
    local cap_name="${1^^}"
    local -A cap_bits=(
        [CAP_CHOWN]=0 [CAP_DAC_OVERRIDE]=1 [CAP_DAC_READ_SEARCH]=2
        [CAP_FOWNER]=3 [CAP_FSETID]=4 [CAP_KILL]=5
        [CAP_SETGID]=6 [CAP_SETUID]=7 [CAP_SETPCAP]=8
        [CAP_LINUX_IMMUTABLE]=9 [CAP_NET_BIND_SERVICE]=10
        [CAP_NET_BROADCAST]=11 [CAP_NET_ADMIN]=12 [CAP_NET_RAW]=13
        [CAP_IPC_LOCK]=14 [CAP_IPC_OWNER]=15 [CAP_SYS_MODULE]=16
        [CAP_SYS_RAWIO]=17 [CAP_SYS_CHROOT]=18 [CAP_SYS_PTRACE]=19
        [CAP_SYS_PACCT]=20 [CAP_SYS_ADMIN]=21 [CAP_SYS_BOOT]=22
        [CAP_SYS_NICE]=23 [CAP_SYS_RESOURCE]=24 [CAP_SYS_TIME]=25
        [CAP_SYS_TTY_CONFIG]=26 [CAP_MKNOD]=27 [CAP_LEASE]=28
        [CAP_AUDIT_WRITE]=29 [CAP_AUDIT_CONTROL]=30 [CAP_SETFCAP]=31
        [CAP_MAC_OVERRIDE]=32 [CAP_MAC_ADMIN]=33 [CAP_SYSLOG]=34
        [CAP_WAKE_ALARM]=35 [CAP_BLOCK_SUSPEND]=36
    )
    echo "${cap_bits[$cap_name]:-}"
}

# ──────────────────────────────────────────────────────────────
# Container mount check
# ──────────────────────────────────────────────────────────────
_check_container_mounts() {
    print_subsection "Container Mounts"

    local sensitive_host_paths=(
        "/etc" "/root" "/home" "/var" "/tmp"
        "/proc" "/sys" "/dev"
        "/boot" "/lib/modules"
    )

    while IFS= read -r mount_line; do
        local mount_point mount_src
        mount_point=$(echo "$mount_line" | awk '{print $5}')
        mount_src=$(echo "$mount_line" | awk -F' - ' '{print $2}' | awk '{print $2}')

        for sensitive in "${sensitive_host_paths[@]}"; do
            if [[ "$mount_src" == "$sensitive"* ]] || [[ "$mount_point" == "$sensitive" ]]; then
                add_finding "HIGH" "containers" "-" "Host path mounted: ${mount_src} -> ${mount_point}" \
                    "Host directory ${mount_src} is mounted into container - host access possible" \
                    "ls -la ${mount_point}" \
                    "mountinfo_line=$(echo "$mount_line" | head -c 220) sensitive_match=${sensitive}" \
                    "Remove broad host bind mounts; use read-only, subpath, and tmpfs; enforce allowed hostPath policies; never mount Docker socket or / from host unless strictly isolated." \
                    "https://attack.mitre.org/techniques/T1611/" \
                    "T1611"
            fi
        done

    done < /proc/self/mountinfo 2>/dev/null

    # /dev accessible
    if [[ -d /dev ]] && ls /dev/sd* /dev/xvd* /dev/nvme* &>/dev/null; then
        add_finding "HIGH" "containers" "-" "Host block devices accessible in container" \
            "Host block devices (/dev/sd*, etc.) are accessible - can mount host filesystem" \
            "mkdir /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host" \
            "dev_sample=$(ls /dev/sd* /dev/xvd* /dev/nvme* 2>/dev/null | head -5 | tr '\n' ' ')" \
            "Use cgroup/device controllers; avoid --privileged; set defaultDevices cgroup rules; in Kubernetes disable hostDevices and unsafe sysctl; use read-only root where possible." \
            "https://attack.mitre.org/techniques/T1611/" \
            "T1611"
    fi
}

# ──────────────────────────────────────────────────────────────
# Namespace check
# ──────────────────────────────────────────────────────────────
_check_container_namespace() {
    print_subsection "Namespace Analysis"

    if cmd_exists nsenter; then
        # PID 1 namespace'ine girebilir miyiz?
        if nsenter -t 1 -m echo "test" &>/dev/null; then
            add_finding "CRITICAL" "containers" "-" "nsenter to PID 1 possible" \
                "Can enter host PID 1 namespace - full host access" \
                "nsenter --mount=/proc/1/ns/mnt -- /bin/bash" \
                "check=nsenter_-t_1_-m_echo_test succeeded binary=$(command -v nsenter 2>/dev/null) nsenter_perms=$(file_perms "$(command -v nsenter 2>/dev/null)" 2>/dev/null)" \
                "Remove CAP_SYS_ADMIN from workloads; block nsenter in restricted images; use user namespaces and seccomp; prevent mount namespace sharing with host init." \
                "https://attack.mitre.org/techniques/T1611/" \
                "T1611"
        fi
    fi

    # Cgroup escape check
    local cgroup_info
    cgroup_info=$(cat /proc/1/cgroup 2>/dev/null | head -3)
    if [[ -n "$cgroup_info" ]]; then
        [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${GREY}cgroup: ${cgroup_info}${RESET}"
    fi
}

# ──────────────────────────────────────────────────────────────
# Writable host path check
# ──────────────────────────────────────────────────────────────
_check_writable_host_paths() {
    print_subsection "Writable Host Paths"

    local critical_paths=(
        "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly"
        "/etc/init.d" "/etc/rc.d" "/etc/rc.local"
        "/etc/sudoers.d" "/etc/ld.so.preload"
        "/usr/lib/systemd/system" "/lib/systemd/system"
    )

    for path in "${critical_paths[@]}"; do
        if [[ -e "$path" ]] && is_writable "$path"; then
            local _crit_type
            [[ -d "$path" ]] && _crit_type=dir || _crit_type=file
            add_finding "CRITICAL" "containers" "-" "Writable critical host path: ${path}" \
                "Critical system path ${path} is writable from container" \
                "Write malicious content to achieve persistence/escalation" \
                "path=${path} type=${_crit_type} perms=$(file_perms "$path" 2>/dev/null) owner=$(file_owner "$path" 2>/dev/null)" \
                "Fix host-side permissions and ownership; remove dangerous volume mounts; use read-only rootfs and separate volumes for each concern; scan for writes from containers." \
                "https://attack.mitre.org/techniques/T1611/" \
                "T1611"
        fi
    done
}

# ──────────────────────────────────────────────────────────────
# Kubernetes secret check
# ──────────────────────────────────────────────────────────────
_check_kubernetes_secrets() {
    local sa_dir="/var/run/secrets/kubernetes.io/serviceaccount"
    [[ -d "$sa_dir" ]] || return

    print_subsection "Kubernetes ServiceAccount"

    local sa_token="${sa_dir}/token"
    local sa_cert="${sa_dir}/ca.crt"
    local sa_ns="${sa_dir}/namespace"

    if [[ -r "$sa_token" ]]; then
        local namespace
        namespace=$(cat "$sa_ns" 2>/dev/null || echo "unknown")
        local _sa_cert_ok
        [[ -r "$sa_cert" ]] && _sa_cert_ok=yes || _sa_cert_ok=no

        add_finding "HIGH" "containers" "-" "Kubernetes SA token accessible" \
            "ServiceAccount token found for namespace: ${namespace}" \
            "kubectl --token=\$(cat ${sa_token}) get pods -n ${namespace}" \
            "token_path=${sa_token} token_perms=$(file_perms "$sa_token" 2>/dev/null) token_owner=$(file_owner "$sa_token" 2>/dev/null) namespace=${namespace} ca.crt_present=${_sa_cert_ok}" \
            "Use least-privilege RBAC for service accounts; disable default SA token mounting when unused; rotate tokens; network policy to API server; store secrets in external secret managers with short TTL." \
            "https://attack.mitre.org/techniques/T1552/007/" \
            "T1552.007"

        echo -e "  ${BOLD_YELLOW}[HIGH]${RESET} Kubernetes SA token: ${sa_token}"
        echo -e "         ${GREY}Namespace: ${namespace}${RESET}"

        # kubectl API check
        if cmd_exists kubectl; then
            local k8s_perms
            k8s_perms=$(kubectl auth can-i --list 2>/dev/null | head -5)
            if [[ -n "$k8s_perms" ]]; then
                echo -e "  ${GREY}SA permissions (first 5):${RESET}"
                echo "$k8s_perms" | while read -r line; do
                    echo -e "    ${GREY}${line}${RESET}"
                done
            fi
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Container environment variable credentials
# ──────────────────────────────────────────────────────────────
_check_container_env_credentials() {
    print_subsection "Container Environment Secrets"

    local sensitive_vars=(
        "SECRET" "PASSWORD" "PASSWD" "TOKEN" "KEY"
        "AWS_" "AZURE_" "GCP_" "GOOGLE_"
        "DATABASE_URL" "REDIS_URL" "MONGODB_URI"
        "API_KEY" "SERVICE_ACCOUNT"
    )

    local found=0
    for var_prefix in "${sensitive_vars[@]}"; do
        local matches
        matches=$(env 2>/dev/null | grep -iE "^${var_prefix}" | head -3)
        if [[ -n "$matches" ]]; then
            if [[ $found -eq 0 ]]; then
                add_finding "HIGH" "containers" "-" "Sensitive environment variables in container" \
                    "Container environment contains potential secrets" \
                    "env | grep -iE 'secret|password|token|key|aws|azure|gcp'" \
                    "matched_prefix=${var_prefix} sample_vars=$(echo "$matches" | sed 's/=.*/=REDACTED/' | head -3 | tr '\n' '; ')" \
                    "Inject secrets via mounted files or secret stores; avoid plain env for credentials; use external secret operators; scrub CI/CD logs and image history." \
                    "https://attack.mitre.org/techniques/T1552/001/" \
                    "T1552.001"
            fi
            echo "$matches" | head -2 | while read -r var; do
                local masked="${var%%=*}=$(echo "${var#*=}" | head -c 20)..."
                echo -e "  ${BOLD_YELLOW}[CRED]${RESET} ${masked}"
            done
            found=1
        fi
    done
}
