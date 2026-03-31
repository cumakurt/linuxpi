#!/usr/bin/env bash
# core/detector.sh - Platform, environment, and virtualization detection

# ──────────────────────────────────────────────────────────────
# Plain global variables (replaces fragile associative array)
# ──────────────────────────────────────────────────────────────
SYSTEM_KERNEL=""
SYSTEM_KERNEL_SHORT=""
SYSTEM_ARCH=""
SYSTEM_HOSTNAME=""
SYSTEM_DISTRO=""
SYSTEM_DISTRO_VER=""
SYSTEM_DISTRO_CODENAME=""
SYSTEM_INIT=""
SYSTEM_UPTIME=""
SYSTEM_CPU_COUNT=""
SYSTEM_IS_CONTAINER="0"
SYSTEM_CONTAINER_TYPE=""
SYSTEM_IS_VM="0"
SYSTEM_VM_TYPE=""
SYSTEM_CLOUD_PROVIDER=""
SYSTEM_IS_CLOUD="0"
SYSTEM_SHELL=""
SYSTEM_USER=""
SYSTEM_UID=""
SYSTEM_GID=""
SYSTEM_HOME=""

# ──────────────────────────────────────────────────────────────
# Basic system information
# ──────────────────────────────────────────────────────────────
detect_system_info() {
    SYSTEM_KERNEL="$(uname -r 2>/dev/null)"
    SYSTEM_KERNEL_SHORT="$(parse_kernel_version "$SYSTEM_KERNEL")"
    SYSTEM_ARCH="$(uname -m 2>/dev/null)"
    SYSTEM_HOSTNAME="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)"
    SYSTEM_UPTIME="$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk '{print $3,$4}' | tr -d ',')"
    SYSTEM_CPU_COUNT="$(nproc 2>/dev/null || grep -c processor /proc/cpuinfo 2>/dev/null || echo 1)"
    SYSTEM_SHELL="${SHELL:-unknown}"
    SYSTEM_USER="$(id -un 2>/dev/null)"
    SYSTEM_UID="$(id -u 2>/dev/null)"
    SYSTEM_GID="$(id -g 2>/dev/null)"
    SYSTEM_HOME="${HOME:-$(getent passwd "$SYSTEM_USER" 2>/dev/null | cut -d: -f6)}"

    log_info "System: ${SYSTEM_KERNEL} ${SYSTEM_ARCH} user=${SYSTEM_USER}(${SYSTEM_UID})"
}

# ──────────────────────────────────────────────────────────────
# Distribution detection (50+ distros)
# ──────────────────────────────────────────────────────────────
detect_distro() {
    local name="" version="" codename=""

    if [[ -f /etc/os-release ]]; then
        name="$(grep -m1 '^NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
        version="$(grep -m1 '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
        codename="$(grep -m1 '^VERSION_CODENAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
    elif [[ -f /etc/lsb-release ]]; then
        name="$(grep DISTRIB_ID /etc/lsb-release | cut -d= -f2)"
        version="$(grep DISTRIB_RELEASE /etc/lsb-release | cut -d= -f2)"
        codename="$(grep DISTRIB_CODENAME /etc/lsb-release | cut -d= -f2)"
    elif [[ -f /etc/debian_version ]]; then
        name="Debian"
        version="$(cat /etc/debian_version)"
    elif [[ -f /etc/redhat-release ]]; then
        name="$(cat /etc/redhat-release | awk '{print $1}')"
        version="$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+')"
    elif [[ -f /etc/alpine-release ]]; then
        name="Alpine"
        version="$(cat /etc/alpine-release)"
    elif [[ -f /etc/arch-release ]]; then
        name="Arch"
        version="rolling"
    elif [[ -f /etc/gentoo-release ]]; then
        name="Gentoo"
        version="$(cat /etc/gentoo-release | grep -oE '[0-9.]+')"
    elif [[ -f /etc/slackware-version ]]; then
        name="Slackware"
        version="$(cat /etc/slackware-version | awk '{print $2}')"
    fi

    SYSTEM_DISTRO="${name:-Unknown}"
    SYSTEM_DISTRO_VER="${version:-unknown}"
    SYSTEM_DISTRO_CODENAME="${codename:-}"

    log_info "Distro: ${SYSTEM_DISTRO} ${SYSTEM_DISTRO_VER}"
}

# ──────────────────────────────────────────────────────────────
# Init system detection
# ──────────────────────────────────────────────────────────────
detect_init_system() {
    local init="unknown"

    if [[ -d /run/systemd/system ]]; then
        init="systemd"
    elif [[ -f /etc/init.d/cron ]] || [[ -d /etc/init.d ]]; then
        init="sysvinit"
    elif cmd_exists openrc; then
        init="openrc"
    elif [[ -f /sbin/upstart ]]; then
        init="upstart"
    elif [[ -f /etc/s6 ]] || [[ -d /etc/s6 ]]; then
        init="s6"
    fi

    SYSTEM_INIT="$init"
}

# ──────────────────────────────────────────────────────────────
# Container detection
# ──────────────────────────────────────────────────────────────
detect_container() {
    local container_type=""

    if [[ -f /.dockerenv ]]; then
        container_type="docker"
    elif grep -qa 'docker' /proc/1/cgroup 2>/dev/null; then
        container_type="docker"
    elif [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        container_type="kubernetes"
    elif grep -qa 'lxc' /proc/1/cgroup 2>/dev/null || [[ -f /run/host-rootfs ]]; then
        container_type="lxc"
    elif grep -qa 'containerd\|cri-o' /proc/1/cgroup 2>/dev/null; then
        container_type="containerd"
    elif [[ -f /run/.containerenv ]]; then
        container_type="podman"
        [[ "$(id -u)" != "0" ]] && container_type="podman-rootless"
    elif [[ -f /run/host/os-release ]] || grep -qa 'systemd-nspawn' /proc/1/environ 2>/dev/null; then
        container_type="nspawn"
    elif [[ -f /proc/vz/veinfo ]] || [[ -d /proc/vz ]]; then
        container_type="openvz"
    elif [[ -f /proc/1/status ]] && grep -qa 'security.jail' /proc/1/status 2>/dev/null; then
        container_type="jail"
    fi

    if [[ -n "$container_type" ]]; then
        SYSTEM_IS_CONTAINER="1"
        SYSTEM_CONTAINER_TYPE="$container_type"
        log_warn "Container detected: $container_type"
    fi
}

# ──────────────────────────────────────────────────────────────
# Virtualization detection
# ──────────────────────────────────────────────────────────────
detect_virtualization() {
    [[ "$SYSTEM_IS_CONTAINER" == "1" ]] && return 0

    local vm_type=""

    if cmd_exists systemd-detect-virt; then
        vm_type="$(systemd-detect-virt 2>/dev/null || true)"
        [[ "$vm_type" == "none" ]] && vm_type=""
    fi

    if [[ -z "$vm_type" ]]; then
        local dmi_product
        dmi_product="$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")"

        case "${dmi_product,,}" in
            *vmware*)         vm_type="vmware" ;;
            *virtualbox*)     vm_type="virtualbox" ;;
            *"kvm"*|*"qemu"*) vm_type="kvm" ;;
            *"microsoft"*|*"hyper-v"*) vm_type="hyperv" ;;
            *"xen"*)          vm_type="xen" ;;
            *"bochs"*)        vm_type="bochs" ;;
            *"parallels"*)    vm_type="parallels" ;;
        esac
    fi

    if [[ -z "$vm_type" ]]; then
        if grep -qa 'hypervisor\|QEMU\|VMware\|VirtualBox' /proc/cpuinfo 2>/dev/null; then
            vm_type="hypervisor"
        fi
    fi

    if [[ -n "$vm_type" ]]; then
        SYSTEM_IS_VM="1"
        SYSTEM_VM_TYPE="$vm_type"
        log_info "VM detected: $vm_type"
    fi
}

# ──────────────────────────────────────────────────────────────
# Cloud provider detection
# ──────────────────────────────────────────────────────────────
detect_cloud_provider() {
    local provider=""

    if safe_run 2 curl -sf --max-time 1 http://169.254.169.254/latest/meta-data/ami-id &>/dev/null; then
        provider="aws"
    elif safe_run 2 curl -sf --max-time 1 -H "Metadata-Flavor: Google" \
        http://metadata.google.internal/computeMetadata/v1/instance/id &>/dev/null; then
        provider="gcp"
    elif safe_run 2 curl -sf --max-time 1 -H "Metadata: true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
        provider="azure"
    elif safe_run 2 curl -sf --max-time 1 http://169.254.169.254/opc/v1/instance/ &>/dev/null; then
        provider="oracle"
    elif safe_run 2 curl -sf --max-time 1 http://169.254.169.254/metadata/v1/id &>/dev/null; then
        provider="digitalocean"
    elif [[ -f /etc/cloud/cloud.cfg ]]; then
        provider="$(grep -oE 'aws|gcp|azure|oracle|digitalocean|hetzner' /etc/cloud/cloud.cfg 2>/dev/null | head -1)"
    fi

    if [[ -n "$provider" ]]; then
        SYSTEM_IS_CLOUD="1"
        SYSTEM_CLOUD_PROVIDER="$provider"
        log_info "Cloud provider detected: $provider"
    fi
}

# ──────────────────────────────────────────────────────────────
# Detection orchestrator
# ──────────────────────────────────────────────────────────────
run_detection() {
    local start_ms
    start_ms=$(timestamp_ms)

    detect_system_info
    detect_distro
    detect_init_system
    detect_container
    detect_virtualization

    [[ "${STEALTH_MODE:-0}" != "1" ]] && detect_cloud_provider

    log_timing "detector" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# Print system info summary
# ──────────────────────────────────────────────────────────────
print_system_info() {
    print_section "SYSTEM INFORMATION"

    print_subsection "Host Details"
    echo -e "  ${BOLD_WHITE}Hostname:${RESET}    ${SYSTEM_HOSTNAME}"
    echo -e "  ${BOLD_WHITE}OS:${RESET}          ${SYSTEM_DISTRO} ${SYSTEM_DISTRO_VER} ${SYSTEM_DISTRO_CODENAME:+(${SYSTEM_DISTRO_CODENAME})}"
    echo -e "  ${BOLD_WHITE}Kernel:${RESET}      ${SYSTEM_KERNEL}"
    echo -e "  ${BOLD_WHITE}Arch:${RESET}        ${SYSTEM_ARCH}"
    echo -e "  ${BOLD_WHITE}Init:${RESET}        ${SYSTEM_INIT}"
    echo -e "  ${BOLD_WHITE}Uptime:${RESET}      ${SYSTEM_UPTIME}"
    echo -e "  ${BOLD_WHITE}CPUs:${RESET}        ${SYSTEM_CPU_COUNT}"

    print_subsection "Current User"
    echo -e "  ${BOLD_WHITE}User:${RESET}        ${SYSTEM_USER} (UID=${SYSTEM_UID}, GID=${SYSTEM_GID})"
    echo -e "  ${BOLD_WHITE}Shell:${RESET}       ${SYSTEM_SHELL}"
    echo -e "  ${BOLD_WHITE}Home:${RESET}        ${SYSTEM_HOME}"

    if [[ "${SYSTEM_UID}" == "0" ]]; then
        print_good "Running as ROOT"
    fi

    print_subsection "Environment"
    if [[ "${SYSTEM_IS_CONTAINER}" == "1" ]]; then
        print_warn "Container environment: ${SYSTEM_CONTAINER_TYPE}"
    fi
    if [[ "${SYSTEM_IS_VM}" == "1" ]]; then
        print_info "Virtual machine: ${SYSTEM_VM_TYPE}"
    fi
    if [[ "${SYSTEM_IS_CLOUD}" == "1" ]]; then
        print_warn "Cloud environment: ${SYSTEM_CLOUD_PROVIDER}"
    fi
}
