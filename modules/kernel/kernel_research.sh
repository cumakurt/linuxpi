#!/usr/bin/env bash
# modules/kernel/kernel_research.sh - Advanced / research-oriented kernel & capability context
# Loaded by kernel_enum.sh and suid_finder.sh (capability narratives).

# Cached full config file text (empty if unavailable)
declare -g _KERNEL_RESEARCH_CONFIG_TEXT=""

# ──────────────────────────────────────────────────────────────
# Load running kernel's build configuration when exposed
# ──────────────────────────────────────────────────────────────
_kernel_research_load_config() {
    [[ -n "$_KERNEL_RESEARCH_CONFIG_TEXT" ]] && return 0
    local kver
    kver=$(uname -r 2>/dev/null) || return 1

    if [[ -r "/boot/config-${kver}" ]]; then
        _KERNEL_RESEARCH_CONFIG_TEXT=$(cat "/boot/config-${kver}" 2>/dev/null)
        return 0
    fi
    if [[ -r /proc/config.gz ]]; then
        _KERNEL_RESEARCH_CONFIG_TEXT=$(zcat /proc/config.gz 2>/dev/null)
        return 0
    fi
    return 1
}

# Returns: y | m | n | notset
_kernel_research_config_sym() {
    local sym="$1"
    local line
    line=$(echo "$_KERNEL_RESEARCH_CONFIG_TEXT" | grep -E "^${sym}=" 2>/dev/null | head -1)
    [[ -z "$line" ]] && { echo "notset"; return; }
    case "$line" in
        *"=y"*)  echo "y" ;;
        *"=m"*)  echo "m" ;;
        *"=n"*)  echo "n" ;;
        *)       echo "notset" ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Capability → privilege-escalation class (for evidence enrichment)
# ──────────────────────────────────────────────────────────────
capability_research_append() {
    local c="${1,,}"
    case "$c" in
        cap_sys_admin)
            echo " Research: CAP_SYS_ADMIN allows mount namespace manipulation, many cgroup ops, and historical container-breakout primitives; often sufficient for full root on misconfigured systems."
            ;;
        cap_sys_module)
            echo " Research: CAP_SYS_MODULE permits loading kernel modules — equivalent to arbitrary kernel code execution if module signing is off or bypassed."
            ;;
        cap_setuid)
            echo " Research: CAP_SETUID allows switching EUID; combined with exploitable binaries it commonly yields direct root shells."
            ;;
        cap_setgid)
            echo " Research: CAP_SETGID allows switching EGID; often chained with setgid binaries or supplementary groups for privilege boundaries."
            ;;
        cap_dac_override)
            echo " Research: CAP_DAC_OVERRIDE ignores discretionary read/write/execute checks — enables reading secrets and planting binaries where DAC would block."
            ;;
        cap_dac_read_search)
            echo " Research: CAP_DAC_READ_SEARCH bypasses read/search permission checks — useful for harvesting /etc/shadow, SSH keys, and DB files."
            ;;
        cap_sys_ptrace)
            echo " Research: CAP_SYS_PTRACE allows attaching to processes — classic injection into higher-privilege or same-user processes (depends on Yama/ptrace_scope)."
            ;;
        cap_net_admin)
            echo " Research: CAP_NET_ADMIN enables interface/routing/firewall changes and some tunneling — lateral movement and traffic manipulation."
            ;;
        cap_net_raw)
            echo " Research: CAP_NET_RAW allows raw and packet sockets — spoofing, sniffing on some setups, and protocol-level attacks."
            ;;
        cap_sys_rawio)
            echo " Research: CAP_SYS_RAWIO grants low-level MMIO/port access on some platforms — hardware/kernel adjacent abuse."
            ;;
        cap_chown|cap_fowner)
            echo " Research: File ownership / FOWNER bypass capabilities weaken object DAC; often used to claim SUID files or logs."
            ;;
        cap_kill)
            echo " Research: CAP_KILL can signal arbitrary processes — DoS and sometimes race exploitation with poorly written daemons."
            ;;
        cap_linux_immutable)
            echo " Research: CAP_LINUX_IMMUTABLE sets FS immutable flags — persistence and denial of legitimate admin updates."
            ;;
        cap_audit_write)
            echo " Research: CAP_AUDIT_WRITE can spam or forge audit records — evasion and log poisoning in some configurations."
            ;;
        *)
            echo ""
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# sysfs CPU vulnerability mitigations (Spectre/Meltdown family)
# ──────────────────────────────────────────────────────────────
_enum_cpu_vulnerabilities_sysfs() {
    local vuln_dir="/sys/devices/system/cpu/vulnerabilities"
    [[ -d "$vuln_dir" ]] || return 0

    print_subsection "CPU vulnerability mitigations (sysfs)"
    local f name content
    local summary=""
    for f in "$vuln_dir"/*; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f")
        content=$(tr -s ' \n' ' ' < "$f" 2>/dev/null | head -c 220)
        [[ -z "$content" ]] && continue
        echo -e "  ${GREY}${name}:${RESET} ${content}"
        summary+="; ${name}: ${content}"
    done

    [[ -z "$summary" ]] && return 0

    add_finding "INFO" "kernel" "-" "CPU vulnerability sysfs summary (research)" \
        "Kernel exposes per-vulnerability mitigation state under /sys/devices/system/cpu/vulnerabilities — useful to judge exploit preconditions (e.g. Spectre, Meltdown, retbleed)." \
        "cat /sys/devices/system/cpu/vulnerabilities/*" \
        "Paths: ${vuln_dir}${summary:0:400}" \
        "Keep microcode and kernel updated; follow vendor guidance for retpoline, IBRS, and branch prediction mitigations." \
        "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html" \
        "T1082"
}

# ──────────────────────────────────────────────────────────────
# Selected CONFIG_* symbols with exploit-research context
# ──────────────────────────────────────────────────────────────
_enum_kernel_config_research() {
    print_subsection "Kernel build config (research)"

    if ! _kernel_research_load_config; then
        echo -e "  ${GREY}No readable kernel config (/boot/config-\$(uname -r) or /proc/config.gz).${RESET}"
        add_finding "INFO" "kernel" "-" "Kernel config not exposed (research)" \
            "Build configuration is not available on this system — CONFIG_* hardening cannot be assessed from disk." \
            "Install linux-headers or kernel-debuginfo, or use a distro that ships /boot/config-*." \
            "uname -r=$(uname -r 2>/dev/null)" \
            "Expose config for compliance baselines; not strictly required for runtime sysctl checks." \
            "https://www.kernel.org/doc/html/latest/kbuild/kconfig.html" \
            "T1082"
        return 0
    fi

    echo -e "  ${GREY}Source: boot config or /proc/config.gz${RESET}"

    # sym|label|research note (one line)
    local rows=(
        "CONFIG_RANDOMIZE_BASE|KASLR (kernel image)|When enabled, relocates the kernel text — raises bar for info-leak + ROP chains targeting fixed symbols."
        "CONFIG_STACKPROTECTOR_STRONG|Stack canary (strong)|Helps block stack buffer overflows toward saved return addresses."
        "CONFIG_HARDENED_USERCOPY|Hardened usercopy|Rejects known-bad copy_to/from_user patterns; reduces heap/data corruption primitives."
        "CONFIG_FORTIFY_SOURCE|Fortify source|Compile-time bounds checks on common libc-style calls."
        "CONFIG_BPF_SYSCALL|BPF syscall|Required for eBPF; combined with unprivileged BPF sysctl it expands kernel attack surface."
        "CONFIG_BPF_UNPRIV_DEFAULT_OFF|Unpriv BPF default off|When=y, new kernels default to restricting unprivileged BPF (align with sysctl)."
        "CONFIG_USER_NS|User namespaces|Enables unprivileged user namespaces when allowed by sysctl — many LPE chains need a namespace sandbox."
        "CONFIG_DEBUG_KERNEL|Debug kernel|Extra debug paths can weaken security or leak symbols; avoid on production kernels."
        "CONFIG_SLAB_FREELIST_RANDOM|Slab freelist randomization|Raises difficulty of heap layout exploitation."
        "CONFIG_DEBUG_WX|W^X debug|Helps detect writable+executable mappings (kernel W^X violations)."
    )

    local row sym label note val line
    local evidence_parts=""
    for row in "${rows[@]}"; do
        IFS='|' read -r sym label note <<< "$row"
        val=$(_kernel_research_config_sym "$sym")
        case "$val" in
            y)  line="${BOLD_GREEN}y${RESET}" ;;
            m)  line="${BOLD_YELLOW}m${RESET}" ;;
            n)  line="${BOLD_RED}n${RESET}" ;;
            *)  line="${GREY}?${RESET}" ;;
        esac
        echo -e "  ${BOLD_WHITE}${sym}${RESET}=${line}  ${GREY}(${label})${RESET}"
        echo -e "     ${GREY}${note}${RESET}"
        evidence_parts+=" ${sym}=${val};"
    done

    add_finding "INFO" "kernel" "-" "Kernel build CONFIG summary (research)" \
        "Compiled-in options relevant to memory corruption reliability, eBPF, user namespaces, and KASLR — use with CVE analysis and exploit preconditions." \
        "zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(RANDOMIZE|STACKPROTECTOR|BPF|USER_NS|HARDENED|FORTIFY|DEBUG_)'" \
        "Sample:${evidence_parts:0:500}" \
        "Prefer vendor-hardened kernels; align CONFIG_USER_NS/BPF with organizational container and desktop policies." \
        "https://www.kernel.org/doc/html/latest/security/index.html" \
        "T1082"
}

# ──────────────────────────────────────────────────────────────
# x86: SMEP / SMAP / NX / PTI narrative (beyond verbose-only lines)
# ──────────────────────────────────────────────────────────────
_enum_x86_mitigations_research() {
    [[ "$SYSTEM_ARCH" =~ x86 ]] || return 0

    print_subsection "x86 hardware mitigations (research)"

    local smep="absent" smap="absent" nx="absent" pti="unknown"
    grep -qi smep /proc/cpuinfo 2>/dev/null && smep="present"
    grep -qi smap /proc/cpuinfo 2>/dev/null && smap="present"
    grep -qi ' nx ' /proc/cpuinfo 2>/dev/null && nx="present"
    if grep -qi pti /proc/cpuinfo 2>/dev/null; then
        pti="indicated in cpuinfo"
    elif [[ -r /sys/devices/system/cpu/vulnerabilities/meltdown ]]; then
        pti="see meltdown sysfs entry"
    fi

    echo -e "  ${GREY}SMEP (supervisor mode exec prevention):${RESET} ${smep}"
    echo -e "  ${GREY}SMAP (supervisor mode access prevention):${RESET} ${smap}"
    echo -e "  ${GREY}NX (No-eXecute / XD):${RESET} ${nx}"
    echo -e "  ${GREY}KPTI / Meltdown class:${RESET} ${pti}"

    local narrative
    narrative="SMEP blocks executing user pages in ring0; SMAP blocks implicit kernel access to user pages — both force kernel exploit chains to bypass or disable these features (e.g. via ROP to native_write_cr4). NX/DEP limits executable data regions. KPTI isolates user/kernel page tables against Meltdown-class leaks."
    echo -e "  ${GREY}${narrative}${RESET}"

    add_finding "INFO" "kernel" "-" "x86 SMEP/SMAP/NX research context" \
        "${narrative}" \
        "grep -E 'smep|smap| nx |pti' /proc/cpuinfo" \
        "arch=${SYSTEM_ARCH}; smep=${smep}; smap=${smap}; nx=${nx}; pti_note=${pti}" \
        "Keep microcode updated; kernel mitigations are complementary to compiler and allocator hardening." \
        "https://kernel.org/doc/html/latest/x86/mds.html" \
        "T1082"
}

# ──────────────────────────────────────────────────────────────
# Map key sysctl outcomes to exploit-precondition notes (informational)
# ──────────────────────────────────────────────────────────────
_enum_sysctl_research_correlation() {
    print_subsection "Sysctl ↔ exploit precondition notes (research)"

    local notes=()
    local v

    v=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)
    [[ "$v" == "0" ]] && notes+=("unprivileged_bpf_disabled=0: eBPF verifier bugs become reachable from user namespace + BPF programs.")

    v=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null)
    [[ "$v" == "1" ]] && notes+=("unprivileged_userns_clone=1: unprivileged user namespaces simplify many public kernel exploit sandboxes.")

    v=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
    [[ "$v" == "0" ]] && notes+=("randomize_va_space=0: userspace ASLR off — userland exploits and some kernel info-leak chains become easier.")

    v=$(sysctl -n vm.unprivileged_userfaultfd 2>/dev/null)
    [[ "$v" == "1" ]] && notes+=("unprivileged_userfaultfd=1: historically involved in UAF race exploitation (see kernel hardening guidance).")

    if [[ ${#notes[@]} -eq 0 ]]; then
        echo -e "  ${GREY}No high-signal weak sysctl combinations flagged for research note (or sysctl unavailable).${RESET}"
        return 0
    fi

    local n ev=""
    for n in "${notes[@]}"; do
        echo -e "  ${BOLD_YELLOW}•${RESET} ${n}"
        ev+=" ${n}"
    done

    add_finding "INFO" "kernel" "-" "Sysctl exploit-precondition notes (research)" \
        "Correlates relaxed sysctl values with common kernel exploit building blocks (namespaces, BPF, ASLR, userfaultfd)." \
        "sysctl -a 2>/dev/null | grep -E 'unprivileged_bpf|unprivileged_userns|randomize_va_space|userfaultfd'" \
        "${ev:0:450}" \
        "Tighten sysctl defaults per CIS/distro hardening guides; test desktop/container workloads after changes." \
        "https://www.kernel.org/doc/Documentation/sysctl/kernel.txt" \
        "T1082"
}

# ──────────────────────────────────────────────────────────────
# Entry: called from run_kernel_enum
# ──────────────────────────────────────────────────────────────
_run_kernel_advanced_research() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "ADVANCED KERNEL RESEARCH"

    _enum_x86_mitigations_research
    _enum_cpu_vulnerabilities_sysfs
    _kernel_research_load_config &>/dev/null
    _enum_kernel_config_research
    _enum_sysctl_research_correlation
}
