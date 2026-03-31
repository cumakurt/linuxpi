#!/usr/bin/env bash
# modules/network/network_enum.sh - Network information and configuration analysis

run_network_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "NETWORK ENUMERATION"

    local start_ms
    start_ms=$(timestamp_ms)

    _enum_interfaces
    _enum_open_ports
    _enum_routing
    _enum_arp_cache
    _check_firewall_rules
    _check_network_services
    _enum_dns_config

    log_timing "network_enum" "$(elapsed_since "$start_ms")"
}

_enum_interfaces() {
    print_subsection "Network Interfaces"

    if cmd_exists ip; then
        ip addr show 2>/dev/null | while IFS= read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    elif cmd_exists ifconfig; then
        ifconfig -a 2>/dev/null | while IFS= read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    fi

    # VPN tespiti
    if ip link show 2>/dev/null | grep -qiE "tun|tap|wg|vpn"; then
        print_info "VPN/Tunnel interface detected"
        local _vpn_if
        _vpn_if=$(ip link show 2>/dev/null | grep -iE "tun|tap|wg|vpn" | head -3 | tr '\n' '; ')
        add_finding "INFO" "network" "-" "VPN/Tunnel interface detected" \
            "Tunnel interface found - may indicate VPN access or network pivoting opportunity" "" \
            "ip_link_hints=${_vpn_if:-detected}" \
            "Document expected VPN interfaces; restrict lateral movement with host firewall and split tunnel policies; monitor routes and DNS when VPN is required." \
            "https://attack.mitre.org/techniques/T1016/" \
            "T1016"
    fi
}

_enum_open_ports() {
    print_subsection "Listening Services"

    local ports_output=""

    if cmd_exists ss; then
        ports_output=$(ss -tlnpu 2>/dev/null)
    elif cmd_exists netstat; then
        ports_output=$(netstat -tlnpu 2>/dev/null)
    fi

    [[ -z "$ports_output" ]] && { print_info "Cannot enumerate ports"; return; }

    echo "$ports_output" | head -30 | while IFS= read -r line; do
        echo -e "  ${GREY}${line}${RESET}"
    done

    # Localhost only services (internal, potansiyel pivot)
    local local_services
    local_services=$(echo "$ports_output" | grep -E "127\.|::1" | grep -oE ":[0-9]+" | sort -u)

    if [[ -n "$local_services" ]]; then
        echo -e "\n  ${CYAN}[INFO]${RESET} Localhost-only services:"
        echo "$local_services" | while read -r port; do
            echo -e "  ${GREY}  ${port}${RESET}"
        done
        add_finding "INFO" "network" "-" "Localhost-only services detected" \
            "Services bound to localhost only - may be accessible after privilege escalation" \
            "curl http://127.0.0.1:PORT  OR  ssh -L PORT:127.0.0.1:PORT user@host" \
            "localhost_ports=$(echo "$local_services" | tr '\n' ',' | head -c 200)" \
            "Bind sensitive admin APIs to Unix sockets with strict permissions or authenticated reverse proxies; require auth on localhost services; use network namespaces for isolation." \
            "https://attack.mitre.org/techniques/T1046/" \
            "T1046"
    fi
}

_enum_routing() {
    print_subsection "Routing Table"

    if cmd_exists ip; then
        ip route show 2>/dev/null | head -10 | while IFS= read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    elif cmd_exists route; then
        route -n 2>/dev/null | head -15 | while IFS= read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
    fi
}

_enum_arp_cache() {
    print_subsection "ARP Cache (Neighbors)"

    local arp_output=""
    if cmd_exists ip; then
        arp_output=$(ip neigh show 2>/dev/null)
    elif cmd_exists arp; then
        arp_output=$(arp -n 2>/dev/null)
    fi

    [[ -z "$arp_output" ]] && return

    echo "$arp_output" | head -20 | while IFS= read -r line; do
        echo -e "  ${GREY}${line}${RESET}"
    done

    local host_count
    host_count=$(echo "$arp_output" | wc -l)
    echo -e "  ${GREY}Total discovered hosts: ${host_count}${RESET}"
}

_check_firewall_rules() {
    print_subsection "Firewall Rules"

    # iptables rules
    if cmd_exists iptables; then
        local ipt_rules
        ipt_rules=$(safe_run 5 iptables -L -n 2>/dev/null)
        if [[ -n "$ipt_rules" ]]; then
            echo -e "  ${CYAN}[INFO]${RESET} iptables rules:"
            echo "$ipt_rules" | head -15 | while IFS= read -r line; do
                echo -e "  ${GREY}${line}${RESET}"
            done
        fi
    fi

    # nftables rules
    if cmd_exists nft; then
        local nft_rules
        nft_rules=$(safe_run 5 nft list ruleset 2>/dev/null)
        if [[ -n "$nft_rules" ]]; then
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${CYAN}[INFO]${RESET} nftables rules present"
        fi
    fi

    # UFW
    if cmd_exists ufw; then
        local ufw_status
        ufw_status=$(safe_run 3 ufw status 2>/dev/null)
        echo -e "  ${CYAN}[INFO]${RESET} UFW: $(echo "$ufw_status" | head -1)"
    fi
}

_check_network_services() {
    print_subsection "Network Service Vulnerabilities"

    # NFS no_root_squash check
    if [[ -r /etc/exports ]]; then
        local nfs_noroot
        nfs_noroot=$(grep -i "no_root_squash" /etc/exports 2>/dev/null)
        if [[ -n "$nfs_noroot" ]]; then
            add_finding "HIGH" "network" "-" "NFS no_root_squash misconfiguration" \
                "NFS exports with no_root_squash allow root access from client" \
                "showmount -e TARGET && mount -t nfs TARGET:/export /mnt && cp /bin/bash /mnt && chmod +s /mnt/bash" \
                "file=/etc/exports perms=$(file_perms /etc/exports 2>/dev/null) owner=$(file_owner /etc/exports 2>/dev/null) matching_lines=$(echo "$nfs_noroot" | head -c 300)" \
                "Remove no_root_squash; use root_squash and all_squash with anonuid/anongid; export only required subtrees; enforce Kerberos sec=krb5p where possible; firewall port 2049 to trusted clients." \
                "https://attack.mitre.org/techniques/T1080/" \
                "T1080"
            echo -e "  ${BOLD_RED}[HIGH]${RESET} NFS no_root_squash:"
            echo "$nfs_noroot" | while IFS= read -r line; do
                echo -e "  ${GREY}${line}${RESET}"
            done
        fi
    fi

    # Writable NFS mounts check
    while IFS= read -r mount_line; do
        if echo "$mount_line" | grep -qi "nfs"; then
            local mount_point
            mount_point=$(echo "$mount_line" | awk '{print $2}')
            if [[ -d "$mount_point" ]] && is_writable "$mount_point"; then
                add_finding "HIGH" "network" "-" "Writable NFS mount: ${mount_point}" \
                    "NFS mounted directory is writable" \
                    "cp /bin/bash ${mount_point}/ && chmod +s ${mount_point}/bash && ${mount_point}/bash -p" \
                    "mount_point=${mount_point} mount_line=$(echo "$mount_line" | head -c 200) dir_perms=$(file_perms "$mount_point" 2>/dev/null) dir_owner=$(file_owner "$mount_point" 2>/dev/null)" \
                    "Tighten export options (ro, root_squash); use Kerberos; avoid world-writable exports; remount with least privilege and monitor for SUID files on NFS." \
                    "https://attack.mitre.org/techniques/T1080/" \
                    "T1080"
            fi
        fi
    done < /proc/mounts 2>/dev/null

    # rpcbind / portmap check
    if ss -tlnp 2>/dev/null | grep -q ":111 " || netstat -tlnp 2>/dev/null | grep -q ":111 "; then
        print_info "rpcbind (port 111) is running"
    fi
}

_enum_dns_config() {
    print_subsection "DNS Configuration"

    if [[ -r /etc/resolv.conf ]]; then
        echo -e "  ${GREY}/etc/resolv.conf:${RESET}"
        grep -v "^#" /etc/resolv.conf 2>/dev/null | while IFS= read -r line; do
            echo -e "  ${GREY}  ${line}${RESET}"
        done
    fi

    if [[ -r /etc/hosts ]]; then
        local hosts_count
        hosts_count=$(grep -v "^#\|^$\|^127\.\|^::1" /etc/hosts 2>/dev/null | wc -l)
        [[ $hosts_count -gt 0 ]] && print_info "Interesting /etc/hosts entries: ${hosts_count}"

        # Writable /etc/hosts - DNS poisoning
        if is_writable /etc/hosts; then
            add_finding "MEDIUM" "network" "-" "Writable /etc/hosts" \
                "/etc/hosts is writable - local DNS poisoning possible" \
                "echo '127.0.0.1 target-domain.com' >> /etc/hosts" \
                "file=/etc/hosts perms=$(file_perms /etc/hosts 2>/dev/null) owner=$(file_owner /etc/hosts 2>/dev/null)" \
                "chmod 644, chown root:root; use immutable flag after validation where supported; prefer systemd-resolved or nsswitch policies that resist local tampering; deploy integrity monitoring." \
                "https://attack.mitre.org/techniques/T1557/" \
                "T1557"
        fi
    fi
}
