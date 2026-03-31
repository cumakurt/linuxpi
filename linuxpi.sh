#!/usr/bin/env bash
# ============================================================
# LinuxPi — Linux Privilege Escalation Framework v1.0
# ============================================================
# Developer: Cuma KURT <cumakurt@gmail.com>
# LinkedIn:  https://www.linkedin.com/in/cuma-kurt-34414917/
# License:   GPL v3
# Repo:      https://github.com/cumakurt/linuxpi
#
# LEGAL WARNING:
# This tool is designed ONLY for authorized penetration testing
# and security assessments. Unauthorized use is strictly
# prohibited and may violate applicable laws.
# ============================================================

set -o pipefail
IFS=$'\n\t'

# ──────────────────────────────────────────────────────────────
# Script root path (symlink safe)
# ──────────────────────────────────────────────────────────────
_get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [[ -L "$source" ]]; do
        local dir="$(cd -P "$(dirname "$source")" && pwd)"
        source="$(readlink "$source")"
        [[ "$source" != /* ]] && source="${dir}/${source}"
    done
    cd -P "$(dirname "$source")" && pwd
}

export SCRIPT_DIR
SCRIPT_DIR="$(_get_script_dir)"

# ──────────────────────────────────────────────────────────────
# Module loader
# ──────────────────────────────────────────────────────────────
_source_module() {
    local mod_file="${SCRIPT_DIR}/${1}"
    if [[ -f "$mod_file" ]]; then
        # shellcheck source=/dev/null
        source "$mod_file"
    else
        echo "[ERROR] Missing module: ${mod_file}" >&2
        exit 1
    fi
}

# Load core utilities first
_source_module "utils/colors.sh"
_source_module "utils/logger.sh"
_source_module "utils/helpers.sh"
_source_module "utils/parser.sh"

# Preserve original args for stealth re-exec
ORIGINAL_ARGS=("$@")
export ORIGINAL_ARGS

# Parse arguments (before anything else)
parse_args "$@"

# Load remaining modules
_source_module "core/detector.sh"
_source_module "core/analyzer.sh"
_source_module "core/reporter.sh"
_source_module "core/exploiter.sh"
_source_module "core/enumerator.sh"
_source_module "modules/kernel/kernel_enum.sh"
_source_module "modules/sudo/sudo_enum.sh"
_source_module "modules/suid/suid_finder.sh"
_source_module "modules/cron/cron_enum.sh"
_source_module "modules/credentials/cred_finder.sh"
_source_module "modules/network/network_enum.sh"
_source_module "modules/containers/container_detect.sh"
_source_module "modules/services/service_enum.sh"
_source_module "modules/security/security_enum.sh"
_source_module "core/main.sh"

# ──────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────
TIMEOUT_PID=""

# Setup timeout
_setup_timeout_handler

# Run
main
