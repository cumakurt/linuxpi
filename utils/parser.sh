#!/usr/bin/env bash
# utils/parser.sh - Argument parsing and configuration management

# ──────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────
parse_args() {
    # Defaults (exported runtime config)
    : "${VERBOSE_MODE:=0}"
    : "${QUIET_MODE:=0}"
    : "${DEBUG_MODE:=0}"
    : "${STEALTH_MODE:=0}"
    : "${OUTPUT_FORMAT:=text}"
    : "${OUTPUT_FILE:=}"
    : "${ACTIVE_MODULE:=all}"
    : "${EXPLOIT_MODE:=0}"
    : "${AUTO_RUN_SHELL:=0}"
    : "${RISK_LEVEL:=low}"
    : "${CONTAINER_MODE:=0}"
    : "${CLOUD_MODE:=0}"
    : "${SUGGEST_EXPLOITS:=1}"
    : "${SCAN_TIMEOUT:=300}"
    : "${LOG_FILE:=/tmp/.linuxpi_$(date +%s).log}"
    : "${REPORT_FULL_SECRETS:=0}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE_MODE=1
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=1
                VERBOSE_MODE=0
                shift
                ;;
            --debug)
                DEBUG_MODE=1
                VERBOSE_MODE=1
                shift
                ;;
            --stealth)
                STEALTH_MODE=1
                QUIET_MODE=1
                shift
                ;;
            -f|--format)
                [[ -z "${2:-}" ]] && { usage; exit 1; }
                case "${2,,}" in
                    text|json|html|xml|markdown) OUTPUT_FORMAT="${2,,}" ;;
                    *) echo "Invalid format: $2. Valid values: text|json|html|xml|markdown" >&2; exit 1 ;;
                esac
                shift 2
                ;;
            -o|--output)
                [[ -z "${2:-}" ]] && { usage; exit 1; }
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -m|--module)
                [[ -z "${2:-}" ]] && { usage; exit 1; }
                ACTIVE_MODULE="${2,,}"
                shift 2
                ;;
            --exploit|--auto-exploit)
                EXPLOIT_MODE=1
                shift
                ;;
            --run)
                # Unattended shell-classified exploit attempts after scan (implies exploit mode).
                AUTO_RUN_SHELL=1
                EXPLOIT_MODE=1
                shift
                ;;
            --risk-level)
                [[ -z "${2:-}" ]] && { usage; exit 1; }
                case "${2,,}" in
                    low|medium|high|critical) RISK_LEVEL="${2,,}" ;;
                    *) echo "Invalid risk level: $2. Valid values: low|medium|high|critical" >&2; exit 1 ;;
                esac
                shift 2
                ;;
            --container-mode)
                CONTAINER_MODE=1
                shift
                ;;
            --cloud)
                CLOUD_MODE=1
                [[ -n "${2:-}" && ! "$2" =~ ^- ]] && { CLOUD_PROVIDER="${2,,}"; shift; }
                shift
                ;;
            --suggest-exploits)
                SUGGEST_EXPLOITS=1
                shift
                ;;
            --no-suggest)
                SUGGEST_EXPLOITS=0
                shift
                ;;
            --report-full-secrets)
                REPORT_FULL_SECRETS=1
                shift
                ;;
            --timeout)
                [[ -z "${2:-}" || ! "${2}" =~ ^[0-9]+$ ]] && { echo "Invalid timeout value: must be a positive integer" >&2; exit 1; }
                SCAN_TIMEOUT="$2"
                shift 2
                ;;
            --log-file)
                [[ -z "${2:-}" ]] && { usage; exit 1; }
                LOG_FILE="$2"
                shift 2
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            --full)
                ACTIVE_MODULE="all"
                SUGGEST_EXPLOITS=1
                shift
                ;;
            --minimal)
                ACTIVE_MODULE="kernel,sudo,suid"
                SUGGEST_EXPLOITS=0
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --version)
                echo "linuxpi v${TOOL_VERSION:-1.0.0}"
                echo "Developed by ${TOOL_AUTHOR_NAME} <${TOOL_AUTHOR_EMAIL}>"
                echo "${TOOL_AUTHOR_LINKEDIN}"
                exit 0
                ;;
            *)
                echo "Unknown option: $1. Use --help for usage information." >&2
                exit 1
                ;;
        esac
    done

    # Structured reports (json|html|xml|markdown): scan UI goes to stderr during the run;
    # the report alone is written to stdout (or -o file) after enumeration. Use -q for minimal stderr.

    # --run needs shell exploits in the risk budget (high+).
    if [[ "${AUTO_RUN_SHELL:-0}" == "1" ]]; then
        case "${RISK_LEVEL}" in
            low|medium) RISK_LEVEL=high ;;
        esac
    fi

    # Export configuration to environment variables
    export VERBOSE_MODE QUIET_MODE DEBUG_MODE STEALTH_MODE
    export OUTPUT_FORMAT OUTPUT_FILE ACTIVE_MODULE
    export EXPLOIT_MODE AUTO_RUN_SHELL RISK_LEVEL CONTAINER_MODE CLOUD_MODE
    export SUGGEST_EXPLOITS SCAN_TIMEOUT LOG_FILE REPORT_FULL_SECRETS
    export CLOUD_PROVIDER="${CLOUD_PROVIDER:-}"

    [[ "${NO_COLOR:-0}" == "1" ]] && unset RED GREEN YELLOW BLUE MAGENTA CYAN WHITE GREY \
        BOLD_RED BOLD_GREEN BOLD_YELLOW BOLD_BLUE BOLD_MAGENTA BOLD_CYAN BOLD_WHITE \
        BG_RED BG_GREEN BG_YELLOW BG_BLUE BOLD DIM UNDERLINE BLINK INVERT RESET

    return 0
}

# ──────────────────────────────────────────────────────────────
# Usage guide
# ──────────────────────────────────────────────────────────────
usage() {
    cat << EOF
${BOLD_WHITE}USAGE:${RESET}
  ./linuxpi.sh [OPTIONS]

${BOLD_WHITE}BASIC OPTIONS:${RESET}
  -v, --verbose           Verbose output
  -q, --quiet             Quiet mode (findings only)
      --debug             Debug mode (developer output)
      --stealth           Stealth mode (minimal footprint)
  -h, --help              Show this help message
      --version           Show version

${BOLD_WHITE}MODULE SELECTION:${RESET}
  -m, --module MODULE     Run specific module(s):
                          kernel|sudo|suid|capabilities|cron|
                          services|containers|credentials|network|
                          security|filesystem|all
      --full              All modules + exploit suggestions
      --minimal           Core modules only (fast)

${BOLD_WHITE}OUTPUT:${RESET}
  -f, --format FORMAT     Output format: text|json|html|xml|markdown
  -o, --output FILE       Save output to file
      --no-color          Disable colored output
  (json|html|xml|markdown: scan progress on stderr; final report on stdout or -o. Use -q to reduce stderr noise.)

${BOLD_RED}UNSAFE — CREDENTIALS IN REPORTS:${RESET}
      --report-full-secrets  Include plaintext secrets in the credentials_* report fields
                          (passwords, hashes, tokens). ${BOLD_RED}Extreme leak risk.${RESET} Default is redacted only.

${BOLD_WHITE}EXPLOITATION:${RESET}
      --suggest-exploits  Show exploit suggestions (default: on)
      --no-suggest        Disable exploit suggestions
      --exploit           Interactive exploit menu after scan (DANGEROUS)
      --run               After scan: auto-try shell-classified exploits sequentially (no prompts;
                          implies --exploit, raises risk to high if lower). DANGEROUS.
      --risk-level LEVEL  Max risk level: low|medium|high|critical

${BOLD_WHITE}ADVANCED:${RESET}
      --container-mode    Container escape focused scan
      --cloud [PROVIDER]  Cloud platform scan (aws|azure|gcp)
      --timeout SECONDS   Scan timeout in seconds (default: 300)
      --log-file FILE     Log file path

${BOLD_WHITE}EXAMPLES:${RESET}
  ./linuxpi.sh                          # Standard scan
  ./linuxpi.sh -v --format json         # Verbose + JSON output
  ./linuxpi.sh -m kernel --suggest-exploits
  ./linuxpi.sh --full -o /tmp/report.html --format html
  ./linuxpi.sh --stealth -m sudo,suid
  curl -sL https://server/linuxpi.sh | bash    # Memory-only execution

${BOLD_WHITE}DEVELOPER:${RESET}
  ${TOOL_AUTHOR_NAME} <${TOOL_AUTHOR_EMAIL}>
  ${TOOL_AUTHOR_LINKEDIN}
  https://github.com/cumakurt/linuxpi

${BOLD_RED}⚠  LEGAL WARNING:${RESET}
  This tool is designed ONLY for authorized penetration testing.
  Unauthorized use is strictly prohibited and may violate applicable laws.

EOF
}

# ──────────────────────────────────────────────────────────────
# Module activation check
# ──────────────────────────────────────────────────────────────
is_module_active() {
    local module="$1"
    [[ "$ACTIVE_MODULE" == "all" ]] && return 0
    echo "$ACTIVE_MODULE" | tr ',' '\n' | grep -qx "$module"
}
