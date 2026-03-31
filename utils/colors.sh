#!/usr/bin/env bash
# utils/colors.sh - Terminal color and style definitions

# ──────────────────────────────────────────────────────────────
# Tool metadata (defaults; override via environment if needed)
# ──────────────────────────────────────────────────────────────
: "${TOOL_VERSION:=1.0.0}"
: "${TOOL_AUTHOR_NAME:=Cuma KURT}"
: "${TOOL_AUTHOR_EMAIL:=cumakurt@gmail.com}"
: "${TOOL_AUTHOR_LINKEDIN:=https://www.linkedin.com/in/cuma-kurt-34414917/}"
export TOOL_VERSION TOOL_AUTHOR_NAME TOOL_AUTHOR_EMAIL TOOL_AUTHOR_LINKEDIN

# ──────────────────────────────────────────────────────────────
# Color support detection
# ──────────────────────────────────────────────────────────────
_colors_supported() {
    [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]] && command -v tput &>/dev/null
}

if _colors_supported; then
    # Text Colors
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    MAGENTA=$'\033[0;35m'
    CYAN=$'\033[0;36m'
    WHITE=$'\033[0;37m'
    GREY=$'\033[0;90m'

    # Bold Colors
    BOLD_RED=$'\033[1;31m'
    BOLD_GREEN=$'\033[1;32m'
    BOLD_YELLOW=$'\033[1;33m'
    BOLD_BLUE=$'\033[1;34m'
    BOLD_MAGENTA=$'\033[1;35m'
    BOLD_CYAN=$'\033[1;36m'
    BOLD_WHITE=$'\033[1;37m'

    # Background Colors
    BG_RED=$'\033[41m'
    BG_GREEN=$'\033[42m'
    BG_YELLOW=$'\033[43m'
    BG_BLUE=$'\033[44m'

    # Styles
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    UNDERLINE=$'\033[4m'
    BLINK=$'\033[5m'
    INVERT=$'\033[7m'
    RESET=$'\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN=''
    WHITE='' GREY='' BOLD_RED='' BOLD_GREEN='' BOLD_YELLOW=''
    BOLD_BLUE='' BOLD_MAGENTA='' BOLD_CYAN='' BOLD_WHITE=''
    BG_RED='' BG_GREEN='' BG_YELLOW='' BG_BLUE=''
    BOLD='' DIM='' UNDERLINE='' BLINK='' INVERT='' RESET=''
fi

# ──────────────────────────────────────────────────────────────
# Severity color mapping (CVSS-based)
# ──────────────────────────────────────────────────────────────
color_for_severity() {
    local severity="${1^^}"
    case "$severity" in
        CRITICAL)  echo -n "${BOLD_WHITE}${BG_RED}" ;;
        HIGH)      echo -n "${BOLD_RED}" ;;
        MEDIUM)    echo -n "${BOLD_YELLOW}" ;;
        LOW)       echo -n "${BOLD_CYAN}" ;;
        INFO)      echo -n "${CYAN}" ;;
        *)         echo -n "${WHITE}" ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Print helpers
# ──────────────────────────────────────────────────────────────
print_banner() {
    # π motif: circle (C/d) and digits — LinuxPi brand
    echo -e "      ${BOLD_WHITE}╭──────────────╮${RESET}"
    echo -e "     ${BOLD_WHITE}╱${RESET}       ${BOLD_MAGENTA}π${RESET}        ${BOLD_WHITE}╲${RESET}"
    echo -e "    ${BOLD_WHITE}│${RESET}   ${GREY}3.14159265…${RESET}   ${BOLD_WHITE}│${RESET}  ${GREY}C/d${RESET}"
    echo -e "     ${BOLD_WHITE}╲${RESET}   ${GREY}Linux · π${RESET}    ${BOLD_WHITE}╱${RESET}"
    echo -e "      ${BOLD_WHITE}╰──────────────╯${RESET}"
    echo -e "${BOLD_WHITE}            LinuxPi${RESET}  ${GREY}· Linux Privilege Escalation v${TOOL_VERSION}${RESET}"
    echo -e "${GREY}            github.com/cumakurt/linuxpi${RESET}"
    echo -e "${GREY}  Developed by ${TOOL_AUTHOR_NAME}${RESET}"
    echo -e "${GREY}  ${TOOL_AUTHOR_EMAIL}${RESET}"
    echo -e "${GREY}  ${TOOL_AUTHOR_LINKEDIN}${RESET}"
    echo -e "${GREY}  ⚠  For authorized penetration testing only${RESET}"
    echo -e ""
}

print_section() {
    local title="$1"
    local width=70
    local line
    line=$(printf '─%.0s' $(seq 1 $width))
    echo -e "\n${BOLD_BLUE}╔${line}╗${RESET}"
    printf "${BOLD_BLUE}║${RESET} ${BOLD_WHITE}%-${width}s${RESET}${BOLD_BLUE}║${RESET}\n" " $title"
    echo -e "${BOLD_BLUE}╚${line}╝${RESET}"
}

print_subsection() {
    local title="$1"
    echo -e "\n${BOLD_CYAN}  ▶ ${title}${RESET}"
    echo -e "${GREY}  $(printf '─%.0s' $(seq 1 60))${RESET}"
}

print_finding() {
    local severity="$1"
    local title="$2"
    local detail="$3"
    local color
    color=$(color_for_severity "$severity")

    echo -e "  ${color}[${severity:0:4}]${RESET} ${BOLD_WHITE}${title}${RESET}"
    [[ -n "$detail" ]] && echo -e "         ${GREY}${detail}${RESET}"
}

print_info()    { echo -e "  ${CYAN}[INFO]${RESET} $*"; }
print_good()    { echo -e "  ${BOLD_GREEN}[GOOD]${RESET} $*"; }
print_warn()    { echo -e "  ${BOLD_YELLOW}[WARN]${RESET} $*"; }
print_error()   { echo -e "  ${BOLD_RED}[ERR ]${RESET} $*" >&2; }
print_debug()   { [[ "${DEBUG_MODE:-0}" == "1" ]] && echo -e "  ${GREY}[DBG ]${RESET} $*" >&2; }
print_success() { echo -e "  ${BOLD_GREEN}[+]${RESET} $*"; }
print_fail()    { echo -e "  ${BOLD_RED}[-]${RESET} $*"; }
print_check()   { echo -e "  ${YELLOW}[?]${RESET} $*"; }

print_progress() {
    local current="$1"
    local total="$2"
    local label="${3:-}"
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 5 ))
    local empty=$(( 20 - filled ))
    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    printf "\r  ${CYAN}[%s]${RESET} %3d%% %s" "$bar" "$pct" "$label" >&2
    [[ $current -eq $total ]] && echo "" >&2
}
