#!/usr/bin/env bash
# modules/credentials/cred_finder.sh - Credential harvesting engine

run_cred_enum() {
    [[ "${QUIET_MODE:-0}" == "0" ]] && print_section "CREDENTIAL HARVESTING"
    if [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]] && [[ "${QUIET_MODE:-0}" == "0" ]]; then
        echo -e "  ${BOLD_RED}[!] --report-full-secrets: plaintext credentials will be embedded in report output.${RESET}" >&2
    fi

    local start_ms
    start_ms=$(timestamp_ms)

    _check_passwd_shadow
    _check_ssh_keys
    _check_bash_history
    _check_config_files
    _check_env_variables
    _check_database_creds
    _check_cloud_creds
    _check_browser_creds
    _check_interesting_files
    _check_devops_creds
    _check_git_credentials

    log_timing "cred_enum" "$(elapsed_since "$start_ms")"
}

# ──────────────────────────────────────────────────────────────
# /etc/passwd and /etc/shadow analysis
# ──────────────────────────────────────────────────────────────
_check_passwd_shadow() {
    print_subsection "Password Files"

    # /etc/shadow readable check
    if is_readable /etc/shadow; then
        local _shadow_perms _shadow_evidence
        _shadow_perms=$(file_perms /etc/shadow 2>/dev/null)

        echo -e "  ${BOLD_RED}[CRIT]${RESET} /etc/shadow READABLE - password hashes:"
        local hash_count=0
        local _hash_users=""
        while IFS=: read -r user hash rest; do
            [[ -z "$hash" ]] && continue
            [[ "$hash" =~ ^\*|^! ]] && continue
            echo -e "  ${GREY}${user}:${hash:0:30}...${RESET}"
            _hash_users="${_hash_users:+${_hash_users}, }${user}"
            hash_count=$(( hash_count + 1 ))
        done < /etc/shadow 2>/dev/null
        echo -e "  ${BOLD_YELLOW}Total crackable hashes: ${hash_count}${RESET}"

        _shadow_evidence="File: /etc/shadow (permissions: ${_shadow_perms}) ; Crackable hashes: ${hash_count} ; Users with hashes: ${_hash_users}"
        add_finding "CRITICAL" "credentials" "-" "/etc/shadow is readable" \
            "/etc/shadow is readable by current user - password hashes exposed" \
            "cat /etc/shadow | cut -d: -f1,2 | grep -v '*\\|!' | hashcat -m 1800" \
            "$_shadow_evidence" \
            "Set /etc/shadow permissions to 640 owned by root:shadow. Rotate all exposed passwords immediately." \
            "https://attack.mitre.org/techniques/T1003/008/" \
            "T1003.008"
        local _su_prev=0
        while IFS=: read -r user hash rest; do
            [[ -z "$hash" ]] && continue
            [[ "$hash" =~ ^\*|^! ]] && continue
            [[ $_su_prev -ge 16 ]] && break
            if [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]]; then
                append_credential_preview "/etc/shadow is readable" "${user}:${hash}"
            else
                append_credential_preview "/etc/shadow is readable" "${user}: hash prefix ${hash:0:12}… (length ${#hash})"
            fi
            _su_prev=$(( _su_prev + 1 ))
        done < /etc/shadow 2>/dev/null
    fi

    # /etc/passwd - hashed passwords (old systems)
    local passwd_hashes
    passwd_hashes=$(awk -F: '$2 != "x" && $2 != "" && $2 != "*" && $2 != "!" {print $1":"$2}' /etc/passwd 2>/dev/null)
    if [[ -n "$passwd_hashes" ]]; then
        local _ph_count
        _ph_count=$(echo "$passwd_hashes" | wc -l)
        add_finding "HIGH" "credentials" "-" "Password hashes in /etc/passwd" \
            "Old-style password hashes found in /etc/passwd" \
            "echo '${passwd_hashes}' | hashcat -m 500" \
            "File: /etc/passwd ; ${_ph_count} accounts with inline password hashes ; Accounts: $(echo "$passwd_hashes" | cut -d: -f1 | tr '\n' ', ')" \
            "Migrate hashes to /etc/shadow using pwconv. Set /etc/passwd second field to 'x'." \
            "https://attack.mitre.org/techniques/T1003/008/" \
            "T1003.008"
        echo -e "  ${BOLD_RED}[HIGH]${RESET} Hashes in /etc/passwd:"
        echo "$passwd_hashes" | head -5 | while read -r line; do
            echo -e "  ${GREY}${line}${RESET}"
        done
        local _ph_line _ph_n=0
        while IFS= read -r _ph_line && [[ $_ph_n -lt 5 ]]; do
            append_credential_preview "Password hashes in /etc/passwd" "$_ph_line"
            _ph_n=$(( _ph_n + 1 ))
        done <<< "$passwd_hashes"
    fi

    # /etc/passwd writable
    if is_writable /etc/passwd; then
        local _pw_perms
        _pw_perms=$(file_perms /etc/passwd 2>/dev/null)
        add_finding "CRITICAL" "credentials" "-" "Writable /etc/passwd" \
            "/etc/passwd is writable - can add root user without password" \
            "echo 'hacker::\$(openssl passwd -1 hacked):0:0:root:/root:/bin/bash' >> /etc/passwd" \
            "File: /etc/passwd (permissions: ${_pw_perms}, owner: $(file_owner /etc/passwd 2>/dev/null))" \
            "Set /etc/passwd permissions to 644 owned by root:root." \
            "https://attack.mitre.org/techniques/T1098/" \
            "T1098"
    fi

    # /etc/group writable
    if is_writable /etc/group; then
        local _grp_perms
        _grp_perms=$(file_perms /etc/group 2>/dev/null)
        add_finding "HIGH" "credentials" "-" "Writable /etc/group" \
            "/etc/group is writable - can add user to privileged groups" \
            "sed -i 's/^sudo.*/&,$(id -un)/' /etc/group" \
            "File: /etc/group (permissions: ${_grp_perms}, owner: $(file_owner /etc/group 2>/dev/null))" \
            "Set /etc/group permissions to 644 owned by root:root." \
            "https://attack.mitre.org/techniques/T1098/" \
            "T1098"
    fi
}

# ──────────────────────────────────────────────────────────────
# SSH key check
# ──────────────────────────────────────────────────────────────
_check_ssh_keys() {
    print_subsection "SSH Keys"

    local ssh_dirs=()
    local home_base="${SYSTEM_HOME:-/home}"

    # Scan all home directories
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -ge 1000 || "$user" == "root" ]] || continue
        [[ -d "${home}/.ssh" ]] && ssh_dirs+=("${home}/.ssh:${user}")
    done < /etc/passwd 2>/dev/null

    for ssh_entry in "${ssh_dirs[@]}"; do
        IFS=: read -r ssh_dir ssh_user <<< "$ssh_entry"

        # Private keys
        while IFS= read -r key_file; do
            if is_readable "$key_file"; then
                local key_type
                key_type=$(head -1 "$key_file" 2>/dev/null)

                if echo "$key_type" | grep -qi "PRIVATE KEY"; then
                    local is_encrypted=0
                    echo "$key_type" | grep -qi "ENCRYPTED" && is_encrypted=1

                    local severity="CRITICAL"
                    local note="unencrypted"
                    [[ $is_encrypted -eq 1 ]] && severity="HIGH" && note="encrypted"

                    local _key_perms _key_sz
                    _key_perms=$(file_perms "$key_file" 2>/dev/null)
                    _key_sz=$(wc -c < "$key_file" 2>/dev/null)
                    add_finding "$severity" "credentials" "-" "SSH private key (${note}): ${key_file}" \
                        "SSH private key found for user ${ssh_user} - ${note}" \
                        "ssh -i ${key_file} ${ssh_user}@target" \
                        "File: ${key_file} (permissions: ${_key_perms}, size: ${_key_sz}B) ; Owner user: ${ssh_user} ; Key type: ${key_type:0:40} ; Encrypted: $([ $is_encrypted -eq 1 ] && echo yes || echo no)" \
                        "Remove unused SSH keys. Encrypt all private keys with passphrases. Restrict file permissions to 600." \
                        "https://attack.mitre.org/techniques/T1552/004/" \
                        "T1552.004"
                    append_credential_preview "SSH private key (${note}): ${key_file}" "header: ${key_type:0:72}"

                    echo -e "  $(color_for_severity "$severity")[${severity:0:4}]${RESET} SSH key: ${key_file} ${GREY}(${note})${RESET}"
                fi
            fi
        done < <(find "$ssh_dir" -name "id_*" -o -name "*.pem" -o -name "*.key" 2>/dev/null)

        # authorized_keys - who can connect to this user
        if [[ -r "${ssh_dir}/authorized_keys" ]] && is_writable "${ssh_dir}/authorized_keys"; then
            local _ak_perms _ak_keys
            _ak_perms=$(file_perms "${ssh_dir}/authorized_keys" 2>/dev/null)
            _ak_keys=$(wc -l < "${ssh_dir}/authorized_keys" 2>/dev/null)
            add_finding "CRITICAL" "credentials" "-" "Writable authorized_keys: ${ssh_dir}" \
                "Can add own SSH public key to ${ssh_user}'s authorized_keys for persistent access" \
                "echo \"\$(cat ~/.ssh/id_rsa.pub)\" >> ${ssh_dir}/authorized_keys" \
                "File: ${ssh_dir}/authorized_keys (permissions: ${_ak_perms}) ; Target user: ${ssh_user} ; Existing keys: ${_ak_keys}" \
                "Set authorized_keys to 600 owned by the respective user. Remove unnecessary public keys." \
                "https://attack.mitre.org/techniques/T1098/004/" \
                "T1098.004"
        fi

        # known_hosts - useful for lateral movement
        if [[ -r "${ssh_dir}/known_hosts" ]]; then
            local hosts_count
            hosts_count=$(wc -l < "${ssh_dir}/known_hosts" 2>/dev/null)
            [[ "${VERBOSE_MODE:-0}" == "1" ]] && echo -e "  ${CYAN}[INFO]${RESET} known_hosts (${ssh_user}): ${hosts_count} hosts"
        fi
    done

    # SSH agent socket
    if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
        if is_readable "$SSH_AUTH_SOCK"; then
            add_finding "HIGH" "credentials" "-" "SSH agent socket accessible" \
                "SSH agent socket ${SSH_AUTH_SOCK} is accessible - agent hijacking possible" \
                "SSH_AUTH_SOCK=${SSH_AUTH_SOCK} ssh-add -l && ssh-add" \
                "Socket: ${SSH_AUTH_SOCK} ; Socket permissions: $(file_perms "$SSH_AUTH_SOCK" 2>/dev/null)" \
                "Restrict SSH_AUTH_SOCK permissions. Use ssh-agent with -t to set key lifetime." \
                "https://attack.mitre.org/techniques/T1563/001/" \
                "T1563.001"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Shell history analysis
# ──────────────────────────────────────────────────────────────
_check_bash_history() {
    print_subsection "Shell History"

    local history_files=(
        "${HOME}/.bash_history"
        "${HOME}/.zsh_history"
        "${HOME}/.sh_history"
        "${HOME}/.history"
        "${HOME}/.fish/fish_history"
        "/root/.bash_history"
        "/root/.zsh_history"
    )

    local credential_patterns=(
        "password" "passwd" "pass=" "pwd=" "secret"
        "token" "api_key" "apikey" "access_key"
        "mysql -u" "psql -U" "mongo.*-p"
        "ssh.*-i" "scp.*-i"
        "curl.*-u" "wget.*--http-user"
        "aws.*--secret" "gcloud.*--service-account"
        "kubectl.*--token"
    )

    for hist_file in "${history_files[@]}"; do
        [[ -r "$hist_file" ]] || continue

        echo -e "  ${CYAN}[INFO]${RESET} Reading: ${hist_file}"

        local found_creds=0
        local hist_preview_cap=0
        local _hist_title=""
        for pattern in "${credential_patterns[@]}"; do
            local matches
            matches=$(grep -iE "$pattern" "$hist_file" 2>/dev/null | grep -v "^#" | head -3)
            if [[ -n "$matches" ]]; then
                if [[ $found_creds -eq 0 ]]; then
                    local _hist_lines _hist_perms
                    _hist_lines=$(wc -l < "$hist_file" 2>/dev/null)
                    _hist_perms=$(file_perms "$hist_file" 2>/dev/null)
                    _hist_title="Credentials in shell history: ${hist_file}"
                    add_finding "HIGH" "credentials" "-" "$_hist_title" \
                        "Shell history contains potentially sensitive commands" \
                        "cat ${hist_file} | grep -iE 'password|passwd|secret|token|key'" \
                        "File: ${hist_file} (permissions: ${_hist_perms}, lines: ${_hist_lines}) ; Matched pattern: ${pattern}" \
                        "Clear history: history -c && rm -f ${hist_file}. Set HISTCONTROL=ignoreboth. Configure HISTIGNORE for sensitive commands." \
                        "https://attack.mitre.org/techniques/T1552/003/" \
                        "T1552.003"
                fi
                echo -e "  ${BOLD_YELLOW}[CRED]${RESET} Pattern '${pattern}' found:"
                while IFS= read -r line && [[ $hist_preview_cap -lt 8 ]]; do
                    echo -e "         ${GREY}${line}${RESET}"
                    [[ -n "$_hist_title" ]] && append_credential_preview "$_hist_title" "$line"
                    hist_preview_cap=$(( hist_preview_cap + 1 ))
                done < <(echo "$matches" | head -2)
                found_creds=1
            fi
        done
    done
}

# ──────────────────────────────────────────────────────────────
# Config file credential scan
# ──────────────────────────────────────────────────────────────
_check_config_files() {
    print_subsection "Config File Credentials"

    local interesting_dirs=(
        "/etc" "/opt" "/var/www" "/var/lib"
        "${HOME}" "/root"
        "/srv" "/home"
    )

    local interesting_extensions=("conf" "config" "cfg" "ini" "env" "xml" "yaml" "yml" "json" "properties")
    local credential_patterns=(
        "password\s*=" "passwd\s*=" "pass\s*="
        "secret\s*=" "token\s*=" "api_key\s*="
        "apikey\s*=" "access_key\s*=" "secret_key\s*="
        "db_pass" "database_password" "DB_PASSWORD"
        "MYSQL_ROOT_PASSWORD" "POSTGRES_PASSWORD"
        "AWS_SECRET_ACCESS_KEY" "AWS_ACCESS_KEY_ID"
        "AZURE_CLIENT_SECRET" "GCP_SERVICE_ACCOUNT_KEY"
    )

    local found_files=0

    for search_dir in "${interesting_dirs[@]}"; do
        [[ -d "$search_dir" ]] || continue

        while IFS= read -r conf_file; do
            [[ -r "$conf_file" ]] || continue

            local found_in_file=0
            local cf_preview_cap=0
            local _cf_title=""
            for pattern in "${credential_patterns[@]}"; do
                local matches
                matches=$(grep -niE "$pattern" "$conf_file" 2>/dev/null | head -3)
                if [[ -n "$matches" ]]; then
                    if [[ $found_in_file -eq 0 ]]; then
                        echo -e "  ${BOLD_YELLOW}[CRED]${RESET} Credentials in: ${conf_file}"
                        local _cf_perms _cf_owner
                        _cf_perms=$(file_perms "$conf_file" 2>/dev/null)
                        _cf_owner=$(file_owner "$conf_file" 2>/dev/null)
                        _cf_title="Credentials found in: ${conf_file}"
                        add_finding "HIGH" "credentials" "-" "$_cf_title" \
                            "Config file contains credential-related strings" \
                            "grep -niE 'password|passwd|secret|token|key' ${conf_file}" \
                            "File: ${conf_file} (permissions: ${_cf_perms}, owner: ${_cf_owner}) ; Matched pattern: ${pattern}" \
                            "Remove hardcoded credentials. Use environment variables or a secrets manager (Vault, AWS Secrets Manager)." \
                            "https://attack.mitre.org/techniques/T1552/001/" \
                            "T1552.001"
                        found_files=$(( found_files + 1 ))
                    fi
                    while IFS= read -r line && [[ $cf_preview_cap -lt 6 ]]; do
                        echo -e "         ${GREY}${line}${RESET}"
                        [[ -n "$_cf_title" ]] && append_credential_preview "$_cf_title" "$line"
                        cf_preview_cap=$(( cf_preview_cap + 1 ))
                    done < <(echo "$matches" | head -2)
                    found_in_file=1
                fi
            done
        done < <(safe_run 30 find "$search_dir" -maxdepth 4 -type f \
            \( -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" \
               -o -name "*.env" -o -name ".env" -o -name "*.properties" \) \
            -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null | head -100)
    done

    [[ $found_files -eq 0 ]] && [[ "${VERBOSE_MODE:-0}" == "1" ]] && print_good "No credentials found in config files"
}

# ──────────────────────────────────────────────────────────────
# Environment variables
# ──────────────────────────────────────────────────────────────
_check_env_variables() {
    print_subsection "Environment Variables"

    local sensitive_vars=(
        "PASSWORD" "PASSWD" "SECRET" "TOKEN"
        "API_KEY" "APIKEY" "ACCESS_KEY" "SECRET_KEY"
        "AWS_SECRET" "AWS_ACCESS" "AZURE" "GCP"
        "DATABASE_URL" "DB_PASSWORD" "MYSQL_PASSWORD"
        "REDIS_PASSWORD" "RABBITMQ_PASSWORD"
        "GITHUB_TOKEN" "GITLAB_TOKEN" "SLACK_TOKEN"
        "PRIVATE_KEY" "RSA_PRIVATE" "SSL_KEY"
    )

    local found=0
    local _env_vars_found=""
    for var in "${sensitive_vars[@]}"; do
        local value
        value=$(env 2>/dev/null | grep -i "^${var}=" | head -1)
        if [[ -n "$value" ]]; then
            local _var_name="${value%%=*}"
            _env_vars_found="${_env_vars_found:+${_env_vars_found}, }${_var_name}"
            if [[ $found -eq 0 ]]; then
                found=1
            fi
            local masked="${value:0:30}..."
            echo -e "  ${BOLD_YELLOW}[CRED]${RESET} ${masked}"
        fi
    done
    if [[ $found -eq 1 ]]; then
        local _env_title="Sensitive environment variables found"
        add_finding "HIGH" "credentials" "-" "$_env_title" \
            "Environment contains credentials or secrets" \
            "env | grep -iE 'password|secret|token|key|aws|azure|gcp'" \
            "Variables detected: ${_env_vars_found} ; Process: $$ (${0##*/})" \
            "Move secrets to a dedicated secrets manager. Avoid exporting credentials in .bashrc/.profile. Use tools like direnv with encrypted .envrc." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
        for var in "${sensitive_vars[@]}"; do
            local value
            value=$(env 2>/dev/null | grep -i "^${var}=" | head -1)
            [[ -n "$value" ]] && append_credential_preview "$_env_title" "$value"
        done
    fi

    # /proc/1/environ (if readable - kernel info leak)
    if is_readable /proc/1/environ; then
        add_finding "HIGH" "credentials" "-" "/proc/1/environ readable" \
            "Init process environment is readable - may contain secrets" \
            "cat /proc/1/environ | tr '\\0' '\\n' | grep -iE 'password|secret|token'" \
            "File: /proc/1/environ (readable by UID ${SYSTEM_UID})" \
            "Restrict /proc access with hidepid=2 mount option: mount -o remount,hidepid=2 /proc" \
            "https://attack.mitre.org/techniques/T1057/" \
            "T1057"
    fi
}

# ──────────────────────────────────────────────────────────────
# Database credentials
# ──────────────────────────────────────────────────────────────
_check_database_creds() {
    print_subsection "Database Credentials"

    # MySQL .my.cnf
    local mysql_cnf_files=("${HOME}/.my.cnf" "/root/.my.cnf" "/etc/mysql/debian.cnf")
    for cnf in "${mysql_cnf_files[@]}"; do
        if [[ -r "$cnf" ]]; then
            local creds
            creds=$(grep -iE "^password\s*=" "$cnf" 2>/dev/null)
            if [[ -n "$creds" ]]; then
                local _my_title="MySQL credentials in: ${cnf}"
                add_finding "CRITICAL" "credentials" "-" "$_my_title" \
                    "MySQL client config contains password" \
                    "mysql --defaults-file=${cnf}" \
                    "File: ${cnf} (permissions: $(file_perms "$cnf" 2>/dev/null), owner: $(file_owner "$cnf" 2>/dev/null)) ; Contains: password directive" \
                    "Remove plaintext passwords from .my.cnf. Use mysql_config_editor for encrypted credential storage." \
                    "https://attack.mitre.org/techniques/T1552/001/" \
                    "T1552.001"
                while IFS= read -r _myl; do
                    append_credential_preview "$_my_title" "$_myl"
                done <<< "$creds"
                echo -e "  ${BOLD_RED}[CRIT]${RESET} MySQL creds in ${cnf}: ${creds:0:40}..."
            fi
        fi
    done

    # PostgreSQL .pgpass
    if [[ -r "${HOME}/.pgpass" ]]; then
        local _pg_entries
        _pg_entries=$(wc -l < "${HOME}/.pgpass" 2>/dev/null)
        add_finding "HIGH" "credentials" "-" "PostgreSQL .pgpass found" \
            "PostgreSQL password file found at ${HOME}/.pgpass" \
            "cat ${HOME}/.pgpass" \
            "File: ${HOME}/.pgpass (permissions: $(file_perms "${HOME}/.pgpass" 2>/dev/null), entries: ${_pg_entries})" \
            "Remove .pgpass or restrict to 600. Use SCRAM-SHA-256 authentication and rotate passwords." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
        local _pgl _pg_n=0
        while IFS= read -r _pgl && [[ $_pg_n -lt 3 ]]; do
            append_credential_preview "PostgreSQL .pgpass found" "$(echo "$_pgl" | awk -F: '{OFS=FS; $NF="***REDACTED***"; print}')"
            _pg_n=$(( _pg_n + 1 ))
        done < "${HOME}/.pgpass"
    fi

    # MongoDB
    if [[ -r /etc/mongod.conf ]] || [[ -r /etc/mongodb.conf ]]; then
        local mongo_auth
        mongo_auth=$(grep -iE "auth|security" /etc/mongod.conf /etc/mongodb.conf 2>/dev/null | head -3)
        if echo "$mongo_auth" | grep -qi "enabled.*false\|authorization.*disabled"; then
            add_finding "HIGH" "credentials" "-" "MongoDB authentication disabled" \
                "MongoDB is configured without authentication" \
                "mongo admin --eval 'db.createUser({user:\"hacker\",pwd:\"hacked\",roles:[\"root\"]})'" \
                "Config files: /etc/mongod.conf, /etc/mongodb.conf ; Auth status: disabled" \
                "Enable MongoDB authentication in mongod.conf (security.authorization: enabled). Create admin user and enforce SCRAM." \
                "https://attack.mitre.org/techniques/T1190/" \
                "T1190"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Cloud credential files
# ──────────────────────────────────────────────────────────────
_check_cloud_creds() {
    print_subsection "Cloud Credentials"

    # AWS credentials
    local aws_cred_files=(
        "${HOME}/.aws/credentials"
        "${HOME}/.aws/config"
        "/root/.aws/credentials"
    )

    for aws_file in "${aws_cred_files[@]}"; do
        if [[ -r "$aws_file" ]]; then
            local _aws_profiles
            _aws_profiles=$(grep '^\[' "$aws_file" 2>/dev/null | tr -d '[]' | tr '\n' ', ')
            local _aws_title="AWS credentials file: ${aws_file}"
            add_finding "CRITICAL" "credentials" "-" "$_aws_title" \
                "AWS credentials file is accessible" \
                "cat ${aws_file} | grep -E 'aws_access_key_id|aws_secret_access_key'" \
                "File: ${aws_file} (permissions: $(file_perms "$aws_file" 2>/dev/null)) ; Profiles: ${_aws_profiles:-default}" \
                "Rotate AWS access keys immediately. Use IAM roles instead of long-term credentials. Store in AWS Secrets Manager." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
            while IFS= read -r _aws_line; do
                append_credential_preview "$_aws_title" "$_aws_line"
            done < <(grep -E '^[[:space:]]*(aws_access_key_id|aws_secret_access_key|aws_session_token)' "$aws_file" 2>/dev/null | head -6)
            echo -e "  ${BOLD_RED}[CRIT]${RESET} AWS credentials: ${aws_file}"
        fi
    done

    # GCP credentials
    local gcp_cred_files=(
        "${HOME}/.config/gcloud/credentials.db"
        "${HOME}/.config/gcloud/application_default_credentials.json"
        "/root/.config/gcloud/"
    )

    for gcp_file in "${gcp_cred_files[@]}"; do
        [[ -r "$gcp_file" ]] || continue
        add_finding "HIGH" "credentials" "-" "GCP credentials: ${gcp_file}" \
            "Google Cloud credentials file found" \
            "gcloud auth list" \
            "File: ${gcp_file} (permissions: $(file_perms "$gcp_file" 2>/dev/null))" \
            "Revoke and rotate service account keys. Use Workload Identity Federation where possible." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
    done

    # Azure credentials
    if [[ -d "${HOME}/.azure" ]] && [[ -r "${HOME}/.azure" ]]; then
        add_finding "HIGH" "credentials" "-" "Azure CLI credentials found" \
            "Azure CLI credentials directory exists" \
            "az account list" \
            "Directory: ${HOME}/.azure (permissions: $(file_perms "${HOME}/.azure" 2>/dev/null))" \
            "Run 'az logout' when sessions are not needed. Use managed identities instead of CLI tokens." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
    fi

    # Kubernetes
    if [[ -r "${HOME}/.kube/config" ]]; then
        local _k8s_clusters _k8s_perms
        _k8s_clusters=$(grep -c 'cluster:' "${HOME}/.kube/config" 2>/dev/null)
        _k8s_perms=$(file_perms "${HOME}/.kube/config" 2>/dev/null)
        add_finding "HIGH" "credentials" "-" "Kubernetes config found: ~/.kube/config" \
            "Kubernetes configuration with credentials exists" \
            "kubectl get pods --all-namespaces" \
            "File: ${HOME}/.kube/config (permissions: ${_k8s_perms}) ; Clusters configured: ${_k8s_clusters:-0}" \
            "Restrict kubeconfig permissions to 600. Use short-lived tokens via OIDC. Remove unused cluster contexts." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
    fi
}

# ──────────────────────────────────────────────────────────────
# Browser saved credentials
# ──────────────────────────────────────────────────────────────
_check_browser_creds() {
    print_subsection "Browser Stored Credentials"

    local browser_dirs=(
        "${HOME}/.mozilla/firefox"
        "${HOME}/.config/chromium"
        "${HOME}/.config/google-chrome"
        "${HOME}/.config/BraveSoftware"
    )

    for browser_dir in "${browser_dirs[@]}"; do
        [[ -d "$browser_dir" ]] || continue
        local browser_name
        browser_name=$(basename "$browser_dir")

        # Login data / password databases
        while IFS= read -r login_file; do
            [[ -r "$login_file" ]] || continue
            add_finding "MEDIUM" "credentials" "-" "Browser credential store: ${login_file}" \
                "Browser saved password database found for ${browser_name}" \
                "python3 -c 'import sqlite3; ...' # See: https://github.com/AlessandroZ/LaZagne" \
                "File: ${login_file} (permissions: $(file_perms "$login_file" 2>/dev/null)) ; Browser: ${browser_name}" \
                "Use a dedicated password manager instead of browser-stored credentials. Clear saved passwords from browser." \
                "https://attack.mitre.org/techniques/T1555/003/" \
                "T1555.003"
        done < <(find "$browser_dir" -name "Login Data" -o -name "logins.json" 2>/dev/null)
    done
}

# ──────────────────────────────────────────────────────────────
# Interesting files
# ──────────────────────────────────────────────────────────────
_check_interesting_files() {
    print_subsection "Interesting Files"

    local interesting_patterns=(
        "*.pem" "*.key" "*.pfx" "*.p12"
        "*.kdbx" "*.kdb"           # KeePass
        "id_rsa" "id_dsa" "id_ecdsa" "id_ed25519"
        ".netrc" ".pgpass"
        "wp-config.php" "config.php" "settings.py" "database.yml"
        "*.ovpn" "*.pcap" "*.pcapng"
        "shadow" "passwd" "group"
        "backup*" "*.backup" "*.bak"
    )

    for pattern in "${interesting_patterns[@]}"; do
        while IFS= read -r found_file; do
            [[ -r "$found_file" ]] || continue
            echo -e "  ${BOLD_CYAN}[FILE]${RESET} ${found_file}"
            local _if_perms _if_sz
            _if_perms=$(file_perms "$found_file" 2>/dev/null)
            _if_sz=$(wc -c < "$found_file" 2>/dev/null)
            add_finding "LOW" "credentials" "-" "Interesting file: ${found_file}" \
                "File may contain credentials or sensitive data" \
                "cat ${found_file}" \
                "File: ${found_file} (permissions: ${_if_perms}, size: ${_if_sz}B, owner: $(file_owner "$found_file" 2>/dev/null))" \
                "Review file contents. Remove or restrict access to sensitive files. Set permissions to 600 or tighter." \
                "" \
                "T1552.001"
        done < <(safe_run 20 find /home /root /var /opt /srv /etc -maxdepth 5 \
            -name "$pattern" -type f 2>/dev/null | grep -v ".cache\|.local/share" | head -20)
    done
}

# ──────────────────────────────────────────────────────────────
# DevOps / IaC credentials
# ──────────────────────────────────────────────────────────────
_check_devops_creds() {
    print_subsection "DevOps / IaC Credentials"

    # Ansible vault files
    while IFS= read -r vault_file; do
        if [[ -r "$vault_file" ]] && head -1 "$vault_file" 2>/dev/null | grep -q "ANSIBLE_VAULT"; then
            add_finding "HIGH" "credentials" "-" "Ansible vault file: ${vault_file}" \
                "Encrypted Ansible vault found - may contain infrastructure secrets" \
                "ansible-vault view ${vault_file}" \
                "File: ${vault_file} (permissions: $(file_perms "$vault_file" 2>/dev/null))" \
                "Restrict vault file access. Rotate vault password. Use Ansible Vault with external key management." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
        fi
    done < <(safe_run 15 find /home /root /opt /etc -maxdepth 5 \
        \( -name "vault.yml" -o -name "vault.yaml" -o -name "*.vault" -o -name "secrets.yml" \) \
        -type f 2>/dev/null | head -10)

    # Ansible inventory with credentials
    while IFS= read -r inv_file; do
        [[ -r "$inv_file" ]] || continue
        if grep -qiE "ansible_ssh_pass|ansible_become_pass|ansible_password" "$inv_file" 2>/dev/null; then
            local _inv_title="Ansible inventory with plaintext passwords: ${inv_file}"
            add_finding "CRITICAL" "credentials" "-" "$_inv_title" \
                "Ansible inventory contains plaintext credentials" \
                "grep -iE 'pass|secret' ${inv_file}" \
                "File: ${inv_file} (permissions: $(file_perms "$inv_file" 2>/dev/null)) ; Contains: ansible_ssh_pass or ansible_become_pass" \
                "Move passwords to Ansible Vault. Use SSH key-based auth instead of password auth." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
            while IFS= read -r _inv_line; do
                append_credential_preview "$_inv_title" "$_inv_line"
            done < <(grep -niE "ansible_ssh_pass|ansible_become_pass|ansible_password" "$inv_file" 2>/dev/null | head -4)
        fi
    done < <(safe_run 10 find /home /root /opt /etc -maxdepth 5 \
        \( -name "inventory" -o -name "hosts" -o -name "inventory.ini" -o -name "inventory.yml" \) \
        -type f 2>/dev/null | head -10)

    # Terraform state files
    while IFS= read -r tf_state; do
        if [[ -r "$tf_state" ]]; then
            local _tf_sz
            _tf_sz=$(wc -c < "$tf_state" 2>/dev/null)
            add_finding "HIGH" "credentials" "-" "Terraform state file: ${tf_state}" \
                "Terraform state may contain secrets, API keys, and credentials in plaintext" \
                "grep -iE 'password|secret|token|key' ${tf_state}" \
                "File: ${tf_state} (permissions: $(file_perms "$tf_state" 2>/dev/null), size: ${_tf_sz}B)" \
                "Use remote state backend (S3/GCS) with encryption-at-rest. Never store state files locally in production." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
        fi
    done < <(safe_run 10 find /home /root /opt /var -maxdepth 5 \
        -name "terraform.tfstate*" -type f 2>/dev/null | head -5)

    # Hashicorp Vault token
    if [[ -r "${HOME}/.vault-token" ]]; then
        add_finding "CRITICAL" "credentials" "-" "Hashicorp Vault token: ~/.vault-token" \
            "Vault authentication token accessible" \
            "export VAULT_TOKEN=\$(cat ~/.vault-token) && vault kv list secret/" \
            "File: ${HOME}/.vault-token (permissions: $(file_perms "${HOME}/.vault-token" 2>/dev/null))" \
            "Remove token file. Use vault login with AppRole or Kubernetes auth. Set token TTL to minimum required." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
        local _vtok_sz
        _vtok_sz=$(wc -c < "${HOME}/.vault-token" 2>/dev/null)
        if [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]]; then
            local _vt_raw
            _vt_raw=$(cat "${HOME}/.vault-token" 2>/dev/null)
            append_credential_preview "Hashicorp Vault token: ~/.vault-token" "VAULT_TOKEN=${_vt_raw}"
        else
            append_credential_preview "Hashicorp Vault token: ~/.vault-token" "token file present (~/.vault-token), ${_vtok_sz:-0} bytes (redacted)"
        fi
    fi

    # Consul token
    if [[ -n "${CONSUL_HTTP_TOKEN:-}" ]]; then
        add_finding "HIGH" "credentials" "-" "Consul HTTP token in environment" \
            "HashiCorp Consul authentication token found" "" \
            "Variable: CONSUL_HTTP_TOKEN (present in environment)" \
            "Revoke exposed token. Use Consul ACL with short-lived tokens. Remove from environment." \
            "https://attack.mitre.org/techniques/T1552/001/" \
            "T1552.001"
        if [[ "${REPORT_FULL_SECRETS:-0}" == "1" ]]; then
            append_credential_preview "Consul HTTP token in environment" "CONSUL_HTTP_TOKEN=${CONSUL_HTTP_TOKEN}"
        else
            append_credential_preview "Consul HTTP token in environment" "CONSUL_HTTP_TOKEN=***REDACTED*** (length ${#CONSUL_HTTP_TOKEN})"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────
# Git credential stores
# ──────────────────────────────────────────────────────────────
_check_git_credentials() {
    print_subsection "Git Credentials"

    local git_cred_files=(
        "${HOME}/.git-credentials"
        "/root/.git-credentials"
        "${HOME}/.gitconfig"
    )

    for gcf in "${git_cred_files[@]}"; do
        [[ -r "$gcf" ]] || continue

        if [[ "$gcf" == *"git-credentials" ]]; then
            local _gc_entries
            _gc_entries=$(wc -l < "$gcf" 2>/dev/null)
            local _git_store_title="Git credential store: ${gcf}"
            add_finding "HIGH" "credentials" "-" "$_git_store_title" \
                "Plaintext Git credentials found (URLs with passwords)" \
                "cat ${gcf}" \
                "File: ${gcf} (permissions: $(file_perms "$gcf" 2>/dev/null)) ; Stored credentials: ${_gc_entries}" \
                "Switch to git-credential-cache or git-credential-libsecret. Remove plaintext credential store." \
                "https://attack.mitre.org/techniques/T1552/001/" \
                "T1552.001"
            local _gc_n=0
            while IFS= read -r _gcline && [[ $_gc_n -lt 4 ]]; do
                append_credential_preview "$_git_store_title" "$_gcline"
                _gc_n=$(( _gc_n + 1 ))
            done < <(head -4 "$gcf" 2>/dev/null)
        elif [[ "$gcf" == *"gitconfig" ]]; then
            if grep -qiE "helper\s*=\s*store" "$gcf" 2>/dev/null; then
                print_warn "Git credential helper is 'store' (plaintext)"
            fi
        fi
    done

    # GitHub/GitLab tokens
    while IFS= read -r token_file; do
        [[ -r "$token_file" ]] || continue
        add_finding "HIGH" "credentials" "-" "GitHub/GitLab token file: ${token_file}" \
            "Source code platform authentication token found" \
            "cat ${token_file}" \
            "File: ${token_file} (permissions: $(file_perms "$token_file" 2>/dev/null))" \
            "Revoke and rotate the token. Use fine-grained personal access tokens with minimal scope." \
            "https://attack.mitre.org/techniques/T1528/" \
            "T1528"
    done < <(safe_run 5 find "${HOME}" /root -maxdepth 3 \
        \( -name ".github_token" -o -name ".gitlab_token" -o -name "gh_token" \) \
        -type f 2>/dev/null | head -5)
}
