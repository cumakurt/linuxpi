# LinuxPi (π)

**Linux Privilege Escalation Framework** — comprehensive privilege escalation vector analysis. The **π** motif reflects the ratio *C/d* (circumference to diameter): mapping attack surface to effective privilege boundaries.

> **LEGAL WARNING:** This tool is designed ONLY for authorized penetration testing and security assessments. Unauthorized use is strictly prohibited.

**Türkçe:** [README.tr.md](README.tr.md)

---

## Architecture

```
linuxpi/
├── linuxpi.sh          # Main entrypoint
├── README.md           # Documentation (English)
├── README.tr.md        # Documentation (Türkçe)
├── core/
│   ├── main.sh                # Orchestration engine
│   ├── detector.sh            # System, container, VM, cloud detection
│   ├── analyzer.sh            # CVE matching, CVSS scoring, GTFOBins
│   ├── enumerator.sh          # Module management and sequencing
│   ├── exploiter.sh           # Automated exploitation engine
│   └── reporter.sh            # Multi-format reports (text/json/html/xml/md)
├── modules/
│   ├── kernel/
│   │   ├── kernel_enum.sh      # Kernel CVE, sysctl, module analysis
│   │   ├── kernel_research.sh  # CONFIG/sysfs sysctl research context (KASLR, BPF, mitigations)
│   │   └── kernel_exploits.db  # 67+ kernel CVE database
│   ├── sudo/
│   │   ├── sudo_enum.sh       # Sudo configuration, CVE, privilege analysis
│   │   └── sudo_exploits.db   # 15+ sudo CVE database
│   ├── suid/
│   │   └── suid_finder.sh     # SUID/SGID, capabilities, RPATH/RUNPATH
│   ├── cron/
│   │   └── cron_enum.sh       # Cron, systemd timer, at job analysis
│   ├── credentials/
│   │   └── cred_finder.sh     # Credential harvesting (SSH, DB, cloud, DevOps)
│   ├── network/
│   │   └── network_enum.sh    # Network, NFS, firewall analysis
│   ├── containers/
│   │   └── container_detect.sh # Docker/K8s/LXC escape detection
│   ├── services/
│   │   └── service_enum.sh    # Service, process, software analysis
│   └── security/
│       └── security_enum.sh   # MAC, PATH hijack, shell profile, doas
├── database/
│   ├── cve_database.json      # Structured CVE database
│   ├── epss_scores.db         # EPSS + CVSS scoring database (70+ CVE)
│   ├── gtfobins.json          # GTFOBins mirror (~470+ binaries, jq)
│   └── gtfobins_flat.db       # Same data, flat rows (no jq)
├── utils/
│   ├── colors.sh              # Terminal colors, banner, progress bar
│   ├── logger.sh              # Structured JSON logging
│   ├── helpers.sh             # Helper functions, finding collector
│   └── parser.sh              # Argument parsing, config
├── scripts/
│   └── build_gtfobins_db.py   # Rebuild gtfobins.json from upstream YAML
├── tests/
│   ├── test_exploit_mode.sh   # Exploit engine unit tests
│   └── test_kernel_matching.sh # Kernel CVE matching unit tests
├── output/
│   └── templates/
│       └── html_report.tpl    # SOC-grade HTML report template
└── Makefile                   # Build, test, lint, release helpers
```

## Features

### Scan Modules (12 Modules)

| Module | Description |
|--------|-------------|
| `user` | User context, group memberships, privilege token analysis |
| `kernel` | Kernel CVE matching (67+ CVE), sysctl security, SMEP/SMAP/KASLR |
| `sudo` | Sudo version CVE, privilege parse, env_keep, NOPASSWD, Baron Samedit |
| `suid` | SUID/SGID binary scan, GTFOBins matching, RPATH/RUNPATH hijacking |
| `capabilities` | Linux capabilities analysis (14 dangerous capabilities) |
| `cron` | Cron, systemd timer, at job, wildcard injection, PATH hijacking |
| `credentials` | SSH key, history, config, DB, cloud, DevOps/IaC, git credentials |
| `network` | Interface, port, NFS, firewall, routing, DNS analysis |
| `containers` | Docker socket, privileged container, K8s SA, namespace escape |
| `services` | Running services, writable unit files, process credential leak |
| `filesystem` | World-writable dirs, sensitive files, mount noexec/nosuid |
| `security` | AppArmor/SELinux, PATH hijacking, shell profiles, doas, package dirs |

### CVE Databases

- **67+ Kernel CVE** (2010-2026): Dirty COW, Dirty Pipe, PwnKit, nf_tables UAF, io_uring, eBPF, CopyFail, Dirty Frag, CIFSwitch...
- **15+ Sudo CVE**: Baron Samedit, UID bypass, pwfeedback overflow...
- **Polkit, glibc, snapd, runc, PackageKit, CIFS/cifs.upcall** dedicated checks
- **GTFOBins** ([gtfobins.org](https://gtfobins.org/)): full mirror of documented techniques for **sudo**, **SUID**, and **capabilities** — primary exploit line plus extra techniques in evidence; refresh with `make update-gtfobins`

### Recent 2026 LPE Coverage

LinuxPi includes 2026 local privilege escalation checks observed in the March-June 2026 advisory window:

| CVE / Name | Detection |
|------------|-----------|
| `CVE-2026-31431` CopyFail | Kernel stable-branch range plus AF_ALG / `algif_aead` context |
| `CVE-2026-43284` Dirty Frag ESP | Kernel stable-branch range plus ESP/XFRM and user namespace context |
| `CVE-2026-43500` Dirty Frag RxRPC | Kernel stable-branch range plus RxRPC config/module context |
| `CVE-2026-46300` Fragnesia | Kernel stable-branch range plus ESP/XFRM context |
| `CVE-2026-46333` ssh-keysign-pwn | Kernel stable-branch range plus ptrace and SUID/root helper context |
| `CVE-2026-31635` DirtyDecrypt | Kernel stable-branch range plus RxRPC/RxGK context |
| `CVE-2026-46243` CIFSwitch | CIFS module, `cifs.upcall`, `cifs.spnego` request-key chain |
| `CVE-2026-41651` Pack2TheRoot | PackageKit version and service/tooling presence |

For modern kernel advisories, LinuxPi stores affected ranges per stable branch instead of a single broad min/max window. This reduces false positives around patched stable releases while still surfacing runtime preconditions in evidence.

### EPSS + CVSS Priority Scoring

Each finding is enriched with machine-readable scoring:

- **CVSS Base Score** + Vector string (NVD v3.1)
- **EPSS Score** - Probability of exploitation in next 30 days (FIRST.org model)
- **Priority Score** (0-10) - Composite: `(CVSS × 0.35) + (EPSS × 10 × 0.40) + (exploit_avail × 0.25)`
- **Priority Tier** - IMMINENT (≥8) / LIKELY (≥6) / POSSIBLE (≥4) / UNLIKELY (≥2) / MINIMAL

### Advanced Finding Deduplication

- **CVE-based cross-module merge**: Same CVE from multiple modules → single finding with highest severity
- **Title normalization**: Case-insensitive dedup with prefix stripping (CONFIRMED:, VULNERABLE:, etc.)
- **Detail merge**: Combined context from all modules that detected the same vulnerability

### Enriched Finding Data

Every finding includes structured enrichment fields across all report formats:

| Field | Description | Example |
|-------|-------------|---------|
| **Evidence** | Discovered artifacts, file paths, permissions, actual values | `File: /etc/shadow (permissions: 644) ; Crackable hashes: 3` |
| **Remediation** | Actionable fix guidance | `Set /etc/shadow permissions to 640 owned by root:shadow` |
| **MITRE ATT&CK** | Technique ID mapping | `T1552.001` (Credentials in Files) |
| **References** | NVD, MITRE, GTFOBins URLs | `https://nvd.nist.gov/vuln/detail/CVE-2024-1086` |
| **Credential hints** | Default: redacted snippets only | Use **`--report-full-secrets`** to embed plaintext in report fields (JSON key `credentials_redacted` may hold full values); **high leak risk** |

### Report Formats

- **Text** - Terminal output with evidence bullets, remediation, MITRE tags, inline CVSS/EPSS scoring
- **JSON** - Machine-readable with `evidence`, `remediation`, `references`, `mitre_attack`, `scoring` per finding (SIEM-ready)
- **HTML** - SOC-grade dark theme dashboard with evidence/remediation panels, MITRE badges, scoring
- **XML** - Structured data with `<evidence>`, `<remediation>`, `<references>`, `<mitre-attack>`, `<scoring>` elements
- **Markdown** - Documentation-ready with evidence lists, remediation blockquotes, scoring tables

### Smart Features

- **Severity-based sorting** - Findings sorted CRITICAL → INFO
- **Finding deduplication** - Duplicate findings automatically filtered
- **Progress bar** - Scan progress indicator
- **Module timing** - Execution time per module
- **Risk scoring** - CVSS-based risk scoring
- **Attack paths** - Prioritized attack paths
- **Compliance mapping** - CIS, NIST, OWASP references
- **Exploit mode** - Interactive automated exploitation with risk-level control; **`--run`** runs shell-classified vectors sequentially without prompts after the scan (see Exploit section)

## Installation

Clone with **HTTPS** or **SSH** (if [your SSH key is added to GitHub](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)):

```bash
git clone https://github.com/cumakurt/linuxpi.git
# or
git clone git@github.com:cumakurt/linuxpi.git

cd linuxpi
chmod +x linuxpi.sh
```

The repository does **not** ship `build/` or `dist/` artifacts; run `make standalone` (or use `linuxpi.sh` directly from the source tree).

### Standalone Build

```bash
make standalone    # Single-file bash script
make minimal       # Kernel+sudo+suid only (fast)
make full          # All modules + database
make dist          # Release package (SHA256 checksum)
```

## Usage

### Quick start

```bash
./linuxpi.sh                    # Default: all modules, text report, exploit suggestions on
./linuxpi.sh --help             # Full option list
./linuxpi.sh --version          # Version and author lines
```

### Basic options (`-v`, `-q`, `--debug`, `--no-color`)

```bash
./linuxpi.sh -v                 # Extra enumeration detail (e.g. per-file paths where gated)
./linuxpi.sh -q                 # Quieter stderr; fewer section banners
./linuxpi.sh --debug            # Developer-oriented verbose output
./linuxpi.sh --no-color         # Plain text (no ANSI colors)
./linuxpi.sh --no-color -f text # Colors off + terminal text report
```

### Module selection (`-m`, `--full`, `--minimal`)

`kernel`, `sudo`, `suid`, `capabilities`, `cron`, `services`, `containers`, `credentials`, `network`, `security`, `filesystem`, `all` — comma-separated for multiple modules.

```bash
./linuxpi.sh -m kernel
./linuxpi.sh -m sudo,suid
./linuxpi.sh -m credentials,network,containers
./linuxpi.sh -m all
./linuxpi.sh --full             # Same as all modules + exploit suggestions enabled
./linuxpi.sh --minimal          # Fast path: kernel + sudo + suid only; suggestions off
```

### Report formats (`-f`, `-o`)

Structured formats send live scan lines to **stderr**; the report goes to **stdout** unless `-o` is set. With `-o`, the report is written **only** to the file (not printed twice).

```bash
./linuxpi.sh -f text            # Default human-readable terminal summary
./linuxpi.sh -f json            # JSON on stdout (pipe to `jq`, files, SIEM)
./linuxpi.sh -f json -o /tmp/scan.json
./linuxpi.sh -f html -o /tmp/report.html
./linuxpi.sh --full -f html -o /tmp/report.html -q
./linuxpi.sh -f xml -o /tmp/report.xml
./linuxpi.sh -f markdown -o /tmp/report.md
./linuxpi.sh -f json -v         # Verbose scan on stderr while JSON goes to stdout
```

### Plaintext credentials in reports (`--report-full-secrets`)

Default reports redact credential fields. This opt-in embeds plaintext secrets in report payloads — use only where policy allows and treat output like raw secrets.

```bash
./linuxpi.sh --report-full-secrets -f json -o /tmp/out.json
./linuxpi.sh --full --report-full-secrets -f html -o /tmp/report.html
```

### Exploit suggestions and exploit mode (`--suggest-exploits`, `--no-suggest`, `--exploit`, `--run`, `--risk-level`)

```bash
./linuxpi.sh --suggest-exploits   # Explicitly on (already default when not using --minimal)
./linuxpi.sh --no-suggest         # Scan without exploit suggestion strings in findings
./linuxpi.sh --no-suggest -m suid
./linuxpi.sh --exploit --risk-level low      # Interactive menu; cap at low risk
./linuxpi.sh --exploit --risk-level medium
./linuxpi.sh --exploit --risk-level high
./linuxpi.sh --exploit --risk-level critical
./linuxpi.sh --run                 # After scan: auto-try shell-classified exploits in order (no menu); min risk high
# --run rewrites sudo to sudo -n (no password prompts); NOPASSWD vectors still run. Requires perl for that rewrite.
# Optional per-attempt cap (seconds, default 600): AUTO_SHELL_TIMEOUT=900 ./linuxpi.sh --run
```

### Stealth (`--stealth`)

Re-execs with a disguised process name and enables quiet-style output; use only in authorized tests.

```bash
./linuxpi.sh --stealth
./linuxpi.sh --stealth -m sudo,suid
```

### Container and cloud focus (`--container-mode`, `--cloud`)

```bash
./linuxpi.sh --container-mode
./linuxpi.sh --container-mode -f json -o /tmp/container.json
./linuxpi.sh --cloud              # Cloud heuristics (provider auto-detected when possible)
./linuxpi.sh --cloud aws
./linuxpi.sh --cloud azure
./linuxpi.sh --cloud gcp
./linuxpi.sh --full --cloud aws -o /tmp/cloud.json -f json
```

### Timeout and logging (`--timeout`, `--log-file`)

```bash
./linuxpi.sh --timeout 120                    # Abort scan after 120 seconds (partial report)
./linuxpi.sh --timeout 600 --full -f html -o /tmp/r.html
./linuxpi.sh --log-file /var/log/linuxpi.log  # Structured JSON log path
./linuxpi.sh --log-file ./run.log -f json -o ./findings.json
```

### Piped / memory-only execution

```bash
curl -sL https://example.com/linuxpi.sh | bash
curl -sL https://example.com/linuxpi.sh | bash -s -- --minimal -f json
```

### Combined workflows

```bash
# Lab: full scan, HTML file, quieter stderr, no HTML flood on TTY
./linuxpi.sh --full -f html -o /tmp/report.html -q

# Assessor: XML to file + custom log
./linuxpi.sh --full -f xml -o /tmp/report.xml --log-file /tmp/linuxpi.log

# Targeted quick check with Markdown export
./linuxpi.sh -m kernel,sudo,suid -f markdown -o /tmp/summary.md

# High-signal JSON for automation (non-zero exit encodes severity — see Exit Codes)
./linuxpi.sh --full -f json -o findings.json; echo $?
```

### All Options

```
BASIC OPTIONS:
  -v, --verbose           Verbose output
  -q, --quiet             Quiet mode (findings only)
      --debug             Debug mode (developer output)
      --stealth           Stealth mode (minimal footprint)
  -h, --help              Help menu
      --version           Version info

MODULE SELECTION:
  -m, --module MODULE     Module selection (comma-separated):
                          kernel|sudo|suid|capabilities|cron|
                          services|containers|credentials|network|
                          security|filesystem|all
      --full              All modules + exploit suggestions
      --minimal           Core modules (fast)

OUTPUT:
  -f, --format FORMAT     Output format: text|json|html|xml|markdown
  -o, --output FILE       Save to file
      --no-color          Disable colored output
      --report-full-secrets  Include captured credentials as plaintext in reports (UNSAFE; default is redacted)
  Note: For json|html|xml|markdown, live scan output goes to stderr. Without -o the report is printed to stdout;
        with -o/--output the report is written only to that file (not echoed to the terminal). A short "Report saved" line goes to stderr.
        Use -q for quieter stderr.

EXPLOITATION:
      --suggest-exploits  Show exploit suggestions (default: on)
      --no-suggest        Disable exploit suggestions
      --exploit           Interactive exploit menu after scan (DANGEROUS)
      --run               Auto-try shell-classified exploits sequentially; no prompts (DANGEROUS)
      --risk-level LEVEL  Max risk level: low|medium|high|critical

ADVANCED:
      --container-mode    Container escape focused scan
      --cloud [PROVIDER]  Cloud platform scan (aws|azure|gcp)
      --timeout SECONDS   Timeout (default: 300)
      --log-file FILE     Log file path
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `2` | CRITICAL findings present |
| `3` | HIGH findings present |
| `4` | Other findings present |

## Requirements

- **Bash 4.0+** (recommended)
- **Standard Linux tools**: `find`, `grep`, `awk`, `stat`, `id`
- **Optional**: `jq` (faster GTFOBins / JSON queries), `PyYAML` + `git` (for `make update-gtfobins`), `curl` (cloud detection), `shellcheck` (linting)

## Development and Tests

```bash
make check                       # Bash syntax validation
make test                        # Syntax + unit tests + basic functional scan
make shellcheck                  # Optional lint; prints a warning if shellcheck is unavailable
bash tests/test_exploit_mode.sh
bash tests/test_kernel_matching.sh
```

`make test` runs the exploit engine tests and kernel matcher boundary tests, then verifies `--help` and a quiet kernel scan.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE) (GPL-3.0).

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities in LinuxPi itself.

## Developer

**Cuma KURT** — [cumakurt@gmail.com](mailto:cumakurt@gmail.com)  
[LinkedIn](https://www.linkedin.com/in/cuma-kurt-34414917/) · [GitHub](https://github.com/cumakurt/linuxpi)
