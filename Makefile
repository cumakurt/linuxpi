# LinuxPi - Makefile
# Build: standalone script, minimal, or full version

SHELL         := /bin/bash
TOOL_NAME     := linuxpi
VERSION       := 1.0.0
BUILD_DIR     := build
DIST_DIR      := dist

CORE_FILES    := utils/colors.sh utils/logger.sh utils/helpers.sh utils/parser.sh \
                 core/detector.sh core/analyzer.sh core/reporter.sh \
                 core/exploiter.sh core/enumerator.sh core/main.sh

MODULE_FILES  := modules/kernel/kernel_research.sh \
                 modules/kernel/kernel_enum.sh \
                 modules/sudo/sudo_enum.sh \
                 modules/suid/suid_finder.sh \
                 modules/cron/cron_enum.sh \
                 modules/credentials/cred_finder.sh \
                 modules/network/network_enum.sh \
                 modules/containers/container_detect.sh \
                 modules/services/service_enum.sh \
                 modules/security/security_enum.sh

DB_FILES      := modules/kernel/kernel_exploits.db \
                 modules/sudo/sudo_exploits.db \
                 database/gtfobins.json \
                 database/gtfobins_flat.db \
                 database/cve_database.json \
                 database/epss_scores.db

ALL_FILES     := $(CORE_FILES) $(MODULE_FILES)

.PHONY: all standalone minimal full check install clean help dist

all: standalone

## standalone: Embed all modules into a single bash file
standalone: $(ALL_FILES)
	@echo "[*] Building standalone script..."
	@mkdir -p $(BUILD_DIR)
	@$(MAKE) _build_standalone OUTPUT=$(BUILD_DIR)/$(TOOL_NAME).sh MODULES="$(ALL_FILES)"
	@chmod +x $(BUILD_DIR)/$(TOOL_NAME).sh
	@echo "[+] Standalone built: $(BUILD_DIR)/$(TOOL_NAME).sh"
	@ls -lh $(BUILD_DIR)/$(TOOL_NAME).sh

_build_standalone:
	@echo '#!/usr/bin/env bash' > $(OUTPUT)
	@echo '# LinuxPi v$(VERSION) - Standalone Build' >> $(OUTPUT)
	@echo '# Generated: $(shell date -u +%Y-%m-%dT%H:%M:%SZ)' >> $(OUTPUT)
	@echo '# LEGAL: Authorized penetration testing only' >> $(OUTPUT)
	@echo '' >> $(OUTPUT)
	@echo 'set -euo pipefail' >> $(OUTPUT)
	@echo 'IFS=$$'"'"'\n\t'"'"'' >> $(OUTPUT)
	@echo 'SCRIPT_DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"' >> $(OUTPUT)
	@echo 'export SCRIPT_DIR' >> $(OUTPUT)
	@echo '' >> $(OUTPUT)
	@for f in $(MODULES); do \
		echo "# ===== $$f =====" >> $(OUTPUT); \
		grep -v '^#!/' "$$f" >> $(OUTPUT) 2>/dev/null || true; \
		echo '' >> $(OUTPUT); \
	done
	@echo '' >> $(OUTPUT)
	@echo '# === Embedded databases ===' >> $(OUTPUT)
	@echo 'KERNEL_DB_CONTENT=$$(cat <<'"'"'KERNELDB'"'"'' >> $(OUTPUT)
	@grep -v '^#' modules/kernel/kernel_exploits.db 2>/dev/null >> $(OUTPUT) || true
	@echo 'KERNELDB' >> $(OUTPUT)
	@echo ')' >> $(OUTPUT)
	@echo '' >> $(OUTPUT)
	@echo '# === Entrypoint ===' >> $(OUTPUT)
	@echo 'parse_args "$$@"' >> $(OUTPUT)
	@echo 'TIMEOUT_PID=""' >> $(OUTPUT)
	@echo '_setup_timeout_handler' >> $(OUTPUT)
	@echo 'main' >> $(OUTPUT)

## minimal: Kernel+sudo+suid only (fast, lightweight)
minimal:
	@echo "[*] Building minimal script..."
	@mkdir -p $(BUILD_DIR)
	@$(MAKE) _build_standalone \
		OUTPUT=$(BUILD_DIR)/$(TOOL_NAME)-minimal.sh \
		MODULES="$(CORE_FILES) modules/kernel/kernel_research.sh modules/kernel/kernel_enum.sh modules/sudo/sudo_enum.sh modules/suid/suid_finder.sh"
	@chmod +x $(BUILD_DIR)/$(TOOL_NAME)-minimal.sh
	@echo "[+] Minimal built: $(BUILD_DIR)/$(TOOL_NAME)-minimal.sh"

## full: All modules + embedded database
# Archive only explicit members — do not use "." here: the tarball is written
# inside DIST_DIR and would change the directory while tar reads it ("file changed as we read it").
full: standalone
	@echo "[*] Building full distribution..."
	@mkdir -p $(DIST_DIR)
	@cp $(BUILD_DIR)/$(TOOL_NAME).sh $(DIST_DIR)/
	@cp -r database/ $(DIST_DIR)/
	@rm -f $(DIST_DIR)/$(TOOL_NAME)-$(VERSION)-full.tar.gz
	@tar -czf $(DIST_DIR)/$(TOOL_NAME)-$(VERSION)-full.tar.gz -C $(DIST_DIR) $(TOOL_NAME).sh database
	@echo "[+] Full distribution: $(DIST_DIR)/$(TOOL_NAME)-$(VERSION)-full.tar.gz"

## dist: Prepare release package
dist: full
	@mkdir -p $(DIST_DIR)/release
	@cp $(BUILD_DIR)/$(TOOL_NAME).sh $(DIST_DIR)/release/$(TOOL_NAME)-$(VERSION).sh
	@cp $(BUILD_DIR)/$(TOOL_NAME)-minimal.sh $(DIST_DIR)/release/$(TOOL_NAME)-$(VERSION)-minimal.sh 2>/dev/null || true
	@sha256sum $(DIST_DIR)/release/*.sh > $(DIST_DIR)/release/SHA256SUMS
	@echo "[+] Release files:"
	@ls -lh $(DIST_DIR)/release/

## check: Syntax validation
check:
	@echo "[*] Checking shell syntax..."
	@for f in linuxpi.sh $(ALL_FILES); do \
		bash -n "$$f" && echo "  [OK] $$f" || echo "  [FAIL] $$f"; \
	done
	@echo "[+] Syntax check complete"

## shellcheck: ShellCheck linting (requires: apt install shellcheck)
shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { echo "[WARN] shellcheck not installed"; exit 0; }
	@shellcheck -e SC1090,SC1091,SC2034,SC2154 linuxpi.sh $(ALL_FILES) && echo "[+] ShellCheck passed"

## install: Install to /usr/local/bin (requires root)
install: standalone
	@echo "[*] Installing to /usr/local/bin/$(TOOL_NAME)..."
	@cp $(BUILD_DIR)/$(TOOL_NAME).sh /usr/local/bin/$(TOOL_NAME)
	@chmod +x /usr/local/bin/$(TOOL_NAME)
	@echo "[+] Installed: $(TOOL_NAME)"

## clean: Remove build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "[+] Clean complete"

## test: Run basic tests
test: check
	@echo "[*] Running basic functional test..."
	@bash linuxpi.sh --help > /dev/null && echo "  [OK] --help works"
	@bash linuxpi.sh -m kernel --no-color --quiet > /dev/null; echo "  [OK] kernel module runs (exit: $$?)"
	@echo "[+] Basic tests passed"

## update-gtfobins: Rebuild GTFOBins DB from upstream (git + PyYAML required)
update-gtfobins:
	@echo "[*] Rebuilding GTFOBins database from https://gtfobins.org/ sources..."
	@python3 -c "import yaml" 2>/dev/null || { echo "[ERROR] pip install pyyaml"; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "[ERROR] git required for shallow clone"; exit 1; }
	@_gtf=$$(mktemp -d); \
	  git clone --depth 1 https://github.com/GTFOBins/GTFOBins.github.io.git "$$_gtf/g" && \
	  python3 scripts/build_gtfobins_db.py --local "$$_gtf/g/_gtfobins" && \
	  rm -rf "$$_gtf" && echo "[+] database/gtfobins.json and gtfobins_flat.db updated"

## help: Show this help menu
help:
	@echo "LinuxPi v$(VERSION) - Build System"
	@echo ""
	@grep -E '^## [a-z]' Makefile | sed 's/## /  make /' | column -t -s ':'
	@echo ""
	@echo "Examples:"
	@echo "  make standalone  - Single-file bash script"
	@echo "  make minimal     - Fast lightweight version"
	@echo "  make full        - Complete distribution package"
	@echo "  make check       - Syntax validation"
	@echo "  make test        - Basic functional tests"
