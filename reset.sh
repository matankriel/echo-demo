#!/usr/bin/env bash
# reset.sh — clears all generated data and plants a vulnerable urllib3 for the demo
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

sep()  { printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }
ok()   { printf "  ${GREEN}✓${RESET}  $1\n"; }
skip() { printf "  ${YELLOW}–${RESET}  $1\n"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

printf "\n${BOLD}${RED}  ╔═══════════════════════════════════╗${RESET}\n"
printf   "${BOLD}${RED}  ║       ECHO — RESET ENVIRONMENT    ║${RESET}\n"
printf   "${BOLD}${RED}  ╚═══════════════════════════════════╝${RESET}\n\n"

# ── 1. Kill gateway ────────────────────────────────────────────────────────────
sep
printf "${BOLD}[1/5] Stopping gateway${RESET}\n"
if pkill -f "uvicorn gateway.api:app" 2>/dev/null; then
    sleep 1
    ok "Gateway process killed"
else
    skip "Gateway was not running"
fi

# ── 2. Reset db.json ───────────────────────────────────────────────────────────
sep
printf "${BOLD}[2/5] Resetting factory/db.json${RESET}\n"
echo "[]" > "$SCRIPT_DIR/factory/db.json"
ok "factory/db.json reset to empty array"

# ── 3. Clear artifacts + api_diff cache ────────────────────────────────────────
sep
printf "${BOLD}[3/5] Clearing factory/artifacts + api_diff cache${RESET}\n"
wheel_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "*.whl" 2>/dev/null | wc -l | tr -d ' ')
patch_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "*.patch" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$wheel_count" -gt 0 ]]; then
    rm -f "$SCRIPT_DIR/factory/artifacts/"*.whl
    ok "Removed $wheel_count wheel(s)"
else
    skip "No wheels to remove"
fi

if [[ "$patch_count" -gt 0 ]]; then
    rm -f "$SCRIPT_DIR/factory/artifacts/"*.patch
    ok "Removed $patch_count patch file(s)"
else
    skip "No patch files to remove"
fi

if [[ -f "$SCRIPT_DIR/factory/api_diff_cache.json" ]]; then
    rm -f "$SCRIPT_DIR/factory/api_diff_cache.json"
    ok "Removed factory/api_diff_cache.json"
else
    skip "api_diff_cache.json did not exist"
fi

# ── 4. Clear shim temp file ────────────────────────────────────────────────────
sep
printf "${BOLD}[4/5] Clearing shim temp files${RESET}\n"
if [[ -f /tmp/echo_fix.txt ]]; then
    rm -f /tmp/echo_fix.txt
    ok "Removed /tmp/echo_fix.txt"
else
    skip "/tmp/echo_fix.txt did not exist"
fi

# ── 5. Plant known-vulnerable packages ────────────────────────────────────────
sep
printf "${BOLD}[5/5] Installing vulnerable versions  (demo \"before\" state)${RESET}\n"
pip install "urllib3==2.3.0" --no-deps --quiet 2>&1
pip install "requests==2.28.2" --no-deps --quiet 2>&1
urllib3_v=$(pip show urllib3  | awk '/^Version:/{print $2}')
requests_v=$(pip show requests | awk '/^Version:/{print $2}')
ok "urllib3  $urllib3_v   ${YELLOW}(CVE-2026-21441 — BACKPORT scenario)${RESET}"
ok "requests $requests_v  ${YELLOW}(CVE-2023-32681 — BUMP scenario)${RESET}"

# ── Done ───────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Reset complete.${RESET}\n"
printf   "${CYAN}  State: db empty, artifacts cleared.${RESET}\n"
printf   "${CYAN}  Planted: urllib3 ${YELLOW}2.3.0${CYAN} (BACKPORT)  requests ${YELLOW}2.28.2${CYAN} (BUMP)${RESET}\n"
printf   "${CYAN}  Run ${BOLD}./run.sh${RESET}${CYAN} to start the demo.${RESET}\n\n"
