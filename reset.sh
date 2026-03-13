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

# ── 3. Clear artifacts ─────────────────────────────────────────────────────────
sep
printf "${BOLD}[3/5] Clearing factory/artifacts${RESET}\n"
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

# ── 4. Clear shim temp file ────────────────────────────────────────────────────
sep
printf "${BOLD}[4/5] Clearing shim temp files${RESET}\n"
if [[ -f /tmp/echo_fix.txt ]]; then
    rm -f /tmp/echo_fix.txt
    ok "Removed /tmp/echo_fix.txt"
else
    skip "/tmp/echo_fix.txt did not exist"
fi

# ── 5. Plant a known-vulnerable urllib3 ───────────────────────────────────────
sep
printf "${BOLD}[5/5] Installing vulnerable urllib3==2.3.0 (demo \"before\" state)${RESET}\n"
pip install "urllib3==2.3.0" --quiet 2>&1
installed=$(pip show urllib3 | awk '/^Version:/{print $2}')
ok "urllib3 $installed installed  ${YELLOW}(known vulnerable — falls in CVE-2026-21441 range >= 1.22, < 2.6.3)${RESET}"

# ── Done ───────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Reset complete.${RESET}\n"
printf   "${CYAN}  State: db empty, artifacts cleared, urllib3 ${YELLOW}2.3.0 (vulnerable)${CYAN} planted.${RESET}\n"
printf   "${CYAN}  Run ${BOLD}./run.sh${RESET}${CYAN} to start the demo.${RESET}\n\n"
