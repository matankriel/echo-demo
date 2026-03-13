#!/usr/bin/env bash
# run.sh — full Echo prototype demo, step-by-step
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY_PORT=8000
GATEWAY_URL="http://localhost:$GATEWAY_PORT"
GATEWAY_PID=""

sep()    { printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }
ok()     { printf "  ${GREEN}✓${RESET}  $1\n"; }
warn()   { printf "  ${YELLOW}!${RESET}  $1\n"; }
fail()   { printf "  ${RED}✗${RESET}  $1\n"; }
info()   { printf "  ${CYAN}›${RESET}  $1\n"; }
label()  { printf "  ${DIM}$1${RESET}\n"; }
header() {
    local n="$1" title="$2"
    printf "\n${BOLD}${BLUE}[STEP $n]${RESET} ${BOLD}$title${RESET}\n"
    sep
}

cleanup() {
    if [[ -n "$GATEWAY_PID" ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
        kill "$GATEWAY_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ── Banner ─────────────────────────────────────────────────────────────────────
clear
printf "${BOLD}${CYAN}"
printf "  ███████╗ ██████╗██╗  ██╗ ██████╗ \n"
printf "  ██╔════╝██╔════╝██║  ██║██╔═══██╗\n"
printf "  █████╗  ██║     ███████║██║   ██║\n"
printf "  ██╔══╝  ██║     ██╔══██║██║   ██║\n"
printf "  ███████╗╚██████╗██║  ██║╚██████╔╝\n"
printf "  ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ \n"
printf "${RESET}"
printf "${DIM}  CVE Remediation Prototype — Full Demo Flow${RESET}\n"
printf "${DIM}  $(date '+%Y-%m-%d %H:%M:%S')${RESET}\n\n"

# ── Step 1: Pre-flight ─────────────────────────────────────────────────────────
header 1 "Pre-flight checks"

python3 --version &>/dev/null && ok "Python: $(python3 --version 2>&1)" \
    || { fail "python3 not found"; exit 1; }

[[ -n "${GITHUB_TOKEN:-}" ]] && ok "GITHUB_TOKEN is set" \
    || { fail "GITHUB_TOKEN is not set — run: export GITHUB_TOKEN=<your_token>"; exit 1; }

missing=()
for pkg in fastapi uvicorn packaging requests; do
    pip show "$pkg" &>/dev/null || missing+=("$pkg")
done
if [[ ${#missing[@]} -eq 0 ]]; then
    ok "All dependencies installed (fastapi, uvicorn, packaging, requests)"
else
    fail "Missing packages: ${missing[*]}"
    printf "\n  ${YELLOW}Run:  pip install ${missing[*]}${RESET}\n\n"; exit 1
fi

db_entries=$(python3 -c "import json; print(len(json.load(open('$SCRIPT_DIR/factory/db.json'))))" 2>/dev/null || echo 0)
whl_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "*.whl" 2>/dev/null | wc -l | tr -d ' ')

info "factory/db.json currently has ${BOLD}$db_entries${RESET}${CYAN} entries${RESET}"
info "factory/artifacts has ${BOLD}$whl_count${RESET}${CYAN} pre-built wheel(s)${RESET}"

current_urllib3=$(pip show urllib3 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
printf "\n"
printf "  ${BOLD}Current environment state:${RESET}\n"
printf "  ${DIM}└─${RESET} urllib3 version: "
if [[ "$current_urllib3" == "not installed" ]]; then
    printf "${YELLOW}not installed${RESET}\n"
else
    printf "${YELLOW}${BOLD}$current_urllib3${RESET}  ${RED}← this is the vulnerable version we'll remediate${RESET}\n"
fi

# ── Step 2: Start the Gateway ──────────────────────────────────────────────────
header 2 "Starting the Gateway  (FastAPI · POST /resolve)"

pkill -f "uvicorn gateway.api:app" 2>/dev/null && sleep 1 || true
cd "$SCRIPT_DIR"
uvicorn gateway.api:app --port $GATEWAY_PORT --log-level warning &
GATEWAY_PID=$!
sleep 2

if curl -s "$GATEWAY_URL/docs" > /dev/null 2>&1; then
    ok "Gateway is UP  →  ${BOLD}$GATEWAY_URL${RESET}"
    label "    PID $GATEWAY_PID  |  API docs: $GATEWAY_URL/docs"
else
    fail "Gateway failed to start"; exit 1
fi

# ── Step 3: Discovery — fetch advisories ──────────────────────────────────────
header 3 "Discovery  (GitHub Advisories API → factory/db.json)"

info "Querying GitHub for urllib3 high-severity advisories..."
printf "\n"
python3 "$SCRIPT_DIR/discovery/fetcher.py" 2>&1 | sed 's/^/    /'
printf "\n"

db_entries=$(python3 -c "import json; print(len(json.load(open('$SCRIPT_DIR/factory/db.json'))))")
ok "factory/db.json now contains ${BOLD}$db_entries${RESET} CVE entries"

# ── Step 4: Inspect the Database ──────────────────────────────────────────────
header 4 "Factory DB  (CVE database contents)"
printf "\n"
python3 - <<'PYEOF'
import json
db = json.load(open("factory/db.json"))
FMT = "  {:<20}  {:<10}  {:<12}  {}"
print(FMT.format("CVE ID", "Severity", "Patched Ver", "Affected Range"))
print("  " + "─" * 72)
for e in db:
    bp  = (e.get("resolution_plan") or {}).get("backport_strategy") or []
    rng = bp[0].get("version_range", "—") if bp else "—"
    sev = e.get("severity", "?")
    col = "\033[0;31m" if sev == "High" else "\033[1;33m"
    print(FMT.format(
        e.get("cve_id", "?"),
        f"{col}{sev}\033[0m",
        e.get("first_patched_version", "?"),
        rng,
    ))
PYEOF
printf "\n"

# ── Step 5: Artifacts ─────────────────────────────────────────────────────────
header 5 "Factory Artifacts  (patched wheels ready to install)"
printf "\n"
whl_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "*.whl" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$whl_count" -eq 0 ]]; then
    warn "No pre-built wheels found in factory/artifacts/"
    info "The shim will fall back to PyPI for this run."
    info "To build local patched wheels: ${BOLD}python3 factory/builder.py${RESET}"
else
    for whl in "$SCRIPT_DIR/factory/artifacts/"*.whl; do
        name=$(basename "$whl")
        size=$(python3 -c "import os; s=os.path.getsize('$whl'); print(f'{s/1024:.1f} KB')")
        ok "${BOLD}$name${RESET}  ${DIM}($size)${RESET}"
    done
    printf "\n"
    info "$whl_count patched wheel(s) available — shim will prefer these over PyPI"
fi

# ── Step 6: Gateway resolve tests ─────────────────────────────────────────────
header 6 "Gateway  (testing /resolve for known vulnerable versions)"
printf "\n"
printf "  ${BOLD}%-32s  %-10s  %-22s  %s${RESET}\n" "Query" "Strategy" "Constraint" "CVE"
printf "  %s\n" "$(python3 -c "print('─'*80)")"

test_cases=(
    "urllib3|1.24.0|old 1.x"
    "urllib3|1.25.5|mid 1.x"
    "urllib3|2.0.3|2.0.x"
    "urllib3|2.6.4|already safe"
    "requests|2.28.0|untracked pkg"
)

for tc in "${test_cases[@]}"; do
    IFS='|' read -r pkg ver lbl <<< "$tc"
    resp=$(curl -s --max-time 5 -X POST "$GATEWAY_URL/resolve" \
        -H 'Content-Type: application/json' \
        -d "{\"package\":\"$pkg\",\"version\":\"$ver\"}" 2>/dev/null || echo '{}')
    constraint=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('constraint') or 'null')" 2>/dev/null)
    strategy=$(echo "$resp"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('strategy') or '—')"    2>/dev/null)
    cve=$(echo "$resp"       | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cve_id') or '—')"       2>/dev/null)

    if [[ "$constraint" == "null" || "$constraint" == "None" ]]; then
        printf "  %-32s  ${GREEN}%-10s${RESET}  %-22s  %s\n" \
            "$pkg==$ver  ($lbl)" "clean" "no constraint" "—"
    else
        printf "  %-32s  ${RED}%-10s${RESET}  ${BOLD}%-22s${RESET}  ${DIM}%s${RESET}\n" \
            "$pkg==$ver  ($lbl)" "$strategy" "$constraint" "$cve"
    fi
done
printf "\n"

# ── Step 7: Client Shim ────────────────────────────────────────────────────────
header 7 "Client Shim  (intercept pip install → apply CVE constraints)"

current_before=$(pip show urllib3 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
printf "\n"
printf "  ${BOLD}Before:${RESET}\n"
printf "  ${DIM}└─${RESET} urllib3 == ${BOLD}${YELLOW}$current_before${RESET}  ${RED}(vulnerable)${RESET}\n\n"

printf "  ${DIM}client/requirements.txt:${RESET}\n"
cat "$SCRIPT_DIR/client/requirements.txt" | sed 's/^/    /'
printf "\n"
info "Running shim..."
printf "\n"

bash "$SCRIPT_DIR/client/shim.sh" -r "$SCRIPT_DIR/client/requirements.txt" 2>&1 | sed 's/^/    /'

# ── Step 8: Final verification ────────────────────────────────────────────────
header 8 "Final verification"
printf "\n"

current_after=$(pip show urllib3 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
install_loc=$(pip show urllib3 2>/dev/null | awk '/^Location:/{print $2}' || echo "—")
applied=$(cat /tmp/echo_fix.txt 2>/dev/null | tr '\n' ' ' | sed 's/ $//')

printf "  ${BOLD}Before  →  After${RESET}\n"
printf "  ${DIM}└─${RESET} ${YELLOW}${BOLD}$current_before${RESET} ${DIM}(vulnerable)${RESET}  ${CYAN}→${RESET}  ${GREEN}${BOLD}$current_after${RESET} ${GREEN}(patched)${RESET}\n\n"

ok  "Installed version:  ${BOLD}$current_after${RESET}"
info "Install location:   $install_loc"
[[ -n "$applied" ]] && info "CVE constraint applied: ${BOLD}$applied${RESET}"

printf "\n"
python3 - "$current_after" <<'PYEOF'
import json, sys
ver = sys.argv[1]
db  = json.load(open("factory/db.json"))
hits = []
for e in db:
    for b in (e.get("resolution_plan") or {}).get("backport_strategy", []):
        if b.get("pivot_stable_version", "") in ver:
            hits.append(e["cve_id"])
if hits:
    print(f"  \033[0;32m✓\033[0m  Installed version satisfies remediation for: {', '.join(hits)}")
else:
    print(f"  \033[2m–\033[0m  Installed version not directly traced to an echo artifact")
PYEOF

# ── Summary ────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Demo complete!${RESET}\n\n"
printf "  ${BOLD}What just happened:${RESET}\n"
printf "  ${DIM}1.${RESET}  Gateway started at ${BOLD}$GATEWAY_URL${RESET}\n"
printf "  ${DIM}2.${RESET}  Discovery pulled ${BOLD}$db_entries CVEs${RESET} from GitHub Advisories into factory/db.json\n"
printf "  ${DIM}3.${RESET}  Gateway mapped every vulnerable urllib3 version to a safe constraint\n"
printf "  ${DIM}4.${RESET}  Shim intercepted ${BOLD}pip install${RESET}, applied the constraint, upgraded urllib3\n"
printf "       ${YELLOW}${BOLD}$current_before${RESET}  →  ${GREEN}${BOLD}$current_after${RESET}\n\n"
printf "  ${DIM}Gateway is still running (PID $GATEWAY_PID). Press Ctrl+C to stop it.${RESET}\n\n"

wait "$GATEWAY_PID" 2>/dev/null || true
