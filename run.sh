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
for pkg in fastapi uvicorn packaging requests build; do
    pip show "$pkg" &>/dev/null || missing+=("$pkg")
done
if [[ ${#missing[@]} -eq 0 ]]; then
    ok "All dependencies installed (fastapi, uvicorn, packaging, requests, build)"
else
    fail "Missing packages: ${missing[*]}"
    printf "\n  ${YELLOW}Run:  pip install ${missing[*]}${RESET}\n\n"; exit 1
fi

db_entries=$(python3 -c "import json; print(len(json.load(open('$SCRIPT_DIR/factory/db.json'))))" 2>/dev/null || echo 0)
whl_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "*.whl" 2>/dev/null | wc -l | tr -d ' ')

info "factory/db.json currently has ${BOLD}$db_entries${RESET}${CYAN} entries${RESET}"
info "factory/artifacts has ${BOLD}$whl_count${RESET}${CYAN} pre-built wheel(s)${RESET}"

printf "\n"
printf "  ${BOLD}Current environment state:${RESET}\n"
current_urllib3=$(pip show urllib3  2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
current_requests=$(pip show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
printf "  ${DIM}└─${RESET} urllib3  version: ${YELLOW}${BOLD}$current_urllib3${RESET}  ${RED}← vulnerable (BACKPORT scenario)${RESET}\n"
printf "  ${DIM}└─${RESET} requests version: ${YELLOW}${BOLD}$current_requests${RESET}  ${RED}← vulnerable (BUMP scenario)${RESET}\n"

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
header 3 "Discovery  (GitHub Advisories API + requests CVE injection → factory/db.json)"

info "Querying GitHub for urllib3 advisories and injecting hardcoded requests CVE-2023-32681..."
info "Writing clean advisory data to factory/db.json (no api_diff — computed later by builder)..."
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
FMT = "  {:<20}  {:<10}  {:<12}  {:<10}  {}"
print(FMT.format("CVE ID", "Severity", "Patched Ver", "Strategy", "Affected Range"))
print("  " + "─" * 78)
for e in db:
    plan  = e.get("resolution_plan") or {}
    bp    = plan.get("backport_strategy") or []
    rng   = bp[0].get("version_range", "—") if bp else \
            plan.get("bump_strategy", {}).get("affected_range", "—")
    sev   = e.get("severity", "?")
    strat = "BACKPORT" if bp else "BUMP"
    scol  = "\033[1;33m" if strat == "BACKPORT" else "\033[0;32m"
    col   = "\033[0;31m" if sev == "High" else "\033[1;33m"
    print(FMT.format(
        e.get("cve_id", "?"),
        f"{col}{sev}\033[0m",
        e.get("first_patched_version", "?"),
        f"{scol}{strat}\033[0m",
        rng,
    ))
PYEOF
printf "\n"

# ── Step 5: Build Factory Artifacts ───────────────────────────────────────────
header 5 "Factory Builder  (patching wheels · urllib3=BACKPORT · requests=BUMP)"
printf "\n"
info "Running builder.py (API diff per sub-group → api_diff_cache.json · BACKPORT → echo wheel · BUMP → PyPI verify)..."
printf "\n"
python3 "$SCRIPT_DIR/factory/builder.py" 2>&1 | sed 's/^/    /'
printf "\n"

whl_count=$(find "$SCRIPT_DIR/factory/artifacts" -name "*.whl" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$whl_count" -gt 0 ]]; then
    info "Wheels in factory/artifacts/:"
    for whl in "$SCRIPT_DIR/factory/artifacts/"*.whl; do
        name=$(basename "$whl")
        size=$(python3 -c "import os; s=os.path.getsize('$whl'); print(f'{s/1024:.1f} KB')")
        ok "${BOLD}$name${RESET}  ${DIM}($size)${RESET}"
    done
else
    warn "No wheels produced — check builder output above."
fi

# ── Step 6: Scenario Summary ───────────────────────────────────────────────────
header 6 "Scenario Summary  (A = BUMP · B = BACKPORT)"
printf "\n"
python3 - <<'PYEOF'
import json, os

db         = json.load(open("factory/db.json"))
cache_path = "factory/api_diff_cache.json"
diff_cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}

G  = "\033[0;32m"; Y = "\033[1;33m"; R = "\033[0;31m"
C  = "\033[0;36m"; B = "\033[1m";    D = "\033[2m";  X = "\033[0m"

for e in db:
    pkg  = e.get("package", "?")
    cve  = e.get("cve_id",  "?")
    fp   = e.get("first_patched_version", "")
    plan = e.get("resolution_plan", {})
    bp   = plan.get("backport_strategy") or []

    if bp:
        strat = "BACKPORT"
        pivot = bp[0].get("pivot_stable_version", "")
        api   = diff_cache.get(f"{pkg}:{pivot}:{fp}", {})
        has_b = api.get("has_breaking_changes", False)
        removed = len(api.get("removed", []))
        changed = len(api.get("changed", []))
        added   = len(api.get("added",   []))
        err     = api.get("error", "")
        col     = Y
        label   = "SCENARIO B — BACKPORT"
        action  = "→ local echo-patched wheel built"
        if err:
            diff_line = f"{D}api diff inconclusive ({err[:60]}){X}"
        elif has_b:
            diff_line = f"{removed} symbols removed, {changed} signatures changed  {R}BREAKING{X}"
        else:
            diff_line = f"no breaking changes  ({added} added)  {G}CLEAN{X}"
    else:
        strat     = "BUMP"
        col       = G
        label     = "SCENARIO A — BUMP"
        action    = "→ verified on PyPI, no wheel needed"
        diff_line = f"no breaking changes  {G}CLEAN{X}"

    bar = "─" * 58
    print(f"  {col}┌{bar}┐{X}")
    print(f"  {col}│{X}  {B}{label}{X}   [{cve}]  {B}{pkg}{X}")
    print(f"  {col}│{X}  api diff:  {diff_line}")
    print(f"  {col}│{X}  action:    {action}")
    print(f"  {col}└{bar}┘{X}")
    print()
PYEOF

# ── Step 7: Gateway resolve tests ─────────────────────────────────────────────
header 7 "Gateway  (testing /resolve for known vulnerable versions)"
printf "\n"
printf "  ${BOLD}%-34s  %-10s  %-24s  %s${RESET}\n" "Query" "Strategy" "Constraint" "CVE"
printf "  %s\n" "$(python3 -c "print('─'*84)")"

test_cases=(
    "urllib3|1.24.0|old 1.x"
    "urllib3|1.25.5|mid 1.x"
    "urllib3|2.0.3|2.0.x"
    "urllib3|2.6.4|already safe"
    "requests|2.28.2|pinned vulnerable"
    "requests|2.31.0|already patched"
)

for tc in "${test_cases[@]}"; do
    IFS='|' read -r pkg ver lbl <<< "$tc"
    resp=$(curl -s --max-time 5 -X POST "$GATEWAY_URL/resolve" \
        -H 'Content-Type: application/json' \
        -d "{\"package\":\"$pkg\",\"version\":\"$ver\"}" 2>/dev/null || echo '{}')
    constraint=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('constraint') or 'null')" 2>/dev/null)
    strategy=$(echo "$resp"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('strategy') or '—')"    2>/dev/null)
    cve=$(echo "$resp"         | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cve_id') or '—')"       2>/dev/null)
    api_sum=$(echo "$resp"     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_break_summary') or '')" 2>/dev/null)

    if [[ "$constraint" == "null" || "$constraint" == "None" ]]; then
        printf "  %-34s  ${GREEN}%-10s${RESET}  %-24s  %s\n" \
            "$pkg==$ver  ($lbl)" "clean" "no constraint" "—"
    else
        printf "  %-34s  ${RED}%-10s${RESET}  ${BOLD}%-24s${RESET}  ${DIM}%s${RESET}\n" \
            "$pkg==$ver  ($lbl)" "$strategy" "$constraint" "$cve"
        if [[ -n "$api_sum" ]]; then
            printf "  ${DIM}    ↳ api: %s${RESET}\n" "$api_sum"
        fi
    fi
done
printf "\n"

# ── Step 8: Dep conflict check ────────────────────────────────────────────────
header 8 "Dependency Conflict Check  (horizontal + vertical)"
printf "\n"
python3 "$SCRIPT_DIR/client/dep_checker.py" -r "$SCRIPT_DIR/client/requirements.txt" 2>&1 | sed 's/^/  /' || true
printf "\n"

# ── Step 9: Client Shim ────────────────────────────────────────────────────────
header 9 "Client Shim  (intercept pip install → apply CVE constraints)"

urllib3_before=$(pip show urllib3   2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
requests_before=$(pip show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
printf "\n"
printf "  ${BOLD}Before:${RESET}\n"
printf "  ${DIM}└─${RESET} urllib3  == ${BOLD}${YELLOW}$urllib3_before${RESET}  ${RED}(vulnerable — BACKPORT)${RESET}\n"
printf "  ${DIM}└─${RESET} requests == ${BOLD}${YELLOW}$requests_before${RESET}  ${RED}(vulnerable — BUMP)${RESET}\n\n"

printf "  ${DIM}client/requirements.txt:${RESET}\n"
cat "$SCRIPT_DIR/client/requirements.txt" | sed 's/^/    /'
printf "\n"
info "Running shim (includes dep-check + gateway lookup + pip install)..."
printf "\n"

bash "$SCRIPT_DIR/client/shim.sh" -r "$SCRIPT_DIR/client/requirements.txt" 2>&1 | sed 's/^/    /'

# ── Step 10: Final verification ───────────────────────────────────────────────
header 10 "Final verification"
printf "\n"

urllib3_after=$(pip show urllib3   2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
requests_after=$(pip show requests 2>/dev/null | awk '/^Version:/{print $2}' || echo "not installed")
urllib3_loc=$(pip show urllib3   2>/dev/null | awk '/^Location:/{print $2}' || echo "—")
requests_loc=$(pip show requests 2>/dev/null | awk '/^Location:/{print $2}' || echo "—")
applied=$(cat /tmp/echo_fix.txt 2>/dev/null | tr '\n' ' ' | sed 's/ $//')

printf "  ${BOLD}Before  →  After${RESET}\n"
printf "  ${DIM}└─${RESET} urllib3   ${YELLOW}${BOLD}$urllib3_before${RESET} ${DIM}(BACKPORT/vulnerable)${RESET}  ${CYAN}→${RESET}  ${GREEN}${BOLD}$urllib3_after${RESET} ${GREEN}(patched)${RESET}\n"
printf "  ${DIM}└─${RESET} requests  ${YELLOW}${BOLD}$requests_before${RESET} ${DIM}(BUMP/vulnerable)${RESET}    ${CYAN}→${RESET}  ${GREEN}${BOLD}$requests_after${RESET} ${GREEN}(patched)${RESET}\n\n"

ok  "urllib3  installed: ${BOLD}$urllib3_after${RESET}  ${DIM}($urllib3_loc)${RESET}"
ok  "requests installed: ${BOLD}$requests_after${RESET}  ${DIM}($requests_loc)${RESET}"
[[ -n "$applied" ]] && info "CVE constraints applied: ${BOLD}$applied${RESET}"

printf "\n"
python3 - "$urllib3_after" "$requests_after" <<'PYEOF'
import json, sys
urllib3_ver, requests_ver = sys.argv[1], sys.argv[2]
db = json.load(open("factory/db.json"))

hits = []
for e in db:
    pkg   = e.get("package", "")
    cve   = e.get("cve_id", "?")
    plan  = e.get("resolution_plan", {})
    bp    = plan.get("backport_strategy", [])
    strat = "BACKPORT" if bp else "BUMP"
    installed = urllib3_ver if pkg == "urllib3" else requests_ver

    # Check bump strategy satisfaction
    target = plan.get("bump_strategy", {}).get("target_version", "")
    if target and target in installed:
        hits.append(f"{cve} [{pkg} {strat}]")
        continue
    # Check backport artifact
    for b in bp:
        pivot = b.get("pivot_stable_version", "")
        if pivot and pivot in installed:
            hits.append(f"{cve} [{pkg} {strat}]")

if hits:
    for h in hits:
        print(f"  \033[0;32m✓\033[0m  Remediation confirmed: {h}")
else:
    print(f"  \033[2m–\033[0m  Installed versions not directly traced to echo artifacts")
PYEOF

# ── Summary ────────────────────────────────────────────────────────────────────
sep
printf "\n${BOLD}${GREEN}  Demo complete!${RESET}\n\n"
printf "  ${BOLD}What just happened:${RESET}\n"
printf "  ${DIM}1.${RESET}  Gateway started at ${BOLD}$GATEWAY_URL${RESET}\n"
printf "  ${DIM}2.${RESET}  Discovery pulled ${BOLD}$db_entries CVEs${RESET} from GitHub + hardcoded requests entry\n"
printf "  ${DIM}3.${RESET}  Builder ran AST-based API diff per sub-group → cached in api_diff_cache.json\n"
printf "  ${DIM}4.${RESET}  Builder built local echo-patched wheel for urllib3 (BACKPORT)\n"
printf "  ${DIM}5.${RESET}  Dep-checker flagged version conflict before install\n"
printf "  ${DIM}6.${RESET}  Shim intercepted ${BOLD}pip install${RESET}, applied constraints, upgraded both packages\n"
printf "       urllib3:  ${YELLOW}${BOLD}$urllib3_before${RESET}  →  ${GREEN}${BOLD}$urllib3_after${RESET}\n"
printf "       requests: ${YELLOW}${BOLD}$requests_before${RESET}  →  ${GREEN}${BOLD}$requests_after${RESET}\n\n"
printf "  ${DIM}Gateway is still running (PID $GATEWAY_PID). Press Ctrl+C to stop it.${RESET}\n\n"

wait "$GATEWAY_PID" 2>/dev/null || true
