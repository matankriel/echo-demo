#!/usr/bin/env bash
# Echo shim: intercepts pip install -r <file> and injects CVE constraints.
set -euo pipefail

GATEWAY="http://localhost:8000/resolve"
CONSTRAINTS_FILE="/tmp/echo_fix.txt"
ARTIFACTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/factory/artifacts"

# Find -r <file> in arguments
req_arg=""
args=("$@")
for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == "-r" ]]; then
        next=$((i + 1))
        if [[ $next -lt ${#args[@]} ]]; then
            req_arg="${args[$next]}"
            break
        fi
    fi
done

if [[ -z "$req_arg" ]]; then
    # No requirements file — pass through normally
    pip "$@"
    exit $?
fi

req_file=$(realpath "$req_arg")

DEP_CHECKER="$(cd "$(dirname "$0")" && pwd)/dep_checker.py"
if [[ -f "$DEP_CHECKER" ]]; then
    printf "\nshim: [dep-check] scanning for dependency conflicts...\n"
    python3 "$DEP_CHECKER" -r "$req_file" 2>&1 || true
    printf "\n"
fi

if [[ ! -f "$req_file" ]]; then
    echo "shim: requirements file not found: $req_file" >&2
    pip "$@"
    exit $?
fi

# Parse package==version or package>=version lines
declare -a packages
while IFS= read -r line; do
    # Skip comments and blanks
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue
    # Match package==version or package>=version
    re='^([A-Za-z0-9_.-]+)[>=]+([A-Za-z0-9_.*+-]+)'
    if [[ "$line" =~ $re ]]; then
        pkg="${BASH_REMATCH[1]}"
        ver="${BASH_REMATCH[2]}"
        packages+=("$pkg $ver")
    fi
done < "$req_file"

if [[ ${#packages[@]} -eq 0 ]]; then
    pip "$@"
    exit $?
fi

# Query gateway for each package
> "$CONSTRAINTS_FILE"
gateway_ok=true

for entry in "${packages[@]}"; do
    pkg="${entry%% *}"
    ver="${entry##* }"

    payload="{\"package\":\"$pkg\",\"version\":\"$ver\"}"
    response=$(curl -s --max-time 5 -X POST "$GATEWAY" \
        -H 'Content-Type: application/json' \
        -d "$payload" 2>/dev/null) || { gateway_ok=false; break; }

    if [[ -z "$response" ]]; then
        gateway_ok=false
        break
    fi

    constraint=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('constraint') or '')" 2>/dev/null || true)

    if [[ -n "$constraint" ]]; then
        echo "$constraint" >> "$CONSTRAINTS_FILE"
    fi
done

if [[ "$gateway_ok" == "false" ]]; then
    echo "shim: WARNING — gateway unreachable, running pip without CVE constraints." >&2
    pip "$@"
    exit $?
fi

if [[ -s "$CONSTRAINTS_FILE" ]]; then
    echo "shim: applying CVE constraints from $CONSTRAINTS_FILE"
    cat "$CONSTRAINTS_FILE"

    # Build resolved install list: constrained versions override pinned ones.
    # We cannot use -r req.txt -c constraints.txt because pip treats both as
    # hard requirements and conflicts when they disagree.
    resolved=()
    for entry in "${packages[@]}"; do
        pkg="${entry%% *}"
        ver="${entry##* }"
        constraint_line=$(grep -i "^${pkg}==" "$CONSTRAINTS_FILE" 2>/dev/null || echo "")
        if [[ -n "$constraint_line" ]]; then
            resolved+=("$constraint_line")
        else
            resolved+=("${pkg}==${ver}")
        fi
    done

    pip install "${resolved[@]}" --find-links "$ARTIFACTS_DIR"

    echo ""
    echo "shim: --- installed versions (echo-patched) ---"
    while IFS= read -r constraint_line; do
        [[ -z "${constraint_line// }" ]] && continue
        pkg_name="${constraint_line%%==*}"
        installed=$(pip show "$pkg_name" 2>/dev/null | awk '/^Version:/{print $2}')
        location=$(pip show "$pkg_name" 2>/dev/null | awk '/^Location:/{print $2}')
        echo "  $pkg_name==$installed  (from $location)"
    done < "$CONSTRAINTS_FILE"
    echo "shim: -----------------------------------------------"
else
    echo "shim: no CVE constraints found, running pip normally."
    pip "$@"
fi
