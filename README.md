# Echo — CVE Remediation Prototype

Echo is a prototype system that **automatically detects and remediates vulnerable Python dependencies** at install time. When a developer runs `pip install`, Echo's client shim intercepts the request, queries a CVE gateway, and transparently upgrades any vulnerable package to a safe, patched version — without requiring the developer to change anything about their workflow.

---

## The Problem

Security teams know that vulnerable package versions are constantly being shipped in production. The gap between "CVE published" and "dependency actually updated" can be weeks or months. Existing tools (Dependabot, Snyk, etc.) notify developers but still require human action per-repo. Echo removes that friction entirely.

---

## How It Works

```
Developer runs:   pip install -r requirements.txt
                         │
                         ▼
              ┌─────────────────────┐
              │   Echo Client Shim  │  ← intercepts pip
              └──────────┬──────────┘
                         │  POST /resolve  { package, version }
                         ▼
              ┌─────────────────────┐
              │   Echo Gateway API  │  ← FastAPI service
              └──────────┬──────────┘
                         │  queries
                         ▼
              ┌──────────────────────────┐
              │   factory/db.json        │  ← raw CVE advisory data
              │   factory/api_diff_cache │  ← API diff results (per sub-group)
              └──────────────────────────┘
                         │
                         ▼
              pip install urllib3==2.6.2+echo1 requests==2.31.0
                --find-links factory/artifacts  ← local patched wheels
```

### Data Flow

```
fetcher.py  →  db.json              (raw advisory data only — no computed fields)
builder.py  →  api_diff_cache.json  (keyed by "package:pivot:first_patched")
gateway     reads both at request time
```

`db.json` contains only clean advisory data fetched from GitHub. The API diff analysis (which determines whether a fix is breaking) is computed by the builder during the wheel-building step and stored separately in `api_diff_cache.json`.

### Five Modules

| Module | Path | Role |
|---|---|---|
| **Discovery** | `discovery/fetcher.py` | Queries the GitHub Security Advisories API and writes clean CVE entries to `factory/db.json` |
| **API Checker** | `factory/api_checker.py` | AST-based API compatibility checker — compares public symbols between two package versions |
| **Factory Builder** | `factory/builder.py` | Downloads sdists, computes AST API diff per sub-group (cached in `api_diff_cache.json`), patches source, builds `.whl` artifacts |
| **Gateway** | `gateway/api.py` | FastAPI service exposing `POST /resolve` — reads `db.json` + `api_diff_cache.json`, maps a package + version to a safe constraint |
| **Client Shim** | `client/shim.sh` | Bash wrapper around pip — runs dep-check, queries the gateway, and installs constrained versions |

---

## Quick Start

### Prerequisites

- Python 3.10+
- A GitHub personal access token with `public_repo` scope (for the Advisories API)

### 1. Install dependencies

```bash
pip install fastapi uvicorn packaging requests build
```

### 2. Set your GitHub token

```bash
export GITHUB_TOKEN=your_token_here
```

### 3. Reset the environment (fresh demo state)

```bash
bash reset.sh
```

Clears the CVE database, removes built artifacts, wipes `api_diff_cache.json`, and plants known-vulnerable versions of urllib3 and requests.

### 4. Run the full demo flow

```bash
bash run.sh
```

The script walks through every step with clear terminal output:

1. **Pre-flight** — verifies dependencies and shows the current (vulnerable) package state
2. **Gateway** — starts the FastAPI service on `:8000`
3. **Discovery** — fetches live urllib3 CVEs from GitHub Advisories into `factory/db.json`
4. **DB inspection** — table of all CVE entries, severity, strategy, and affected ranges
5. **Builder** — computes AST API diff per sub-group → `api_diff_cache.json`; builds patched wheels
6. **Scenario summary** — one box per CVE: BUMP (green) or BACKPORT (yellow) with BREAKING/CLEAN
7. **Gateway tests** — fires sample queries to show which versions are flagged and which are safe
8. **Dep-conflict check** — catches `urllib3==2.3.0` violating `requests`' `<1.27` requirement
9. **Client shim** — runs `pip install -r client/requirements.txt` through the shim; shows upgrade
10. **Verification** — confirms the before/after version and which CVEs were remediated

---

## Running Steps Individually

### Start the Gateway

```bash
uvicorn gateway.api:app --port 8000
```

### Fetch CVE advisories

```bash
python3 discovery/fetcher.py
```

Queries GitHub's `/advisories` endpoint for high-severity pip advisories affecting urllib3, injects a hardcoded `requests` entry (CVE-2023-32681), and writes **clean advisory data only** to `factory/db.json`. No API diff is computed here.

### Build patched wheels

```bash
python3 factory/builder.py
```

For each CVE entry in `db.json`, the builder:

1. Downloads the vulnerable (pivot) and patched sdists from PyPI
2. **Computes AST API diff** between pivot → patched, caches result in `factory/api_diff_cache.json` keyed by `"package:pivot:first_patched"`
3. Diffs the two source trees to generate a `.patch` file
4. Applies the security patch to the pivot source
5. Bumps the version string to `<pivot>+echo1`
6. Builds a `.whl` and saves it to `factory/artifacts/`

The builder prints a scenario banner for each entry (`SCENARIO A — BUMP` or `SCENARIO B — BACKPORT`) and an API diff result line (`BREAKING` or `clean`) per sub-group.

> The builder skips entries whose artifact wheel already exists in `factory/artifacts/`. Re-run `reset.sh` to force a full rebuild.

### Test the Gateway directly

```bash
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d '{"package":"urllib3","version":"1.24.0"}' | python3 -m json.tool
```

**Vulnerable version response:**
```json
{
  "constraint": "urllib3==2.6.2+echo1",
  "strategy": "BACKPORT",
  "cve_id": "CVE-2026-21441",
  "api_scenario": "BACKPORT",
  "api_break_summary": "0 removed, 1 changed, 0 added — BREAKING"
}
```

**Safe version response:**
```json
{
  "constraint": null,
  "strategy": null,
  "cve_id": null,
  "api_scenario": null,
  "api_break_summary": null
}
```

### Run the Client Shim

```bash
bash client/shim.sh -r client/requirements.txt
```

The shim:
1. Runs `dep_checker.py` to surface any dependency conflicts in the requirements file
2. Parses `package==version` lines and queries the gateway for each
3. Builds a **resolved install list** — constrained versions replace their pinned counterparts
4. Runs `pip install <resolved_packages> --find-links factory/artifacts`
5. If the gateway is unreachable: warns to stderr and runs pip normally (fail-open — never blocks a developer)

> The shim does **not** use `pip install -r file -c constraints` because pip treats both as hard requirements and conflicts when they disagree. It builds an overridden list instead.

---

## Gateway API Reference

### `POST /resolve`

**Request body:**
```json
{ "package": "urllib3", "version": "1.24.0" }
```

**Response fields:**

| Field | Description |
|---|---|
| `constraint` | Install spec to enforce (e.g. `urllib3==2.6.2+echo1`), or `null` if safe |
| `strategy` | `"BACKPORT"` or `"BUMP"`, or `null` |
| `cve_id` | The matching CVE ID, or `null` |
| `api_scenario` | Same as `strategy` — for display |
| `api_break_summary` | Human-readable API diff summary from `api_diff_cache.json`, or `null` |

**Strategies:**
- `BACKPORT` — the CVE entry has a `backport_strategy`; Echo built a local patched wheel
- `BUMP` — the CVE entry has only a `bump_strategy`; the fix is a safe minor/patch upgrade on PyPI

Interactive API docs available at `http://localhost:8000/docs` when the gateway is running.

---

## Project Structure

```
echo/
├── client/
│   ├── dep_checker.py       # standalone dependency conflict checker
│   ├── shim.sh              # pip wrapper — queries gateway, injects CVE constraints
│   └── requirements.txt     # demo requirements file (urllib3==2.3.0, requests==2.28.2)
├── discovery/
│   └── fetcher.py           # GitHub Advisories → factory/db.json (clean advisory data)
├── factory/
│   ├── api_checker.py       # AST-based API diff between two package versions
│   ├── builder.py           # api_diff per sub-group → api_diff_cache.json; builds .whl artifacts
│   ├── db.json              # CVE advisory database (raw data, no computed fields)
│   ├── api_diff_cache.json  # API diff results keyed by "package:pivot:first_patched" [runtime]
│   └── artifacts/           # patched wheels + patch files [runtime]
├── gateway/
│   └── api.py               # FastAPI /resolve endpoint (reads db.json + api_diff_cache.json)
├── run.sh                   # full demo flow (10 steps)
├── reset.sh                 # resets environment to clean demo state
└── README.md
```

> Files marked `[runtime]` are generated at run time and not committed to the repository.

---

## Design Decisions

**`api_diff` lives in its own cache, not in `db.json`** — `db.json` contains only raw advisory data fetched from GitHub. Computed/derived data (API diffs) is stored separately in `api_diff_cache.json`, keyed by `"package:pivot:first_patched"`. This keeps the advisory database clean and makes the API diff granularity match the sub-group model (one diff per `(package, pivot, first_patched)` triple, not one per CVE).

**Strategy is derived from structure, not from api_diff** — Whether a CVE entry uses BACKPORT or BUMP is determined by the presence of `backport_strategy` in `resolution_plan`. The `api_diff` results in the cache are informational (surfaced in gateway responses) but do not drive routing decisions.

**Fail-open shim** — If the gateway is unreachable, the shim falls back to running pip normally. It never blocks a developer's workflow; security is additive, not a hard gate.

**Constraint resolution overrides pinned versions** — When constraints and pinned versions conflict (e.g. `urllib3==2.3.0` in requirements vs `urllib3==2.6.2+echo1` from the gateway), the shim builds a new resolved install list where constrained versions win. Standard `pip install -r ... -c ...` cannot resolve this because pip treats both as hard requirements.

**Local artifacts via `--find-links`** — When Echo builds a patched `+echo1` wheel, pip resolves it from the local artifacts directory instead of PyPI. The fix is fully self-contained and works without internet access once the wheels are built.

**CVE database is plain JSON** — `factory/db.json` is a flat JSON array. Simple to inspect, diff, audit, and extend. No database process required.

**Gateway is stateless** — The gateway reads `db.json` and `api_diff_cache.json` on every request. Changes to either file take effect immediately without a restart.

---

## Current Coverage

| CVE | Package | Affected Range | Strategy | Patched Wheel |
|---|---|---|---|---|
| CVE-2026-21441 | urllib3 | >= 1.22, < 2.6.3 | BACKPORT | `urllib3-2.6.2+echo1` |
| CVE-2025-66471 | urllib3 | >= 1.0, < 2.6.0 | BACKPORT | `urllib3-2.5.0+echo1` |
| CVE-2025-66418 | urllib3 | >= 1.24, < 2.6.0 | BACKPORT | `urllib3-2.5.0+echo1` |
| CVE-2023-43804 | urllib3 | >= 2.0.0, < 2.0.6 | BACKPORT | `urllib3-2.0.5+echo1` |
| CVE-2021-33503 | urllib3 | >= 1.25.4, < 1.26.5 | BACKPORT | `urllib3-1.26.4+echo1` |
| CVE-2020-7212  | urllib3 | >= 1.25.2, <= 1.25.7 | BACKPORT | `urllib3-1.25.7+echo1` |
| CVE-2019-11324 | urllib3 | < 1.24.2 | BACKPORT | `urllib3-1.24.1+echo1` |
| CVE-2023-32681 | requests | >= 2.1.0, < 2.31.0 | BUMP | _(PyPI: requests==2.31.0)_ |

---

## Prototype Scope

This is a proof-of-concept. Current limitations:

- **urllib3 + requests only** — the discovery and builder are scoped to these two packages. Extending to other packages requires adding ecosystem entries to the fetcher and re-running the builder.
- **No auth on the gateway** — the API has no authentication. In production, it would sit behind mTLS or an internal service mesh.
- **Shim is Bash** — the client shim works on macOS and Linux. A production version would be a pip plugin (`pip install echo-shim`).
- **AST diff is heuristic** — the API checker compares public function/class names and required parameters using Python's `ast` module. It does not resolve imports or track re-exports, so results are approximate.
