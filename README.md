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
              ┌─────────────────────┐
              │   Factory DB        │  ← CVE database (db.json)
              │   (factory/db.json) │     populated by Discovery
              └─────────────────────┘
                         │
                         ▼
              pip install -r requirements.txt
                -c /tmp/echo_fix.txt          ← constraint injected
                --find-links factory/artifacts ← local patched wheels
```

### Four Modules

| Module | Path | Role |
|---|---|---|
| **Discovery** | `discovery/fetcher.py` | Queries the GitHub Security Advisories API and writes CVE entries to `factory/db.json` |
| **Factory DB** | `factory/db.json` | JSON database of CVE entries — affected versions, patch strategies, artifact metadata |
| **Factory Builder** | `factory/builder.py` | Downloads vulnerable + patched sdists from PyPI, diffs them, applies patches, and builds local `.whl` artifacts |
| **Gateway** | `gateway/api.py` | FastAPI service exposing `POST /resolve` — maps a package + version to a safe constraint |
| **Client Shim** | `client/shim.sh` | Bash wrapper around pip that injects CVE constraints transparently |

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

This clears the CVE database, removes any built artifacts, and plants a known-vulnerable version of urllib3 to make the remediation visible.

### 4. Run the full demo flow

```bash
bash run.sh
```

The script walks through every step with clear output:

1. **Pre-flight** — verifies dependencies and shows the current (vulnerable) package state
2. **Gateway** — starts the FastAPI service on `:8000`
3. **Discovery** — fetches live urllib3 CVEs from GitHub Advisories into `factory/db.json`
4. **DB inspection** — prints a table of all CVE entries, severity, and affected ranges
5. **Artifacts** — lists any pre-built patched wheels in `factory/artifacts/`
6. **Gateway tests** — fires sample queries to show which versions are flagged and which are clean
7. **Shim** — runs `pip install -r client/requirements.txt` through the shim, showing the upgrade
8. **Verification** — confirms the before/after version and which CVE was remediated

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

Queries GitHub's `/advisories` endpoint for high-severity pip advisories affecting urllib3 and writes them to `factory/db.json`.

### Build patched wheels (optional)

```bash
python3 factory/builder.py
```

For each CVE entry in `db.json`, the builder:
1. Downloads the vulnerable version sdist from PyPI
2. Downloads the patched version sdist from PyPI
3. Diffs the two to generate a `.patch` file
4. Applies the patch to the vulnerable source
5. Bumps the version string to `<version>+echo1`
6. Builds a `.whl` and saves it to `factory/artifacts/`

> This step takes a few minutes as it downloads from PyPI. The built wheels are checked in and re-used on subsequent runs.

### Test the Gateway directly

```bash
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d '{"package":"urllib3","version":"1.24.0"}' | python3 -m json.tool
```

**Vulnerable version response:**
```json
{
  "constraint": "urllib3==2.6.3",
  "strategy": "BACKPORT",
  "cve_id": "CVE-2026-21441"
}
```

**Safe version response:**
```json
{
  "constraint": null,
  "strategy": null,
  "cve_id": null
}
```

### Run the Client Shim

```bash
bash client/shim.sh -r client/requirements.txt
```

The shim:
1. Parses `package==version` / `package>=version` lines from the requirements file
2. Queries the gateway for each package
3. If a CVE constraint is returned, writes it to `/tmp/echo_fix.txt`
4. Runs `pip install -r <file> -c /tmp/echo_fix.txt --find-links factory/artifacts`
5. If the gateway is unreachable: warns to stderr and runs pip normally (fail-open — never blocks a developer)

---

## Gateway API Reference

### `POST /resolve`

**Request body:**
```json
{ "package": "urllib3", "version": "1.24.0" }
```

**Response — CVE found:**
```json
{
  "constraint": "urllib3==2.6.3",
  "strategy": "BACKPORT",
  "cve_id": "CVE-2026-21441"
}
```

**Response — no CVE:**
```json
{ "constraint": null, "strategy": null, "cve_id": null }
```

**Strategies:**
- `BACKPORT` — the fix requires crossing a major version boundary; Echo builds a backported wheel
- `BUMP` — the fix is a safe minor/patch upgrade within the same major version

Interactive API docs available at `http://localhost:8000/docs` when the gateway is running.

---

## Project Structure

```
echo/
├── client/
│   ├── shim.sh              # pip wrapper — injects CVE constraints
│   └── requirements.txt     # example requirements file for demo
├── discovery/
│   └── fetcher.py           # GitHub Advisories → factory/db.json
├── factory/
│   ├── builder.py           # builds patched .whl artifacts
│   ├── db.json              # CVE database
│   └── artifacts/           # patched wheels + patch files
├── gateway/
│   └── api.py               # FastAPI /resolve endpoint
├── run.sh                   # full demo flow script
├── reset.sh                 # resets environment to clean demo state
└── README.md
```

---

## Design Decisions

**Fail-open shim** — If the gateway is unreachable for any reason, the shim falls back to running pip normally. It never blocks a developer's workflow; security is additive, not a hard gate.

**Local artifacts via `--find-links`** — When Echo builds a patched `+echo1` wheel, pip resolves it from the local artifacts directory instead of PyPI. This means the fix is fully air-gapped and works without internet access once the wheels are built.

**CVE database is plain JSON** — `factory/db.json` is a flat JSON array. Simple to inspect, diff, audit, and extend. No database process required.

**Gateway is stateless** — The gateway reads `db.json` on every request. No cache, no state. This means changes to the database take effect immediately without a restart.

---

## Current Coverage

| CVE | Package | Affected Range | Strategy |
|---|---|---|---|
| CVE-2026-21441 | urllib3 | >= 1.22, < 2.6.3 | BACKPORT |
| CVE-2025-66471 | urllib3 | >= 1.0, < 2.6.0 | BACKPORT |
| CVE-2025-66418 | urllib3 | >= 1.24, < 2.6.0 | BACKPORT |
| CVE-2023-43804 | urllib3 | >= 2.0.0, < 2.0.6 | BUMP |
| CVE-2021-33503 | urllib3 | >= 1.25.4, < 1.26.5 | BUMP |
| CVE-2020-7212  | urllib3 | >= 1.25.2, <= 1.25.7 | BUMP |
| CVE-2019-11324 | urllib3 | < 1.24.2 | BUMP |

---

## Prototype Scope

This is a proof-of-concept. Current limitations:

- **urllib3 only** — the discovery and builder are scoped to urllib3. Extending to other packages requires adding ecosystem entries to the fetcher and re-running the builder.
- **No auth on the gateway** — the API has no authentication. In production, it would sit behind mTLS or an internal service mesh.
- **Shim is Bash** — the client shim works on macOS and Linux. A production version would be a pip plugin (`pip install echo-shim`).
