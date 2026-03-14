#!/usr/bin/env python3
"""Fetch GitHub security advisories for urllib3 and populate factory/db.json."""

import json
import os
import sys
import uuid
from pathlib import Path

import requests
from packaging.version import Version

DB_PATH = Path(__file__).parent.parent / "factory" / "db.json"
ADVISORIES_URL = "https://api.github.com/advisories"


def get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("Error: GITHUB_TOKEN environment variable not set.")
    return token


def fetch_advisories(token: str) -> list:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "type": "reviewed",
        "ecosystem": "pip",
        "severity": "high",
        "affects": "urllib3",
        "per_page": 100,
    }
    resp = requests.get(ADVISORIES_URL, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def decide_strategy(vulnerable_range: str, patched_version: str) -> str:
    def major(s):
        for part in s.split(","):
            try:
                return Version(part.strip().lstrip("><=! ")).major
            except Exception:
                continue
        return None

    vuln_major = major(vulnerable_range)
    try:
        patch_major = Version(patched_version).major
    except Exception:
        return "BACKPORT"
    return "BUMP" if vuln_major == patch_major else "BACKPORT"


def build_cve_entry(advisory: dict, vuln: dict) -> dict | None:
    cve_id = advisory.get("cve_id") or advisory.get("ghsa_id")
    if not cve_id:
        return None

    package_name = (vuln.get("package") or {}).get("name", "")
    vulnerable_range = vuln.get("vulnerable_version_range", "")
    first_patched_raw = vuln.get("first_patched_version")
    first_patched = first_patched_raw if isinstance(first_patched_raw, str) else (first_patched_raw or {}).get("identifier", "")
    severity = advisory.get("severity", "unknown")
    cvss_score = (advisory.get("cvss") or {}).get("score")
    strategy = decide_strategy(vulnerable_range, first_patched) if first_patched else "BACKPORT"

    # pivot = last VULNERABLE version (one step before the fix)
    # This ensures old != new so the diff contains the real security patch.
    try:
        v = Version(first_patched)
        if v.micro > 0:
            pivot_version = f"{v.major}.{v.minor}.{v.micro - 1}"
        elif v.minor > 0:
            pivot_version = f"{v.major}.{v.minor - 1}.0"
        else:
            pivot_version = first_patched  # can't go lower; same-version diff is fine
    except Exception:
        pivot_version = first_patched or "unknown"

    try:
        floor_v = Version(vulnerable_range.split(",")[0].strip().lstrip("><=! "))
        branch_label = f"{floor_v.major}.{floor_v.minor}"
    except Exception:
        branch_label = "unknown"

    return {
        "cve_id": cve_id,
        "package": package_name,
        "severity": severity.capitalize(),
        "cvss_score": cvss_score,
        "status": "Active",
        "fix_commit_sha": "unknown",
        "first_patched_version": first_patched or "unknown",
        "patch_file_uid": str(uuid.uuid4()),
        "resolution_plan": {
            "bump_strategy": {
                "affected_range": vulnerable_range,
                "target_version": first_patched or "unknown",
                "notes": "Safe minor upgrade path identified." if strategy == "BUMP" else "Bump not available across major versions.",
            },
            "backport_strategy": [{
                "sub_group_id": f"urllib3-v{branch_label}-branch",
                "version_range": vulnerable_range,
                "pivot_stable_version": pivot_version,
                "artifact": {
                    "uid": f"urllib3-{pivot_version}+echo1-py3-none-any.whl",
                    "sha256": "mock-sha256",
                    "size_bytes": 140000,
                },
            }],
        },
    }


def _hardcoded_requests_entry() -> dict:
    return {
        "cve_id": "CVE-2023-32681",
        "package": "requests",
        "severity": "High",
        "cvss_score": 6.1,
        "status": "Active",
        "fix_commit_sha": "74ea7cf7",
        "first_patched_version": "2.31.0",
        "patch_file_uid": str(uuid.uuid4()),
        "resolution_plan": {
            "bump_strategy": {
                "affected_range": ">=2.1.0, <2.31.0",
                "target_version": "2.31.0",
                "notes": "Safe minor upgrade path identified.",
            },
            "backport_strategy": [],
        },
    }


def main():
    token = get_token()
    print("Fetching urllib3 high-severity advisories + injecting requests CVE-2023-32681...")
    advisories = fetch_advisories(token)
    print(f"Found {len(advisories)} urllib3 advisories.")

    db = []
    if DB_PATH.exists():
        with open(DB_PATH) as f:
            content = f.read().strip()
            db = json.loads(content) if content else []
    existing_ids = {e["cve_id"] for e in db}

    new_entries: list[dict] = []

    # Inject hardcoded requests CVE
    req_entry = _hardcoded_requests_entry()
    if req_entry["cve_id"] not in existing_ids:
        new_entries.append(req_entry)
        existing_ids.add(req_entry["cve_id"])

    for advisory in advisories:
        for vuln in advisory.get("vulnerabilities") or []:
            entry = build_cve_entry(advisory, vuln)
            if entry and entry["cve_id"] not in existing_ids:
                new_entries.append(entry)
                existing_ids.add(entry["cve_id"])

    db.extend(new_entries)
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)
    print(f"{len(new_entries)} new entries written to {DB_PATH}")


if __name__ == "__main__":
    main()
