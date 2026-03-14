"""Gateway API: resolves package versions against CVE remediation database."""

import json
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel
from packaging.version import Version
from packaging.specifiers import SpecifierSet

DB_PATH = Path(__file__).parent.parent / "factory" / "db.json"
API_DIFF_CACHE_PATH = Path(__file__).parent.parent / "factory" / "api_diff_cache.json"
ARTIFACTS_DIR = Path(__file__).parent.parent / "factory" / "artifacts"

app = FastAPI(title="Echo Gateway")


class ResolveRequest(BaseModel):
    package: str
    version: str


class ResolveResponse(BaseModel):
    constraint: str | None
    strategy: str | None = None
    cve_id: str | None = None
    api_scenario: str | None = None
    api_break_summary: str | None = None


def _api_break_summary(api_diff: dict) -> str | None:
    if not api_diff or api_diff.get("error"):
        return None
    r = len(api_diff.get("removed", []))
    c = len(api_diff.get("changed", []))
    a = len(api_diff.get("added", []))
    if api_diff.get("has_breaking_changes"):
        return f"{r} removed, {c} changed, {a} added — BREAKING"
    return f"no breaking changes ({a} added)"


def load_db() -> list:
    if DB_PATH.exists():
        with open(DB_PATH) as f:
            return json.load(f)
    return []


def load_api_diff_cache() -> dict:
    if API_DIFF_CACHE_PATH.exists():
        with open(API_DIFF_CACHE_PATH) as f:
            return json.load(f)
    return {}


@app.post("/resolve", response_model=ResolveResponse)
def resolve(req: ResolveRequest):
    db = load_db()
    try:
        req_version = Version(req.version)
    except Exception:
        return ResolveResponse(constraint=None)

    for entry in db:
        if entry.get("package", "").lower() != req.package.lower():
            continue

        plan = entry.get("resolution_plan", {})
        cve_id = entry.get("cve_id")

        # Check backport strategies first
        for backport in plan.get("backport_strategy", []):
            version_range = backport.get("version_range", "")
            if not version_range:
                continue
            try:
                spec = SpecifierSet(version_range)
                if req_version in spec:
                    pivot = backport.get("pivot_stable_version", "")
                    # Derive version from artifact uid; fall back to plain pivot if wheel is absent
                    artifact_uid = backport.get("artifact", {}).get("uid", "")
                    if artifact_uid and (ARTIFACTS_DIR / artifact_uid).exists():
                        # Local patched wheel present — parse exact version from filename
                        parts = artifact_uid.split("-")
                        artifact_version = parts[1].replace("_", "+", 1) if len(parts) >= 2 else pivot
                    else:
                        # No local wheel — use plain pivot so pip can resolve from PyPI
                        artifact_version = pivot
                    constraint = f"{req.package}=={artifact_version}"
                    diff_cache = load_api_diff_cache()
                    cache_key = f"{req.package}:{backport.get('pivot_stable_version', '')}:{entry.get('first_patched_version', '')}"
                    api_diff = diff_cache.get(cache_key, {})
                    return ResolveResponse(
                        constraint=constraint,
                        strategy="BACKPORT",
                        cve_id=cve_id,
                        api_scenario="BACKPORT",
                        api_break_summary=_api_break_summary(api_diff),
                    )
            except Exception:
                continue

        # Check bump strategy
        bump = plan.get("bump_strategy", {})
        bump_range = bump.get("affected_range", "")
        if bump_range:
            try:
                spec = SpecifierSet(bump_range)
                if req_version in spec:
                    target = bump.get("target_version", "")
                    constraint = f"{req.package}=={target}"
                    api_diff = {}
                    return ResolveResponse(
                        constraint=constraint,
                        strategy="BUMP",
                        cve_id=cve_id,
                        api_scenario="BUMP",
                        api_break_summary=_api_break_summary(api_diff),
                    )
            except Exception:
                pass

    return ResolveResponse(constraint=None)
