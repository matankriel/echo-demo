"""
factory/builder.py
CVE remediation backport wheel builder.

Run from the project root:
    python factory/builder.py
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import requests

DB_PATH = Path(__file__).parent / "db.json"
ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"


# ── PyPI helpers ───────────────────────────────────────────────────────────────

def get_sdist_url(package: str, version: str) -> str:
    resp = requests.get(PYPI_JSON_URL.format(package=package, version=version), timeout=30)
    resp.raise_for_status()
    sdist_entries = [u for u in resp.json()["urls"] if u["packagetype"] == "sdist"]
    if not sdist_entries:
        raise RuntimeError(f"No sdist found for {package}=={version} on PyPI")
    return sdist_entries[0]["url"]


def download_tarball(url: str, dest: Path) -> None:
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    with open(dest, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=65536):
            fh.write(chunk)


# ── tarball helpers ────────────────────────────────────────────────────────────

def get_top_level_dir(tarball: Path) -> str:
    with tarfile.open(tarball, "r:gz") as tf:
        first = tf.getnames()[0]
    return first.rstrip("/").split("/")[0]


def extract_and_rename(tarball: Path, workdir: Path, target_name: str) -> Path:
    top = get_top_level_dir(tarball)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(workdir)
    renamed = workdir / target_name
    if renamed.exists():
        shutil.rmtree(renamed)
    (workdir / top).rename(renamed)
    return renamed


# ── version-string helpers ─────────────────────────────────────────────────────

def _find_version_file(source_dir: Path, version: str) -> Path | None:
    candidates: list[Path] = []

    for pattern in ("**/_version.py", "**/__version__.py", "**/__init__.py"):
        candidates.extend(sorted(source_dir.glob(pattern)))

    for name in ("setup.cfg", "pyproject.toml", "setup.py"):
        p = source_dir / name
        if p.exists():
            candidates.append(p)

    # hatch/flit dynamic version path via pyproject.toml
    pyproject = source_dir / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                tomllib = None
        if tomllib is not None:
            try:
                data = tomllib.loads(pyproject.read_text())
                hatch_path = data.get("tool", {}).get("hatch", {}).get("version", {}).get("path")
                if hatch_path:
                    candidates.insert(0, source_dir / hatch_path)
            except Exception:
                pass

    for path in candidates:
        try:
            if version in path.read_text(errors="replace"):
                return path
        except OSError:
            continue
    return None


def bump_version(source_dir: Path, old_version: str, new_version: str) -> bool:
    version_file = _find_version_file(source_dir, old_version)
    if version_file is None:
        print(f"  [WARN] Could not locate version string '{old_version}' in {source_dir}")
        return False
    text = version_file.read_text(errors="replace")
    new_text = text.replace(f'"{old_version}"', f'"{new_version}"')
    new_text = new_text.replace(f"'{old_version}'", f"'{new_version}'")
    if new_text == text:
        print(f"  [WARN] Version string '{old_version}' unchanged in {version_file}")
        return False
    version_file.write_text(new_text)
    print(f"  Bumped {version_file.relative_to(source_dir)}: {old_version!r} → {new_version!r}")
    return True


# ── patch helpers ──────────────────────────────────────────────────────────────

def make_patch(workdir: Path, patch_dest: Path) -> None:
    result = subprocess.run(
        ["diff", "-ru", "old", "new"],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    if result.returncode == 2:
        raise RuntimeError(f"diff failed (exit 2):\n{result.stderr}")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    patch_dest.write_text(result.stdout)
    print(f"  Patch written ({len(result.stdout)} bytes): {patch_dest.name}")


def apply_patch(workdir: Path, patch_file: Path) -> bool:
    patch_text = patch_file.read_text()
    if not patch_text.strip():
        print("  Patch is empty (versions are identical) — skipping apply.")
        return True
    result = subprocess.run(
        ["patch", "-p1", "-d", "old/"],
        input=patch_text,
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("  Patch applied cleanly.")
        return True
    elif result.returncode == 1:
        print(f"  [WARN] Patch applied with hunk failures:\n{result.stdout}\n{result.stderr}")
        return False
    else:
        raise RuntimeError(f"patch error (exit {result.returncode}):\n{result.stderr}")


# ── wheel build helpers ────────────────────────────────────────────────────────

def build_wheel(source_dir: Path, dist_dir: Path) -> Path:
    dist_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir), str(source_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"wheel build failed:\n{result.stdout}\n{result.stderr}")
    wheels = list(dist_dir.glob("*.whl"))
    if not wheels:
        raise RuntimeError("build succeeded but no .whl file found")
    return wheels[0]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── main processing ────────────────────────────────────────────────────────────

def process_entry(entry: dict) -> None:
    cve_id: str = entry["cve_id"]
    package: str = entry["package"]
    first_patched: str = entry.get("first_patched_version", "unknown")
    backport_strategy: list = entry.get("resolution_plan", {}).get("backport_strategy") or []

    if not backport_strategy:
        print(f"[{cve_id}] No backport_strategy — skipping.")
        return
    if first_patched == "unknown":
        print(f"[{cve_id}] first_patched_version is 'unknown' — skipping.")
        return

    for sub in backport_strategy:
        pivot: str = sub.get("pivot_stable_version", "unknown")
        if pivot == "unknown":
            print(f"[{cve_id}] pivot_stable_version unknown in {sub.get('sub_group_id')} — skipping.")
            continue

        artifact: dict = sub.setdefault("artifact", {})
        wheel_filename: str = artifact.get("uid", "")

        if wheel_filename and (ARTIFACTS_DIR / wheel_filename).exists():
            print(f"[{cve_id}] Artifact already exists: {wheel_filename} — skipping.")
            continue

        print(f"\n[{cve_id}] sub-group={sub.get('sub_group_id')} pivot={pivot} patched={first_patched}")

        patch_path = ARTIFACTS_DIR / f"{cve_id}.patch"

        with tempfile.TemporaryDirectory(prefix="ehco_build_") as _tmpdir:
            workdir = Path(_tmpdir)

            print("  Fetching sdist URLs ...")
            try:
                old_url = get_sdist_url(package, pivot)
                new_url = get_sdist_url(package, first_patched)
            except Exception as exc:
                print(f"  [ERROR] PyPI fetch failed: {exc} — skipping.")
                continue

            print(f"  Downloading old ({pivot}) ...")
            old_tarball = workdir / f"{package}-{pivot}.tar.gz"
            try:
                download_tarball(old_url, old_tarball)
            except Exception as exc:
                print(f"  [ERROR] Download failed: {exc} — skipping.")
                continue

            print(f"  Downloading new ({first_patched}) ...")
            new_tarball = workdir / f"{package}-{first_patched}.tar.gz"
            try:
                download_tarball(new_url, new_tarball)
            except Exception as exc:
                print(f"  [ERROR] Download failed: {exc} — skipping.")
                continue

            print("  Extracting ...")
            try:
                old_dir = extract_and_rename(old_tarball, workdir, "old")
                extract_and_rename(new_tarball, workdir, "new")
            except Exception as exc:
                print(f"  [ERROR] Extraction failed: {exc} — skipping.")
                continue

            print("  Running diff ...")
            try:
                make_patch(workdir, patch_path)
            except Exception as exc:
                print(f"  [ERROR] diff failed: {exc} — skipping.")
                continue

            artifact["patch_file"] = str(patch_path)

            print("  Applying patch ...")
            try:
                apply_patch(workdir, patch_path)
            except Exception as exc:
                print(f"  [WARN] {exc} — continuing.")

            bumped_version = f"{pivot}+echo1"
            print(f"  Bumping version to {bumped_version!r} ...")
            bump_version(old_dir, pivot, bumped_version)

            print("  Building wheel ...")
            dist_dir = workdir / "dist"
            try:
                wheel_path = build_wheel(old_dir, dist_dir)
                print(f"  Built: {wheel_path.name}")
            except RuntimeError as exc:
                print(f"  [WARN] Wheel build failed: {exc}")
                artifact["sha256"] = "build-failed"
                artifact["uid"] = f"{package}-{bumped_version}-py3-none-any.whl"
                continue

            dest_wheel = ARTIFACTS_DIR / wheel_path.name
            shutil.copy2(wheel_path, dest_wheel)
            print(f"  Saved to {dest_wheel}")

            artifact["uid"] = wheel_path.name
            artifact["sha256"] = sha256_of(dest_wheel)
            artifact["size_bytes"] = dest_wheel.stat().st_size
            print(f"  sha256={artifact['sha256'][:16]}...  size={artifact['size_bytes']}")


def main() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    db: list[dict] = json.loads(DB_PATH.read_text())
    print(f"Processing {len(db)} CVE entries...\n")
    for entry in db:
        process_entry(entry)
    DB_PATH.write_text(json.dumps(db, indent=2) + "\n")
    print("\ndb.json updated with artifact metadata.")


if __name__ == "__main__":
    main()
