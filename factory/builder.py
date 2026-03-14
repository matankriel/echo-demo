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

_FACTORY_DIR = Path(__file__).parent
if str(_FACTORY_DIR) not in sys.path:
    sys.path.insert(0, str(_FACTORY_DIR))
try:
    from api_checker import check_api_compatibility as _check_api
except ImportError:
    _check_api = None  # type: ignore[assignment]

DB_PATH = Path(__file__).parent / "db.json"
API_DIFF_CACHE_PATH = Path(__file__).parent / "api_diff_cache.json"
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
        tf.extractall(workdir, filter="data")
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
    found = False

    # 1. Update the primary version source file
    version_file = _find_version_file(source_dir, old_version)
    if version_file is None:
        print(f"  [WARN] Could not locate version string '{old_version}' in {source_dir}")
    else:
        text = version_file.read_text(errors="replace")
        new_text = text.replace(f'"{old_version}"', f'"{new_version}"')
        new_text = new_text.replace(f"'{old_version}'", f"'{new_version}'")
        if new_text == text:
            print(f"  [WARN] Version string '{old_version}' unchanged in {version_file}")
        else:
            version_file.write_text(new_text)
            print(f"  Bumped {version_file.relative_to(source_dir)}: {old_version!r} → {new_version!r}")
            found = True

    # 2. Update PKG-INFO — hatch-vcs reads this when building from sdist (no git repo)
    pkg_info = source_dir / "PKG-INFO"
    if pkg_info.exists():
        text = pkg_info.read_text(errors="replace")
        # Replace the Version header line
        new_text = re.sub(
            rf"^(Version:\s*){re.escape(old_version)}\s*$",
            f"\\g<1>{new_version}",
            text,
            flags=re.MULTILINE,
        )
        if new_text != text:
            pkg_info.write_text(new_text)
            print(f"  Bumped PKG-INFO Version: {old_version!r} → {new_version!r}")
            found = True

    # 3. Neutralise hatch-vcs in pyproject.toml:
    #    - source="vcs"            → replaced with path= so hatchling reads _version.py
    #    - local_scheme="no-local-version" → removed (it strips the +echo1 suffix)
    #    - [tool.hatch.build.hooks.vcs]    → removed (re-writes _version.py at build time)
    pyproject = source_dir / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(errors="replace")

        # Find the version-file path from the build hook (most reliable source)
        vf_match = re.search(r'version-file\s*=\s*["\']([^"\']+)["\']', text)
        version_file_path = vf_match.group(1) if vf_match else f"src/{source_dir.name}/_version.py"

        patched = text
        # a. Replace source="vcs" with path=<version_file>
        patched = re.sub(
            r'source\s*=\s*["\']vcs["\']',
            f'path = "{version_file_path}"',
            patched,
        )
        # b. Remove the raw-options subsection (contains local_scheme=no-local-version)
        patched = re.sub(
            r'\[tool\.hatch\.version\.raw-options\][^\[]*',
            '',
            patched,
            flags=re.DOTALL,
        )
        # c. Remove the build hook that re-writes _version.py from VCS at build time
        patched = re.sub(
            r'\[tool\.hatch\.build\.hooks\.vcs\][^\[]*',
            '',
            patched,
            flags=re.DOTALL,
        )
        if patched != text:
            pyproject.write_text(patched)
            print("  Patched pyproject.toml: disabled hatch-vcs source + local-version strip")

    return found


# ── patch helpers ──────────────────────────────────────────────────────────────

_NOISE_PATTERNS = re.compile(
    r'^(test[s]?/|docs?/|dummyserver/|\.github/|'
    r'.*\.(rst|md|lock)|PKG-INFO|CHANGES|README|LICENSE|'
    r'.*_version\.py|.*__version__\.py)',
    re.IGNORECASE,
)


def _filter_source_patch(patch_text: str, package_name: str) -> str:
    """Keep only src/<package>/ hunks; drop tests, docs, metadata, version files."""
    if not patch_text.strip():
        return patch_text

    kept_blocks = []
    raw_blocks = re.split(r'(?=^diff -ru )', patch_text, flags=re.MULTILINE)

    for block in raw_blocks:
        if not block.strip():
            continue
        m = re.match(r'diff -ru \S+/(\S+) ', block)
        if not m:
            kept_blocks.append(block)
            continue
        filepath = m.group(1)
        if _NOISE_PATTERNS.match(filepath):
            continue
        kept_blocks.append(block)

    return "".join(kept_blocks)


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


def _load_api_diff_cache() -> dict:
    if API_DIFF_CACHE_PATH.exists():
        return json.loads(API_DIFF_CACHE_PATH.read_text())
    return {}


def _save_api_diff_cache(cache: dict) -> None:
    API_DIFF_CACHE_PATH.write_text(json.dumps(cache, indent=2) + "\n")


# ── main processing ────────────────────────────────────────────────────────────

_G = "\033[0;32m"
_Y = "\033[1;33m"
_R = "\033[0;31m"
_C = "\033[0;36m"
_B = "\033[1m"
_X = "\033[0m"


def _detect_strategy(entry: dict) -> str:
    if entry.get("resolution_plan", {}).get("backport_strategy"):
        return "BACKPORT"
    return "BUMP"


def _print_scenario_banner(cve_id: str, package: str, strategy: str) -> None:
    bar = "─" * 62
    if strategy == "BACKPORT":
        header_color = _Y
        label = "SCENARIO B — BACKPORT"
        detail = "API breaking changes — building patched wheel"
        action = "→ building local echo-patched wheel"
    else:
        header_color = _G
        label = "SCENARIO A — BUMP"
        detail = "no breaking changes detected"
        action = "→ verifying PyPI release only"
    print(f"\n  {header_color}┌{bar}┐{_X}")
    print(f"  {header_color}│{_X}  {_B}{label}{_X}  [{cve_id}]  {package}")
    print(f"  {header_color}│{_X}  {detail}")
    print(f"  {header_color}│{_X}  {action}")
    print(f"  {header_color}└{bar}┘{_X}\n")


def _process_bump_entry(entry: dict) -> None:
    package = entry.get("package", "")
    target = entry.get("resolution_plan", {}).get("bump_strategy", {}).get("target_version", "")
    if not target or target == "unknown":
        print(f"  [BUMP] No target_version — skipping verification.")
        return
    try:
        get_sdist_url(package, target)
        print(f"  [BUMP] Verified {package}=={target} on PyPI — no wheel to build.")
        entry["resolution_plan"]["bump_strategy"]["verified"] = True
    except Exception as exc:
        print(f"  [BUMP] Could not verify {package}=={target} on PyPI: {exc}")


def _process_backport_entry(entry: dict) -> None:
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

            # Compute and cache api_diff for this sub-group
            cache_key = f"{package}:{pivot}:{first_patched}"
            if _check_api is not None:
                diff_cache = _load_api_diff_cache()
                if cache_key not in diff_cache:
                    try:
                        api_diff_result = _check_api(package, pivot, first_patched)
                        diff_cache[cache_key] = api_diff_result
                        _save_api_diff_cache(diff_cache)
                        breaking = api_diff_result.get("has_breaking_changes", False)
                        print(f"  API diff: {'BREAKING' if breaking else 'clean'} ({cache_key})")
                    except Exception as exc:
                        print(f"  [WARN] api_diff failed: {exc}")
                else:
                    print(f"  API diff: cached ({cache_key})")

            print("  Running diff ...")
            try:
                make_patch(workdir, patch_path)
            except Exception as exc:
                print(f"  [ERROR] diff failed: {exc} — skipping.")
                continue

            # Filter to security-relevant source files only
            raw_patch = patch_path.read_text()
            filtered = _filter_source_patch(raw_patch, package)
            if filtered != raw_patch:
                dropped = raw_patch.count("\ndiff -ru ") - filtered.count("\ndiff -ru ")
                kept = filtered.count("\ndiff -ru ") + (1 if filtered.startswith("diff") else 0)
                print(f"  Filtered patch: kept {kept} source file(s), dropped {dropped} noise file(s)")
                patch_path.write_text(filtered)

            artifact["patch_file"] = str(patch_path)

            print("  Applying patch ...")
            try:
                apply_patch(workdir, patch_path)
            except Exception as exc:
                print(f"  [WARN] {exc} — continuing.")

            bumped_version = f"{pivot}+echo1"
            print(f"  Bumping version to {bumped_version!r} ...")
            # The security patch may have updated _version.py from pivot→first_patched.
            # Try bumping the post-patch version (first_patched) first; it's what's
            # actually in the source now.  Then also update PKG-INFO (which still
            # carries the pre-patch pivot version from the original sdist).
            bump_version(old_dir, first_patched, bumped_version)
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


def process_entry(entry: dict) -> None:
    strategy = _detect_strategy(entry)
    _print_scenario_banner(
        entry.get("cve_id", "?"),
        entry.get("package", "?"),
        strategy,
    )

    if strategy == "BUMP":
        _process_bump_entry(entry)
    else:
        _process_backport_entry(entry)


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
