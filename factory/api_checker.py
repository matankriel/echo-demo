"""
factory/api_checker.py
AST-based API diff between two versions of a PyPI package.
"""
from __future__ import annotations

import ast
import tarfile
import tempfile
from pathlib import Path

import requests as _requests

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"

_G = "\033[0;32m"
_Y = "\033[1;33m"
_R = "\033[0;31m"
_C = "\033[0;36m"
_B = "\033[1m"
_D = "\033[2m"
_X = "\033[0m"


def _get_sdist_url(package: str, version: str) -> str:
    resp = _requests.get(PYPI_JSON_URL.format(package=package, version=version), timeout=30)
    resp.raise_for_status()
    entries = [u for u in resp.json()["urls"] if u["packagetype"] == "sdist"]
    if not entries:
        raise RuntimeError(f"No sdist found for {package}=={version}")
    return entries[0]["url"]


def _download_and_extract(url: str, dest_dir: Path) -> Path:
    resp = _requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    tarball = dest_dir / "pkg.tar.gz"
    with open(tarball, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=65536):
            fh.write(chunk)
    with tarfile.open(tarball, "r:gz") as tf:
        names = tf.getnames()
        tf.extractall(dest_dir, filter="data")
    top = names[0].rstrip("/").split("/")[0] if names else ""
    return dest_dir / top


def _sig_from_funcdef(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    pos_only = getattr(node.args, "posonlyargs", [])
    pos_args = pos_only + node.args.args
    n_defaults = len(node.args.defaults)
    n_pos = len(pos_args)
    n_required_pos = n_pos - n_defaults

    args: list[str] = []
    required: list[str] = []

    for i, arg in enumerate(pos_args):
        if arg.arg in ("self", "cls"):
            continue
        args.append(arg.arg)
        if i < n_required_pos:
            required.append(arg.arg)

    for i, arg in enumerate(node.args.kwonlyargs):
        args.append(arg.arg)
        if node.args.kw_defaults[i] is None:
            required.append(arg.arg)

    return {
        "args": args,
        "required": required,
        "has_varargs": node.args.vararg is not None,
    }


def _build_api_map(source_dir: Path) -> dict:
    api: dict = {}
    for py_file in source_dir.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(errors="replace"))
        except Exception:
            continue
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not item.name.startswith("_"):
                    api[f"function: {item.name}"] = _sig_from_funcdef(item)
            elif isinstance(item, ast.ClassDef):
                if not item.name.startswith("_"):
                    api[f"class: {item.name}"] = {
                        "args": [],
                        "required": [],
                        "has_varargs": False,
                    }
    return api


def _compare_maps(
    old: dict, new: dict
) -> tuple[list[str], list[str], list[str]]:
    removed = [k for k in old if k not in new]
    added = [k for k in new if k not in old]
    changed: list[str] = []
    for k in old:
        if k in new and k.startswith("function:"):
            old_req = set(old[k].get("required", []))
            new_req = set(new[k].get("required", []))
            if old_req != new_req:
                notes: list[str] = []
                for p in sorted(old_req - new_req):
                    notes.append(f"removed required param '{p}'")
                for p in sorted(new_req - old_req):
                    notes.append(f"added required param '{p}'")
                changed.append(f"{k} — {', '.join(notes)}")
    return removed, changed, added


def check_api_compatibility(
    package: str, old_version: str, new_version: str
) -> dict:
    try:
        with tempfile.TemporaryDirectory(prefix="ehco_api_") as tmpdir:
            tmp = Path(tmpdir)
            old_work = tmp / "old"
            new_work = tmp / "new"
            old_work.mkdir()
            new_work.mkdir()

            old_url = _get_sdist_url(package, old_version)
            new_url = _get_sdist_url(package, new_version)
            old_dir = _download_and_extract(old_url, old_work)
            new_dir = _download_and_extract(new_url, new_work)

            old_map = _build_api_map(old_dir)
            new_map = _build_api_map(new_dir)
            removed, changed, added = _compare_maps(old_map, new_map)
            has_breaking = bool(removed or changed)

            bar = "─" * 60
            print(f"\n  {_C}┌{bar}┐{_X}")
            print(f"  {_C}│{_X}  {_B}API Diff: {package}  {old_version} → {new_version}{_X}")
            print(f"  {_C}│{_X}  symbols: old={len(old_map)}  →  new={len(new_map)}")
            if has_breaking:
                print(
                    f"  {_C}│{_X}  {_R}BREAKING{_X}: "
                    f"{len(removed)} removed, {len(changed)} changed, {len(added)} added"
                )
            else:
                print(
                    f"  {_C}│{_X}  {_G}CLEAN{_X}: no breaking changes  ({len(added)} added)"
                )
            print(f"  {_C}└{bar}┘{_X}\n")

            return {
                "has_breaking_changes": has_breaking,
                "removed": removed,
                "changed": changed,
                "added": added,
                "old_count": len(old_map),
                "new_count": len(new_map),
            }

    except Exception as exc:
        return {
            "has_breaking_changes": False,
            "removed": [],
            "changed": [],
            "added": [],
            "old_count": 0,
            "new_count": 0,
            "error": str(exc),
        }
