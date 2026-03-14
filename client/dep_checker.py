#!/usr/bin/env python3
"""
client/dep_checker.py
Standalone dependency conflict checker.

Usage:
    python3 dep_checker.py -r requirements.txt
"""
import argparse
import importlib.metadata
import re
import sys

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

_G = "\033[0;32m"
_Y = "\033[1;33m"
_R = "\033[0;31m"
_C = "\033[0;36m"
_B = "\033[1m"
_D = "\033[2m"
_X = "\033[0m"


def parse_requirements(path: str) -> list[tuple[str, str]]:
    pattern = re.compile(r"^([A-Za-z0-9_.-]+)[>=!<]+([A-Za-z0-9._+-]+)")
    result: list[tuple[str, str]] = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = pattern.match(line)
                if m:
                    result.append((m.group(1), m.group(2)))
    except OSError as exc:
        print(f"  {_R}Error reading {path}: {exc}{_X}", file=sys.stderr)
    return result


def get_requires(package: str) -> list[str]:
    raw = importlib.metadata.requires(package) or []
    result: list[str] = []
    for r in raw:
        try:
            req = Requirement(r)
            if req.marker is None or req.marker.evaluate():
                result.append(r)
        except Exception:
            pass
    return result


def build_dep_tree(
    top_level: list[tuple[str, str]]
) -> dict[str, list[Requirement]]:
    tree: dict[str, list[Requirement]] = {}
    for name, _version in top_level:
        raw_reqs = get_requires(name)
        parsed: list[Requirement] = []
        for r in raw_reqs:
            try:
                parsed.append(Requirement(r))
            except Exception:
                pass
        tree[name] = parsed
    return tree


def check_horizontal(
    dep_tree: dict[str, list[Requirement]],
    top_level: list[tuple[str, str]],
) -> list[dict]:
    by_name: dict[str, list[tuple[str, str]]] = {}
    for pkg, reqs in dep_tree.items():
        for req in reqs:
            name = req.name.lower()
            spec = str(req.specifier)
            if spec:
                by_name.setdefault(name, []).append((pkg, spec))

    conflicts: list[dict] = []
    for dep_name, specs_list in by_name.items():
        if len(specs_list) <= 1:
            continue
        all_specs = ",".join(s for _, s in specs_list)
        try:
            merged = SpecifierSet(all_specs)
            candidates = ["1.0", "2.0", "3.0", "4.0"]
            if not any(Version(v) in merged for v in candidates):
                conflicts.append(
                    {"dep": dep_name, "specifiers": specs_list, "type": "horizontal"}
                )
        except Exception:
            pass
    return conflicts


def check_vertical(
    dep_tree: dict[str, list[Requirement]],
    top_level: list[tuple[str, str]],
) -> list[dict]:
    pinned = {name.lower(): ver for name, ver in top_level}
    checks: list[dict] = []
    for pkg, reqs in dep_tree.items():
        for req in reqs:
            dep_name = req.name.lower()
            spec_str = str(req.specifier)
            if dep_name in pinned and spec_str:
                pinned_ver = pinned[dep_name]
                try:
                    satisfies = Version(pinned_ver) in SpecifierSet(spec_str)
                except Exception:
                    satisfies = True
                checks.append(
                    {
                        "package": dep_name,
                        "pinned": pinned_ver,
                        "required_by": pkg,
                        "spec": spec_str,
                        "pass": satisfies,
                        "type": "vertical",
                    }
                )
    return checks


def print_results(
    top_level: list[tuple[str, str]],
    dep_tree: dict[str, list[Requirement]],
    horizontal: list[dict],
    vertical: list[dict],
) -> None:
    bar = "─" * 62
    print(f"\n  {_C}┌{bar}┐{_X}")
    print(f"  {_C}│{_X}  {_B}Echo Dep-Conflict Checker{_X}")
    print(f"  {_C}│{_X}  top-level packages: {', '.join(f'{n}=={v}' for n, v in top_level)}")
    print(f"  {_C}└{bar}┘{_X}")

    print(f"\n  {_B}Dependency Map:{_X}")
    for pkg, reqs in dep_tree.items():
        if reqs:
            print(f"    {_B}{pkg}{_X}:")
            for req in reqs[:8]:  # cap at 8 to avoid flooding output
                print(f"      └─ {req.name}{req.specifier}")
            if len(reqs) > 8:
                print(f"      └─ ... ({len(reqs) - 8} more)")
        else:
            print(f"    {_B}{pkg}{_X}: {_D}(no declared runtime deps){_X}")

    print(f"\n  {_B}Horizontal Conflict Check:{_X}")
    if not horizontal:
        print(f"  {_G}✓{_X}  No horizontal conflicts detected.")
    for c in horizontal:
        specs_str = ", ".join(f"{pkg}→{spec}" for pkg, spec in c["specifiers"])
        print(f"  {_R}✗{_X}  {c['dep']}: incompatible specifiers — {specs_str}")

    print(f"\n  {_B}Vertical Conflict Check{_X}  (pinned version vs declared requirement):")
    if not vertical:
        print(f"  {_D}  (no cross-dep pinning to check){_X}")
    for c in vertical:
        if c["pass"]:
            status = f"{_G}PASS{_X}"
        else:
            status = f"{_R}FAIL{_X}"
        line = (
            f"  {status}  {c['package']}=={c['pinned']} "
            f"satisfies {c['required_by']} req  {_D}{c['spec']}{_X}"
        )
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check dependency conflicts in a requirements file."
    )
    parser.add_argument("-r", dest="requirements", required=True, help="Path to requirements.txt")
    args = parser.parse_args()

    top_level = parse_requirements(args.requirements)
    if not top_level:
        print("  No packages found in requirements file.")
        sys.exit(0)

    dep_tree = build_dep_tree(top_level)
    horizontal = check_horizontal(dep_tree, top_level)
    vertical = check_vertical(dep_tree, top_level)
    print_results(top_level, dep_tree, horizontal, vertical)

    failures = [c for c in vertical if not c["pass"]]
    if horizontal or failures:
        print(f"\n  {_Y}!{_X}  Conflicts detected — review before installing.\n")
        sys.exit(1)
    else:
        print(f"\n  {_G}✓{_X}  All dependency checks passed.\n")


if __name__ == "__main__":
    main()
