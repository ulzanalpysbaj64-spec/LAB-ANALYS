"""Offline audit: compare installed versions with known vulnerabilities.

Usage:  python3 tools/audit.py LOCK_FILE_OR_SBOM [--json]

The input is a lock file (name==version on every line) or a CycloneDX SBOM
(*.json). Advisories are read from tools/advisories.json, a frozen teaching
snapshot. Exit code: 0 = nothing found, 1 = vulnerabilities found.
On your VM, compare the result with the real tool: pip-audit.
"""
import json
import sys

from pkgtools import load_json, parse_version, read_packages

ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}


def matching_range(advisory, version):
    """The range {'introduced', 'fixed'} that contains version, or None."""
    v = parse_version(version)
    for r in advisory["ranges"]:
        if parse_version(r["introduced"]) <= v < parse_version(r["fixed"]):
            return r
    return None


def find(packages, advisories):
    """List of (name, version, advisory, fixed version), most severe first."""
    found = []
    for adv in advisories:
        version = packages.get(adv["package"])
        if version is not None:
            r = matching_range(adv, version)
            if r is not None:
                found.append((adv["package"], version, adv, r["fixed"]))
    found.sort(key=lambda f: (ORDER[f[2]["severity"]], f[0], f[2]["cve"]))
    return found


def smallest_safe(name, version, advisories):
    """The smallest version >= version that none of the advisories affect."""
    candidate = version
    changed = True
    while changed:
        changed = False
        for adv in advisories:
            if adv["package"] == name:
                r = matching_range(adv, candidate)
                if r is not None:
                    candidate, changed = r["fixed"], True
    return candidate


def main():
    args = [a for a in sys.argv[1:] if a != "--json"]
    if len(args) != 1:
        print(__doc__)
        return 2
    packages = read_packages(args[0])
    advisories = load_json("advisories.json")["advisories"]
    found = find(packages, advisories)
    if "--json" in sys.argv:
        print(json.dumps([{"name": n, "version": v, "id": a["id"], "cve": a["cve"],
                           "severity": a["severity"], "fixed": f,
                           "summary": a["summary"]} for n, v, a, f in found], indent=1))
        return 1 if found else 0
    print("Advisory snapshot: %d advisories (tools/advisories.json)" % len(advisories))
    print("Packages checked: %d" % len(packages))
    print()
    if not found:
        print("No known vulnerabilities found in the snapshot.")
        return 0
    names = sorted({n for n, _, _, _ in found})
    print("Found %d known vulnerabilities in %d packages" % (len(found), len(names)))
    row = "%-9s %-10s %-15s %-9s %s"
    print(row % ("Name", "Version", "ID", "Severity", "Fixed in"))
    print(row % ("-" * 9, "-" * 10, "-" * 15, "-" * 9, "-" * 10))
    for name, version, adv, fixed in found:
        print(row % (name, version, adv["cve"], adv["severity"], fixed))
    print()
    counts = ", ".join("%s %d" % (s, sum(1 for f in found if f[2]["severity"] == s))
                       for s in ORDER)
    print("By severity: " + counts)
    print()
    print("Smallest version without these advisories:")
    for name in names:
        version = packages[name]
        print("  %-9s %-10s -> %s" % (name, version, smallest_safe(name, version, advisories)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
