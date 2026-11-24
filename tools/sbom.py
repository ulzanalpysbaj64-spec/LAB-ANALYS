"""Make a simple SBOM (Software Bill of Materials) in CycloneDX JSON format.

Usage:  python3 tools/sbom.py REQUIREMENTS.txt LOCK_FILE -o bom.json

The SBOM lists every component (package and exact version) and who depends
on whom. Others can check it later without the source code, for example
with:  python3 tools/audit.py bom.json
"""
import datetime
import json
import sys
import uuid

from deptree import requires
from pkgtools import load_json, read_lock, read_requirements

APP = "student-portal"


def purl(name, version):
    return "pkg:pypi/%s@%s" % (name, version)


def make_bom(direct, lock, index):
    deps = [{"ref": "app:" + APP,
             "dependsOn": [purl(n, lock[n]) for n, _, _ in direct if n in lock]}]
    for name in sorted(lock):
        reqs = requires(index, name, lock[name]) or []
        deps.append({"ref": purl(name, lock[name]),
                     "dependsOn": [purl(d, lock[d]) for d, _ in reqs if d in lock]})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                         .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "bom-ref": "app:" + APP,
                          "name": APP, "version": "1.0"},
        },
        "components": [{"type": "library", "bom-ref": purl(n, lock[n]),
                        "name": n, "version": lock[n], "purl": purl(n, lock[n])}
                       for n in sorted(lock)],
        "dependencies": deps,
    }


def main():
    args = sys.argv[1:]
    if len(args) != 4 or args[2] != "-o":
        print(__doc__)
        return 2
    bom = make_bom(read_requirements(args[0]), read_lock(args[1]), load_json("index.json"))
    with open(args[3], "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)
    print("Wrote %s: %d components, %d dependency entries"
          % (args[3], len(bom["components"]), len(bom["dependencies"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
