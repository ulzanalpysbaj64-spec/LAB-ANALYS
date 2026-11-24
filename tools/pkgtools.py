"""Small helpers shared by the Lab 10 tools (standard library only).

Names are normalised as pip does (PEP 503): "PyYAML", "pyyaml" and "py_yaml"
mean the same kind of thing. Versions are compared as tuples of numbers,
which is enough for the versions in this lab. Real tools use the full
PEP 440 rules (the "packaging" library).
"""
import json
import os
import re

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))


def normalize(name):
    """PEP 503 name: lower case, runs of - _ . become one -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_version(text):
    """'2022.12.07' -> (2022, 12, 7); '3.1' -> (3, 1, 0)."""
    parts = [int(p) for p in re.findall(r"\d+", text)]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def satisfies(version, spec):
    """True if version matches a spec such as '>=1.21.1,<1.27' ('' = any)."""
    v = parse_version(version)
    for cond in filter(None, (c.strip() for c in spec.split(","))):
        op, ver = re.match(r"(==|!=|>=|<=|>|<)\s*(.+)", cond).groups()
        w = parse_version(ver)
        ok = {"==": v == w, "!=": v != w, ">=": v >= w,
              "<=": v <= w, ">": v > w, "<": v < w}[op]
        if not ok:
            return False
    return True


def read_requirements(path):
    """Read a requirements or lock file.

    Returns a list of (name, version or None, original line). A version is
    returned only for an exact pin 'name==version'. Comments, blank lines
    and '--hash' options are ignored.
    """
    result = []
    with open(path, encoding="utf-8") as f:
        text = f.read().replace("\\\n", " ")
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("--"):
            continue
        line = line.split(" --hash", 1)[0].strip()
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)", line)
        name, spec = m.group(1), m.group(2).strip()
        pin = re.fullmatch(r"==\s*([0-9][0-9A-Za-z.]*)", spec)
        result.append((normalize(name), pin.group(1) if pin else None, line))
    return result


def read_lock(path):
    """Lock file -> {name: version}. Raises ValueError on a line without '=='."""
    lock = {}
    for name, version, line in read_requirements(path):
        if version is None:
            raise ValueError("not an exact pin: " + line)
        lock[name] = version
    return lock


def read_sbom(path):
    """CycloneDX JSON -> {name: version} (only the components list)."""
    with open(path, encoding="utf-8") as f:
        bom = json.load(f)
    return {normalize(c["name"]): c["version"] for c in bom.get("components", [])}


def read_packages(path):
    """A lock file or a CycloneDX SBOM (*.json) -> {name: version}."""
    if path.endswith(".json"):
        return read_sbom(path)
    return read_lock(path)


def load_json(name):
    with open(os.path.join(TOOLS_DIR, name), encoding="utf-8") as f:
        return json.load(f)
