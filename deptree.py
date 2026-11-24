"""Show the dependency tree of a project and check the lock file.

Usage:  python3 tools/deptree.py REQUIREMENTS.txt LOCK_FILE

REQUIREMENTS.txt lists what the project uses directly. LOCK_FILE lists every
package that will be installed, each with an exact version (name==version).
What each version needs is read from tools/index.json.
"""
import sys

from pkgtools import load_json, read_lock, read_requirements, satisfies


def parse_req(text):
    """'urllib3>=1.21.1,<1.27' -> ('urllib3', '>=1.21.1,<1.27')"""
    for i, ch in enumerate(text):
        if ch in "<>=!":
            return text[:i].strip(), text[i:].strip()
    return text.strip(), ""


def requires(index, name, version):
    """List of (name, spec) that this version needs, or None if unknown."""
    reqs = index["packages"].get(name, {}).get(version)
    return None if reqs is None else [parse_req(r) for r in reqs]


def check(direct, lock, index):
    """Return a dict of problem lists; all lists are empty for a good lock."""
    problems = {"not_pinned": [], "unknown": [], "missing": [],
                "conflict": [], "unused": [], "known_problem": []}
    for name, version, line in direct:
        if version is None:
            problems["not_pinned"].append(line)
    used = set()
    todo = [name for name, _, _ in direct]
    while todo:
        name = todo.pop()
        if name in used:
            continue
        used.add(name)
        if name not in lock:
            problems["missing"].append(name)
            continue
        reqs = requires(index, name, lock[name])
        if reqs is None:
            problems["unknown"].append(name + " " + lock[name])
            continue
        for dep, spec in reqs:
            if dep not in lock:
                problems["missing"].append("%s (needed by %s %s)" % (dep, name, lock[name]))
                continue
            if not satisfies(lock[dep], spec):
                problems["conflict"].append("%s %s needs %s %s, lock has %s"
                                            % (name, lock[name], dep, spec, lock[dep]))
            todo.append(dep)
    problems["unused"] = sorted(set(lock) - used)
    for p in index.get("known_problems", []):
        a, b = p["package"], p["with"]
        if (a in lock and b in lock and satisfies(lock[a], p["versions"])
                and satisfies(lock[b], p["with_versions"])):
            problems["known_problem"].append("%s %s with %s %s: %s"
                                             % (a, lock[a], b, lock[b], p["error"]))
    return problems


def print_tree(name, lock, index, prefix, shown, spec=""):
    version = lock.get(name, "MISSING")
    note = "  (needs %s)" % spec if spec else ""
    if name in shown and spec:
        print(prefix + "%s %s%s  [shown above]" % (name, version, note))
        return
    print(prefix + "%s %s%s" % (name, version, note))
    shown.add(name)
    reqs = requires(index, name, version) or []
    child = prefix.replace("+-- ", "|   ").replace("`-- ", "    ")
    for i, (dep, dep_spec) in enumerate(reqs):
        branch = "`-- " if i == len(reqs) - 1 else "+-- "
        print_tree(dep, lock, index, child + branch, shown, dep_spec)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    direct = read_requirements(sys.argv[1])
    lock = read_lock(sys.argv[2])
    index = load_json("index.json")
    print("Direct dependencies (%s): %d" % (sys.argv[1], len(direct)))
    print("Packages in the lock file (%s): %d" % (sys.argv[2], len(lock)))
    print()
    shown = set()
    for name, _, _ in direct:
        print_tree(name, lock, index, "", shown)
    problems = check(direct, lock, index)
    titles = [("not_pinned", "not pinned with == in " + sys.argv[1],
               "every direct dependency is pinned with =="),
              ("unknown", "version not in tools/index.json",
               "every version is in tools/index.json"),
              ("missing", "needed, but not in the lock file",
               "everything that is needed is in the lock file"),
              ("conflict", "version does not match what another package needs",
               "every version matches what other packages need"),
              ("unused", "in the lock file, but nothing needs it",
               "every package in the lock file is needed"),
              ("known_problem", "known not to work together (team notes)",
               "no known problems from the team notes")]
    print()
    print("Checks:")
    for key, title, ok_text in titles:
        if problems[key]:
            print("  PROBLEM  %s:" % title)
            for item in problems[key]:
                print("           - " + item)
        else:
            print("  OK       " + ok_text)
    return 1 if any(problems.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
