"""Check proposed package names for typosquatting (look-alike names).

Usage:  python3 tools/typo_check.py NAMES_FILE

Each line of NAMES_FILE is a package name that someone wants to add.
The tool only compares names: it never downloads or installs anything.
A result of OK or UNKNOWN is not proof that a package is safe.
"""
import sys

from pkgtools import normalize

POPULAR = """
attrs bandit bcrypt beautifulsoup4 boto3 botocore certifi charset-normalizer
click colorama cryptography django fastapi flask flask-login httpx idna
itsdangerous jellyfish jinja2 lxml markupsafe matplotlib numpy openpyxl
packaging pandas pillow pip pip-audit pydantic pyjwt pytest python-dateutil
pyyaml requests rich scipy selenium setuptools six sqlalchemy tqdm urllib3
werkzeug
""".split()


def distance(a, b):
    """Number of single-character changes (insert, delete, replace, swap)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def classify(raw):
    """Return (verdict, explanation) for one proposed name."""
    name = normalize(raw)
    notes = []
    if "I" in raw:
        notes.append("capital I looks like small l")
    if name in POPULAR:
        if notes:
            return "SUSPICIOUS", "same letters as '%s', but %s" % (name, notes[0])
        if raw != name:
            return "OK", "same package as '%s' (pip ignores case, - _ .)" % name
        return "OK", "known popular package"
    for extra in ("python3-", "python-", "py-", "-python", "-py", "3"):
        base = name.replace(extra, "", 1)
        if base != name and base in POPULAR:
            return "SUSPICIOUS", "popular name '%s' with '%s' added" % (base, extra)
    limit = 1 if len(name) <= 5 else 2
    close = sorted((distance(name, p), p) for p in POPULAR)
    if close[0][0] <= limit:
        n, p = close[0]
        why = "looks like '%s' (%d change%s)" % (p, n, "" if n == 1 else "s")
        return "SUSPICIOUS", "; ".join([why] + notes)
    return "UNKNOWN", "not on the popular list: check by hand"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    count = 0
    with open(sys.argv[1], encoding="utf-8") as f:
        for line in f:
            raw = line.split("#", 1)[0].strip()
            if raw:
                verdict, why = classify(raw)
                count += verdict == "SUSPICIOUS"
                print("%-11s %-20s %s" % (verdict, raw, why))
    print()
    print("%d suspicious name(s). Do not install a package before checking it." % count)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
