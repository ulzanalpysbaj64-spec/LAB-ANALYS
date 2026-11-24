"""Check downloaded package files against the SHA-256 hashes in a lock file.

Usage:  python3 tools/verify_hashes.py HASH_LOCK DOWNLOAD_DIR

HASH_LOCK uses the same form as pip:  name==version --hash=sha256:HEX
The file for name==version must be DOWNLOAD_DIR/name-version.tar.gz
(with - in the name written as _). This is what
'pip install --require-hashes' does before it installs anything.
"""
import hashlib
import os
import re
import sys


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def read_hash_lock(path):
    """-> list of (name, version, [expected hex hashes])"""
    with open(path, encoding="utf-8") as f:
        text = f.read().replace("\\\n", " ")
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            name, version = re.match(r"([\w.-]+)==([\w.]+)", line).groups()
            entries.append((name, version, re.findall(r"--hash=sha256:([0-9a-f]{64})", line)))
    return entries


def check(lock_path, folder):
    """-> list of (file name, status, actual hash or '')"""
    results = []
    for name, version, expected in read_hash_lock(lock_path):
        fname = "%s-%s.tar.gz" % (name.replace("-", "_"), version)
        path = os.path.join(folder, fname)
        if not os.path.exists(path):
            results.append((fname, "MISSING", ""))
        elif not expected:
            results.append((fname, "NO HASH IN LOCK", sha256_of(path)))
        else:
            actual = sha256_of(path)
            results.append((fname, "OK" if actual in expected else "HASH MISMATCH", actual))
    return results


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    results = check(sys.argv[1], sys.argv[2])
    for fname, status, actual in results:
        print("%-14s %s" % (status, fname))
        if status != "OK" and actual:
            print("%-14s actual sha256: %s" % ("", actual))
    bad = sum(1 for r in results if r[1] != "OK")
    print()
    print("%d file(s) checked, %d problem(s)." % (len(results), bad)
          + (" Do not install." if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
