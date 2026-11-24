"""Reference tests for Lab 10.  Run from the lab10 folder:

    python3 -m unittest discover -s tests -v

They check portal/requirements-fixed.txt, portal/requirements-fixed.lock
and portal/app.py. On the starting files, 10 of the 19 tests fail.
"""
import os
import re
import sys
import unittest

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(LAB, "tools"))

from audit import find                                  # noqa: E402
from deptree import check                               # noqa: E402
from pkgtools import load_json, read_lock, read_requirements  # noqa: E402

PORTAL = os.path.join(LAB, "portal")
FIXED_TXT = os.path.join(PORTAL, "requirements-fixed.txt")
FIXED_LOCK = os.path.join(PORTAL, "requirements-fixed.lock")
ORIGINAL = {"certifi": "2022.9.24", "charset-normalizer": "2.1.1", "click": "8.1.3",
            "flask": "2.2.2", "idna": "3.4", "itsdangerous": "2.1.2",
            "jinja2": "3.1.2", "markupsafe": "2.1.1", "pyyaml": "5.3.1",
            "requests": "2.28.1", "urllib3": "1.26.12", "werkzeug": "2.2.2"}
AFFECTED = ["certifi", "flask", "idna", "jinja2", "pyyaml", "requests",
            "urllib3", "werkzeug"]


def app_code():
    """app.py without comments, so that a comment cannot pass a test."""
    with open(os.path.join(PORTAL, "app.py"), encoding="utf-8") as f:
        return "\n".join(line.split("#", 1)[0] for line in f)


class FixedLockTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lock = read_lock(FIXED_LOCK)
        cls.direct = read_requirements(FIXED_TXT)
        cls.problems = check(cls.direct, cls.lock, load_json("index.json"))
        cls.found = find(cls.lock, load_json("advisories.json")["advisories"])

    def test_01_original_lock_is_kept(self):
        self.assertEqual(read_lock(os.path.join(PORTAL, "requirements.lock")), ORIGINAL,
                         "do not edit requirements.lock: it is needed for the comparison")

    def test_02_direct_dependencies_listed(self):
        self.assertEqual(sorted(n for n, _, _ in self.direct),
                         ["flask", "pyyaml", "requests"])

    def test_03_direct_dependencies_pinned(self):
        self.assertEqual(self.problems["not_pinned"], [])

    def test_04_direct_pins_match_lock(self):
        for name, version, _ in self.direct:
            self.assertEqual(self.lock.get(name), version,
                             "%s: requirements-fixed.txt and the lock disagree" % name)

    def test_13_versions_known(self):
        self.assertEqual(self.problems["unknown"], [])

    def test_14_nothing_missing(self):
        self.assertEqual(self.problems["missing"], [])

    def test_15_no_conflicts(self):
        self.assertEqual(self.problems["conflict"], [])

    def test_16_nothing_unused(self):
        self.assertEqual(self.problems["unused"], [])

    def test_17_no_known_problems(self):
        self.assertEqual(self.problems["known_problem"], [])


def make_package_test(package):
    def test(self):
        left = ["%s %s" % (a["cve"], a["severity"]) for n, _, a, _ in self.found
                if n == package]
        self.assertEqual(left, [], "%s still has known vulnerabilities" % package)
    return test


for number, package in enumerate(AFFECTED, start=5):
    setattr(FixedLockTest, "test_%02d_no_vulnerabilities_%s" % (number, package),
            make_package_test(package))


class AppCodeTest(unittest.TestCase):

    def test_18_yaml_safe_load(self):
        code = app_code()
        self.assertNotIn("FullLoader", code)
        self.assertIsNone(re.search(r"yaml\.load\(", code),
                          "use yaml.safe_load for data from files and users")

    def test_19_no_debug_mode(self):
        self.assertIsNone(re.search(r"debug\s*=\s*True", app_code()),
                          "the debugger must not be switched on in the code")


if __name__ == "__main__":
    unittest.main()
