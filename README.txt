PCAO 3307 - Lab 10: Analysis of dependencies and vulnerable project libraries
==========================================================================

Everything here works offline with Python 3.8 or newer. Nothing needs to be
installed. Run every command from this folder (lab10).

portal/                    the project we study (a small Flask program)
  app.py                   the program
  requirements.txt         packages that app.py imports directly
  requirements.lock        every installed package with its exact version
  requirements-fixed.txt   your copy to fix (Task 5)
  requirements-fixed.lock  your copy to fix (Task 5)
  candidates.txt           names that teammates want to add (Task 3)
  downloads.lock           hashes of two internal packages (Task 4)
  downloads/               the two downloaded package files (Task 4)

tools/
  deptree.py      dependency tree and lock file checks
  audit.py        offline vulnerability audit (like pip-audit)
  sbom.py         SBOM in CycloneDX JSON format
  typo_check.py   look-alike package names (typosquatting)
  verify_hashes.py  SHA-256 check of downloaded files
  advisories.json 17 real advisories (a frozen teaching snapshot)
  index.json      a tiny offline index: versions and what they need

tests/test_lab10.py   reference tests:
  python3 -m unittest discover -s tests -v

Do NOT install anything from candidates.txt or downloads/.
Do NOT edit requirements.lock: it is the "before" state.
