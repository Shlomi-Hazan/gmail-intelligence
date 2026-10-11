---
name: gmail-project-check
description: Run the local, offline quality gate for Gmail Intelligence - syntax check, unit tests, full secret scan, diff whitespace check - and report actionable failures. Use before committing or opening a PR.
allowed-tools: Bash(python3:*), Bash(python:*), Bash(.venv/bin/python:*), Bash(gmail-intelligence:*), Bash(git diff:*), Bash(git status:*), Read, Grep
---

# gmail-project-check

Local and offline: no network, no Gmail, no paid services. Report problems; do not edit code to fix them unless the user asks.

Run from the repository root with the project venv active (`. .venv/bin/activate`; first time: `pip install -e .`):

```bash
python -m compileall -q src tests scripts
python -I -m unittest discover -s tests
python -I scripts/scan_secrets.py --all
git diff --check
gmail-intelligence doctor
```

Report per step: pass/fail, the exact count from the unittest summary line, and for each failure the file, the line and the likely cause. A secret-scanner finding prints only path, line and rule; never try to print or reveal the matched value. Scanner exit 2 means a scanner error, which blocks commits just like a finding.

Finish with one line: all checks passed, or what must be fixed. A passing result does not imply the code is secure; suggest `gmail-security-review` for security-relevant changes.
