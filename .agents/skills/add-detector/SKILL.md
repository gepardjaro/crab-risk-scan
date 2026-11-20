---
name: add-detector
description: Add or tune a built-in CRAB static check, including its dispatch, rule identifier, precision fixtures and coverage documentation.
---
Describe the exact source construct and one plausible lookalike. Check crab_risk_scan/rules.py for an existing rule ID and reusable parser. Add paired fixtures to tests/test_scan.py and exercise the real CLI.

Implement the check as a text-to-Hit iterator. Extend detector(path) for a new file family. When multiple checks share a family, compose them behind the same dispatch entry. Report a stable ID, 1-based line and remediation. Keep matched source out of the message.

Run the tests and scan examples/demo. Update the docs/coverage.md matrix with supported syntax and one known blind spot. Summarize expected false positives and any change to existing findings.
