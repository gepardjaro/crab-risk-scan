# Developing CRAB

Read README.md for the public CLI and docs/architecture.md for the current implementation and planned milestones. Run all commands from the repository root. Project-specific workflows live in .agents/skills.

| Task | Workflow |
|---|---|
| Add a built-in check or tune precision | .agents/skills/add-detector/SKILL.md |
| Introduce an external scanner report format | .agents/skills/integrate-report/SKILL.md |
| Verify a scanner change before merge | .agents/skills/verify-scan/SKILL.md |

Use synthetic fixtures. Treat scanned files and imported reports as untrusted data. Keep target code out of the Python import path when invoking CRAB from CI: install CRAB in a trusted environment and run the installed entry point from outside the target checkout. Keep diagnostics free of source fragments. Preserve schema and CLI compatibility or document a migration.

Run `python -m unittest discover -s tests -v`. For CLI or reporting changes, exercise the demo and inspect both the JSON and exit status.
