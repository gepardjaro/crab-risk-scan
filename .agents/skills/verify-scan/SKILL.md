---
name: verify-scan
description: Verify a CRAB scanner or reporting change at the CLI boundary, including coverage, privacy and CI exit status.
---
Read the change and identify affected file types and contracts. Run python -m unittest discover -s tests -v. Run python -m crab_risk_scan scan examples/demo twice, capture stdout and status separately, and compare the JSON.

Use temporary clean, finding and malformed inputs to confirm statuses 0, 1 and 2. Combine a finding with a malformed file and confirm both survive in the report with status 2. For traversal changes include a symlink and an oversized supported file. For reporting changes place a synthetic canary in a comment and confirm its value is absent from diagnostics and findings.

Report the exact command, expected and observed status, coverage counts and discrepancies. Turn a newly discovered failure into a focused regression fixture.
