---
name: integrate-report
description: Implement a CRAB adapter that imports saved scanner output for dependency, image or infrastructure findings.
---
Read the second milestone in docs/architecture.md. Identify one producer format and version. Start with saved synthetic clean, finding and malformed reports. Document which fields supply producer identity, advisory or rule ID, severity and location.

Keep the importer separate from source-file dispatch. Bound input size, validate field types and reject unexpected paths that escape the repository. Preserve producer severity and define a mapping for unknown values. Leave missing lines absent. Introduce a documented schema revision if version 1 cannot represent the data faithfully.

Exercise the adapter through its public entry point. Assert deterministic output and incomplete-scan precedence, redact embedded source and credentials, and document a working invocation with the fixture.
