# Scanner integrations and policy

Run each producer against the same snapshot with its own trusted configuration. Keep report files outside the scanned directory. CRAB runs its built-in rules when collecting reports and runs Syft for the separate SBOM command.

| Input to collect | Expected producer output | Notes |
|---|---|---|
| --bandit | Bandit JSON, with results and errors | Keeps test_id, confidence and byte extent when supplied. |
| --opengrep | Opengrep native JSON with version, results and errors | Use the installed pack or a trusted external pack. |
| --osv | OSV-Scanner JSON, lockfile sources | Keeps advisory IDs and aliases. Absolute source paths must map inside the supplied checkout on the same platform. |
| --trivy | Trivy schema 2 filesystem JSON, language-package results | Accepts vulnerability reports. Use the library package filter. |
| --trivy-image | Trivy schema 2 container_image JSON | Requires one unambiguous manifest digest in Metadata.RepoDigests. Supply vulnerability-only output. |
| --gitleaks | Gitleaks v8 JSON array | Use directory scanning on the current snapshot. Raw secret values, snippets and commit descriptions are discarded. |
| --checkov | Checkov JSON block or array of framework blocks | Imports failed_checks and flags reported parsing errors. |
| --shellcheck | ShellCheck JSON array, with start/end coordinates | Imports a selected security-relevant subset. |
| --psscriptanalyzer | Projected JSON array with string Severity and Extent positions | Use the PowerShell exporter below. |

To use the packaged rules, resolve the rule-pack path from the trusted installation before scanning the target. These examples assume a POSIX shell running from a trusted checkout.

```sh
PACK=$(crab-risk-scan rules)
(cd "$TARGET" && opengrep scan --config "$PACK" --json .) > opengrep.json
(cd "$TARGET" && bandit -r . -f json) > bandit.json
(cd "$TARGET" && checkov -d . --framework terraform --output json) > terraform.json
(cd "$TARGET" && gitleaks dir . --redact --report-format json --report-path "$REPORT_DIR/leaks.json")
pwsh -NoProfile -File examples/export-psscriptanalyzer.ps1 "$TARGET" "$REPORT_DIR/powershell.json"
crab-risk-scan collect "$TARGET" --opengrep opengrep.json --bandit bandit.json --checkov terraform.json
```

The caller should interpret each producer's documented exit codes. A finding can yield a nonzero status even when the engine completed. A manifest records the distinction. `--run-manifest` requires version, rule pack and status for every listed input. Files are relative to the manifest directory. Status accepts complete, partial or failed. Partial reports can contribute findings. A failed producer can be listed even when its file is absent.

```json
{
  "version": 1,
  "revision": "example-commit",
  "reports": [
    {"producer": "bandit", "version": "1.8.6", "rule_pack": "bandit-default", "status": "complete", "file": "bandit.json"},
    {"producer": "opengrep", "version": "2.0.0", "rule_pack": "crab-v1", "status": "complete", "file": "opengrep.json"}
  ]
}
```

Direct flags are repeatable. Their status is imported unless the report exposes a problem. A null version or rule pack means that the input did not supply it. A malformed or out-of-scope report produces an error for that input and preserves results from the others.

## Pinch parsers

Install `python -m pip install '.[pinch]'` from the trusted scanner checkout. PostgreSQL parsing uses SQLFluff 3.4.2. For Mojo, supply the absolute path to a compiled trusted grammar with `--mojo-grammar`. CI builds commit `99fe918e69f087f910ef3b11eba31eb0d7e54edf` of HerringtonDarkholme/tree-sitter-mojo and uses py-tree-sitter 0.25.2. Linux build commands from the grammar checkout follow.

```sh
cc -O2 -fPIC -Isrc -c src/parser.c -o parser.o
c++ -O2 -fPIC -Isrc -c src/scanner.cc -o scanner.o
c++ -shared parser.o scanner.o -o mojo.so
```

Keep the library outside the scanned snapshot. A missing parser, missing grammar or unsupported syntax yields exit 2 for eligible files.

## Baselines, thresholds and annotations

Take the fingerprint from a reviewed observation in the JSON report. Store reviewed entries in a trusted policy file with this shape. Replace the placeholder with the complete 64-character lowercase SHA-256 value.

```json
{"version": 1, "suppressions": [{"fingerprint": "REPLACE_WITH_REVIEWED_FINGERPRINT", "reviewer": "security-team", "reason": "Reviewed compensating control, ticket SEC-123"}]}
```

```sh
crab-risk-scan collect "$TARGET" --run-manifest run.json --inventory snapshot.cdx.json --baseline baseline.json --fail-on high
crab-risk-scan collect "$TARGET" --run-manifest run.json --format sarif > crab.sarif
```

Severity order is critical, high, medium, low, info and unknown. The default includes all observations. A high gate fails on high and critical unsuppressed observations. Gitleaks and some Checkov and OSV records have no upstream severity. Review unknowns explicitly when choosing a gate. Suppressions apply per observation, so an independent corroborating finding can still fail the gate.

[Bandit JSON](https://bandit.readthedocs.io/en/latest/formatters/json.html) · [Opengrep JSON](https://www.opengrep.dev/docs/flags/json.html) · [OSV output](https://google.github.io/osv-scanner/output/) · [Trivy reporting](https://trivy.dev/docs/v0.72/guide/configuration/reporting/) · [Mojo grammar](https://github.com/HerringtonDarkholme/tree-sitter-mojo)
