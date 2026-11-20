# Language coverage

Each row describes evidence CRAB can collect. A positive result identifies a reviewable construct or advisory. A clean result applies only to the selected rules, successfully parsed inputs and supplied engine reports.

| Language | Available evidence | Precision boundary |
|---|---|---|
| Python | Native TLS rule and Bandit JSON with confidence. Identical TLS call spans can correlate. | Native check matches the literal ssl name. Aliases and locally rebound names affect precision. Bandit rules bring their own semantics. |
| JavaScript | Opengrep pack covers DOM innerHTML writes, child_process.exec calls and React HTML sinks. Trivy/OSV and Syft cover supported npm manifests. | Review signals. The pack does not establish whether input was sanitized before it reached the sink. |
| TypeScript | Same pack parses TypeScript and TSX, including typed wrappers and React markup. | A clean component using textContent or rendered text stays clean under these rules. Cross-file framework flows require additional rules. |
| Rust | Opengrep matches explicit std::mem::transmute calls. OSV and Trivy ingest Cargo advisories. | Macros, aliases and other unsafe operations exceed the source rule. A conversion using from_bits is a clean fixture. |
| SQL | SQLFluff with fixed PostgreSQL dialect and raw text. Pinch flags GRANT on an explicitly named TABLE to the unquoted PUBLIC role. | Other dialects, implied table targets and application-built SQL need separate rules. Lexer/parser failures yield incomplete coverage. |
| Mojo | Experimental Tree-sitter rule locates direct external_call invocations, including subscripted forms. Severity is informational. | The pinned grammar accepts a subset of Mojo syntax. Error nodes yield incomplete coverage. Comments, strings and indirect FFI wrappers are outside this rule. |
| HTML | Native HTMLParser recognizes form action URLs starting with http://. Relative and HTTPS actions are clean. | Standalone markup only. Framework expression evaluation, script analysis and template source maps require separate engines. |
| Bash | ShellCheck JSON imports SC2046, SC2068, SC2086 and SC2294. | Selected argument-splitting and evaluation diagnostics. ShellCheck selects the dialect and handles quoting and here-documents. Report producer failures via the run manifest. |
| PowerShell | Imports projected PSScriptAnalyzer diagnostic extents. The supplied exporter selects the built-in plaintext-password rule. | Dynamic execution and remoting need additional rules. Review the exported rule selection when changing the ruleset. |
| Terraform | Checkov imports retain the check ID, framework, logical resource and line range. The live fixture compares open SSH ingress with a restricted CIDR. | Precision depends on Checkov's evaluations and available module/variable data. Unresolved deployment inputs do not imply deployed exposure. |

## Cross-cutting coverage

Gitleaks rule IDs and redacted locations can be imported for any text format. Checkov accepts Kubernetes results through the same configuration adapter. Trivy image imports cover OS and language packages with an immutable manifest digest. Source manifests and images with the same package stay in distinct correlation scopes.

Syft inventories supported package metadata. Standalone SQL, shell and HTML files rarely establish package identity. Runtime downloads, PowerShell Gallery module resolution, Mojo-native packages and Terraform providers/modules each need usable catalog evidence. CycloneDX output is independent of the set of vulnerable packages.

[Fixture and integration tests](../tests/) · [Producer formats, parsing dependencies and examples](integrations.md)
