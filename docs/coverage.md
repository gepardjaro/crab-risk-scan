# Language coverage and integration plan

The ten rows define release scope. “Shipped” describes what CRAB can do today. The candidate column names upstream tools for the next adapter. A parser, a lockfile inventory and a security rule each provide different evidence. The initial source scanner only reads Python and Dockerfiles.

| Language or format | Shipped | Candidate engine and input | Gap and acceptance fixture |
|---|---|---|---|
| Python | One AST rule for an explicitly unverified TLS context | Bandit JSON for Python security rules. Opengrep for application-specific source and sink rules. Trivy/Syft for recognized package metadata. | Compare imports and aliases, locally rebound names and a clean TLS client. Retain Bandit rule, line, severity and confidence. |
| JavaScript | Dependency report import. npm lockfile inventory through Syft. | Opengrep for JS/JSX. SCA and SBOM use the lockfile. | Test a browser DOM sink, a server-side sink and their safe counterparts. Deduplicate workspace packages without losing the manifest path. |
| TypeScript | Same npm dependency evidence as JavaScript | Opengrep with TypeScript and TSX rules | Test a typed wrapper and a TSX component with a safe rendering path. Record framework and cross-file coverage separately. |
| Rust | Accepts Trivy language-package findings. Cargo inventory depends on cataloger evidence. | Opengrep for Rust source. OSV-Scanner or cargo-audit on Cargo.lock. | Macro-generated code, FFI and unsafe blocks need review. Test a scoped unsafe operation with a documented safe wrapper. Count advisory findings separately. |
| SQL | Planned | SQLFluff's parser with a fixed dialect and raw templater. Pinch rules over the parsed tree. | Begin with PostgreSQL GRANT to PUBLIC on an explicit relation. Pair a broad grant with a restricted grant. Dynamic SQL and application-built queries need host-language rules. Record dialect/templating failures as partial coverage. |
| Mojo | Research | Evaluate a versioned Mojo grammar against the project's compiler syntax. No general-purpose Mojo security ruleset was verified in this review. | Begin with a review signal at an explicit unsafe foreign-call boundary. Test real syntax, comments, strings and parser error nodes. Keep findings informational until paired fixtures establish precision. Inventory resolved Python interop packages separately. |
| HTML | Planned | Opengrep HTML rules over standalone markup | Start with insecure external form actions and a same-origin form. Distinguish framework templates and inline scripts. Preserve host-file locations when embedded-language mapping exists. |
| Bash | Planned | ShellCheck JSON, plus selected Opengrep Bash rules | Select security-relevant rule IDs and preserve native diagnostic levels. Exercise quoting, here-documents, shebang-only scripts and intentionally split arguments. |
| PowerShell | Planned | PSScriptAnalyzer with trusted built-in rules on .ps1 and .psm1, serialized diagnostic records | Check plaintext credential parameters and their secure forms. Preserve extent coordinates. Dynamic invocation, aliases and remoting limit static coverage. |
| Terraform | Planned | Checkov for HCL, .tf.json and Kubernetes manifests. Burrow handles configuration findings. | Start with one exposed and one restricted ingress rule. Preserve provider, logical resource address and source span. Unresolved modules and variables need explicit unknown status. |

## Shared coverage

Gitleaks is the proposed Sniffer engine across text formats. Drop secret values, source excerpts and tool messages at the adapter boundary. A secret signature says nothing about the surrounding language's SAST coverage. Exoskeleton will import Trivy image reports keyed by immutable image digest and affected package. Dockerfile checks belong to Burrow.

Shell owns the SBOM. Syft catalogs the repository using package metadata and writes CycloneDX JSON. Its lockfile support determines which direct and transitive components appear. It cannot infer every runtime download, vendored binary, Bash program or SQL extension from source text. Expose missing cataloger evidence as an inventory gap. For Terraform, model providers and modules separately from application packages. PowerShell Gallery and Mojo-native dependencies need ecosystem-specific identity and advisory mapping before a vulnerability-free claim is meaningful.

## Integration order

1. **Claws and Shell.** Add Bandit and Opengrep JSON adapters alongside the shipped Trivy dependency importer. Release each language only after fixtures record expected findings, clean cases and parse failures. Pin engine and rule-pack versions separately.
2. **Sniffer, Burrow and Exoskeleton.** Prioritize Gitleaks redaction, Checkov resource identity and Trivy image identity. Test two tools reporting one dependency and two images sharing one package.
3. **Pinch gap rules.** Add PostgreSQL policies first, then HTML templates and Mojo after parser validation. Publish the language, dialect, tested grammar, rule ID and unsupported cases with each pack.
4. **Crab Trap.** Add curated cross-engine mappings and SARIF export. A fixture must show two corroborating observations and two nearby, distinct findings. Keep the SBOM as a separate artifact linked by package URL and snapshot.

## Upstream references

- [Opengrep language list and analysis features](https://www.opengrep.dev/about.html) · [Bandit](https://bandit.readthedocs.io/en/latest/)
- [OSV-Scanner](https://github.com/google/osv-scanner) · [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- [SQLFluff](https://github.com/sqlfluff/sqlfluff) · [Mojo FFI safety](https://mojolang.static.modular.com/nightly/docs/manual/interop/safety/)
- [ShellCheck](https://github.com/koalaman/shellcheck) · [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)
- [Checkov](https://github.com/bridgecrewio/checkov) · [Gitleaks CLI](https://github.com/gitleaks/gitleaks) · [Trivy](https://github.com/aquasecurity/trivy)
- [Syft](https://github.com/anchore/syft) · [JavaScript cataloger evidence and limits](https://oss.anchore.com/docs/capabilities/javascript/)
