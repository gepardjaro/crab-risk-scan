"""Collect one snapshot, retain provenance, and account for incomplete inputs."""
import json
from collections import Counter

from .adapters import ADAPTERS
from .evidence import INVALID, LEVELS, array, fingerprint, load_json, relative_path, token
from .triage import groups, link_inventory, reviewed, policy


def manifest(path):
    data = load_json(path)
    if data["version"] != 1:
        raise ValueError("unsupported manifest")
    inputs = []
    for entry in array(data["reports"]):
        name = entry["producer"]
        if name not in ADAPTERS or entry["status"] not in {"complete", "partial", "failed"}:
            raise ValueError("invalid producer metadata")
        location = relative_path(entry["file"])
        file = path.parent / location
        if not file.resolve().is_relative_to(path.parent.resolve()):
            raise ValueError("report outside manifest folder")
        inputs.append((name, file, {k: token(entry[k]) for k in ("version", "rule_pack", "status")}))
    return token(data["revision"]), inputs


def collect(local, paths=(), *, root=None, inputs=(), run_manifest=None, revision=None,
            inventory=None, baseline=None, threshold="unknown"):
    findings = []
    errors = list(local["errors"])
    occurrences = Counter((h["path"], h["line"], h["rule"]) for h in local["findings"])
    for hit in local["findings"]:
        key = ["crab", hit["path"], hit["line"], hit["rule"]]
        if occurrences[tuple(key[1:])] > 1 and "byte_offset" in hit:
            key.extend([hit["byte_offset"], hit["end_byte_offset"]])
        module = "Burrow" if hit["rule"] == "CRAB-CTR-001" else "Claws"
        findings.append(dict(hit, fingerprint=fingerprint(key), producer="crab", module=module,
                             producer_version="0.2.0", rule_pack="pinch-v1",
                             original_severity=hit["severity"]))
    inputs = [("trivy", p, {}) for p in paths] + list(inputs)
    if run_manifest:
        try:
            declared, listed = manifest(run_manifest)
            if revision and revision != declared:
                raise ValueError("snapshot mismatch")
            revision = declared
            inputs.extend(listed)
        except INVALID:
            errors.append({"reason": "invalid_run_manifest"})
    imports = []
    for index, (name, path, meta) in enumerate(inputs, 1):
        entry = {"input": index, "producer": name, "status": "failed",
                 "producer_version": meta.get("version"), "rule_pack": meta.get("rule_pack")}
        imports.append(entry)
        if meta.get("status") == "failed":
            errors.append({"input": index, "producer": name, "reason": "producer_failed"})
            continue
        try:
            batch = ADAPTERS[name](load_json(path), root)
            if batch.version and meta.get("version") and batch.version != meta["version"]:
                raise ValueError("version mismatch")
            version = batch.version or meta.get("version")
            entry.update(producer_version=version, targets=batch.targets, status="complete")
            if batch.partial or meta.get("status") == "partial":
                entry["status"] = "partial"
                errors.append({"input": index, "producer": name, "reason": "producer_partial"})
            for hit in batch.findings:
                hit.update(producer_version=version, rule_pack=meta.get("rule_pack"), inputs=[index])
            findings.extend(batch.findings)
        except INVALID:
            errors.append({"input": index, "producer": name, "reason": "invalid_report"})
    findings.sort(key=lambda f: (LEVELS.index(f["severity"]), f["path"] or "", f.get("line") or 0,
                                 f["rule"], f["fingerprint"], json.dumps(f, sort_keys=True)))
    unique = {}
    for hit in findings:
        kept = unique.setdefault(hit["fingerprint"], hit)
        if kept is not hit and "inputs" in hit:
            kept["inputs"].extend(hit["inputs"])
            if "aliases" in hit:
                kept["aliases"] = sorted(set(kept.get("aliases", []) + hit["aliases"]))
    observations = list(unique.values())
    for hit in observations:
        if "inputs" in hit:
            hit["inputs"] = sorted(set(hit["inputs"]))
    report = {"schema_version": 2, "files_scanned": local["files_scanned"], "imports": imports,
              "revision": revision, "findings": observations, "groups": groups(observations, revision),
              "errors": errors}
    if inventory:
        try:
            report["inventory"] = link_inventory(load_json(inventory, 32 * 1024 * 1024), observations)
        except INVALID:
            errors.append({"reason": "invalid_inventory"})
    suppressed = set()
    if baseline:
        try:
            suppressed = reviewed(load_json(baseline))
        except INVALID:
            errors.append({"reason": "invalid_baseline"})
    policy(report, threshold, suppressed)
    return report
