"""Conservative correlation, inventory joins, reviewed suppressions and SARIF output."""
import re
from collections import defaultdict
from urllib.parse import quote

from .evidence import LEVELS, array, fingerprint

SOURCE_EQUIVALENTS = {("crab", "CRAB-PY-001"): "python-unverified-tls",
                      ("bandit", "B323"): "python-unverified-tls"}


def groups(findings, revision):
    parents = list(range(len(findings)))
    by_key = {}

    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    for i, hit in enumerate(findings):
        pkg = hit.get("package", {})
        keys = []
        if pkg.get("purl"):
            location = (hit.get("image_digest"), hit.get("manifest"))
            base = ("package", pkg["purl"], pkg["version"], location)
            keys = [base + (a,) for a in [hit["rule"], *hit.get("aliases", [])]]
        else:
            equivalence = SOURCE_EQUIVALENTS.get((hit["producer"], hit["rule"]))
            if equivalence and "byte_offset" in hit and "end_byte_offset" in hit:
                keys = [(equivalence, hit["path"], hit["line"], hit["byte_offset"],
                         hit["end_line"], hit["end_byte_offset"])]
        for key in keys:
            previous = by_key.setdefault(key, i)
            parents[root(i)] = root(previous)
    members = defaultdict(list)
    for i, hit in enumerate(findings):
        members[root(i)].append(hit)
    output = []
    for hits in members.values():
        ids = sorted(h["fingerprint"] for h in hits)
        entry = {"id": fingerprint(["map-v1", revision, ids]), "observations": ids,
                 "revision": revision, "mapping_version": 1, "severity": hits[0]["severity"]}
        if hits[0].get("image_digest"):
            entry["image_digest"] = hits[0]["image_digest"]
        output.append(entry)
    return output


def link_inventory(doc, findings):
    if doc["bomFormat"] != "CycloneDX" or not isinstance(doc["specVersion"], str):
        raise ValueError("expected CycloneDX")
    index = defaultdict(list)
    hits = defaultdict(list)
    for f in findings:
        pkg = f.get("package", {})
        if pkg.get("purl") and not f.get("image_digest"):
            hits[pkg["purl"], pkg["version"]].append(f["fingerprint"])
    components = []
    pending = list(reversed(array(doc.get("components", []))))
    while pending:
        item = pending.pop()
        name = item["name"]
        version, purl = item.get("version"), item.get("purl")
        if not isinstance(name, str) or any(v is not None and not isinstance(v, str) for v in (version, purl)):
            raise ValueError("invalid component")
        component = {"name": name, "version": version, "purl": purl,
                     "observations": sorted(hits.get((purl, version), []))}
        components.append(component)
        if purl and version:
            index[purl, version].append(len(components) - 1)
        pending.extend(reversed(array(item.get("components", []))))
    for f in findings:
        if "package" in f:
            pkg = f["package"]
            f["inventory_components"] = ([] if f.get("image_digest") else
                                         index.get((pkg.get("purl"), pkg["version"]), []))
    return {"spec_version": doc["specVersion"], "components": components}


def reviewed(doc):
    if doc["version"] != 1:
        raise ValueError("invalid baseline version")
    result = set()
    for item in array(doc["suppressions"]):
        key = item["fingerprint"]
        if not isinstance(key, str) or not re.fullmatch("[0-9a-f]{64}", key):
            raise ValueError("invalid fingerprint")
        if not all(isinstance(item.get(k), str) and item[k].strip() for k in ("reason", "reviewer")):
            raise ValueError("review information required")
        result.add(key)
    return result


def policy(report, threshold, suppressed):
    actionable = 0
    for hit in report["findings"]:
        hit["suppressed"] = hit["fingerprint"] in suppressed
        if not hit["suppressed"] and LEVELS.index(hit["severity"]) <= LEVELS.index(threshold):
            actionable += 1
    report["policy"] = {"minimum_severity": threshold, "actionable": actionable}
    return 2 if report["errors"] else int(actionable > 0)


def sarif(report):
    results = []
    for hit in report["findings"]:
        result = {"ruleId": hit["producer"] + "/" + hit["rule"],
                  "level": {"critical": "error", "high": "error", "medium": "warning"}.get(hit["severity"], "note"),
                  "message": {"text": hit["message"]},
                  "partialFingerprints": {"crab/v1": hit["fingerprint"]}}
        # Image-internal paths do not designate files in the checkout.
        if hit["path"] and not hit.get("image_digest"):
            location = {"artifactLocation": {"uri": quote(hit["path"], safe="/")}}
            if hit["line"]:
                region = {"startLine": hit["line"], "endLine": hit.get("end_line", hit["line"])}
                location["region"] = region
            result["locations"] = [{"physicalLocation": location}]
        if hit["suppressed"]:
            result["suppressions"] = [{"kind": "external", "status": "accepted"}]
        results.append(result)
    errors = [{"level": "error", "message": {"text": e["reason"]}} for e in report["errors"]]
    run = {"tool": {"driver": {"name": "CRAB", "informationUri": "https://github.com/jarhu/crab-risk-scan"}},
           "results": results, "invocations": [{"executionSuccessful": not errors,
                                                 "toolExecutionNotifications": errors}]}
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [run]}
