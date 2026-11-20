import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from .rules import detector
from .reporting import collect
from .adapters import ADAPTERS
from .evidence import LEVELS, token
from .pinch import html, mojo, postgres
from .triage import sarif
from .sbom import generate

EXCLUDE = {".git", ".venv", "__pycache__", "node_modules"}
LIMIT = 1024 * 1024


def scan(root, *, extended=False, grammar=None):
    findings = []
    errors = []
    scanned = 0

    def walk_error(exc):
        errors.append({"path": Path(exc.filename).relative_to(root).as_posix(), "reason": "walk_error"})

    if root.is_symlink() or not root.is_dir():
        errors.append({"path": ".", "reason": "expected_directory"})
    else:
        for folder, dirs, files in os.walk(root, onerror=walk_error):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDE and not (Path(folder) / d).is_symlink())
            for name in sorted(files):
                path = Path(folder) / name
                check = detector(path)
                if extended:
                    check = {".html": html, ".htm": html, ".sql": postgres,
                             ".mojo": lambda source: mojo(source, grammar),
                             ".🔥": lambda source: mojo(source, grammar)}.get(path.suffix.lower(), check)
                if check is None:
                    continue
                rel = path.relative_to(root).as_posix()
                try:
                    if not stat.S_ISREG(path.lstat().st_mode):
                        continue
                    with path.open("rb") as stream:
                        raw = stream.read(LIMIT + 1)
                    if len(raw) > LIMIT:
                        errors.append({"path": rel, "reason": "size_limit"})
                        continue
                    hits = list(check(raw.decode("utf-8-sig")))
                    for hit in hits:
                        fields = asdict(hit)
                        for field in ("byte_offset", "end_byte_offset", "end_line"):
                            if not extended or fields[field] is None:
                                fields.pop(field)
                        findings.append(dict(path=rel, **fields))
                    scanned += 1
                except (SyntaxError, ValueError, RecursionError, OSError, ImportError, AttributeError) as exc:
                    errors.append({"path": rel, "reason": type(exc).__name__})
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    return {"schema_version": 1, "files_scanned": scanned, "findings": findings,
            "errors": sorted(errors, key=lambda e: e["path"])}


def main():
    parser = argparse.ArgumentParser(prog="crab-risk-scan", description="CRAB — Code Risk Analysis Bot")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("rules", help="print the installed Opengrep rule-pack path")
    command = sub.add_parser("scan", help="scan a local repository snapshot")
    command.add_argument("directory", type=Path)
    combined = sub.add_parser("collect", help="scan a snapshot and correlate saved scanner reports")
    combined.add_argument("directory", type=Path)
    for producer in ADAPTERS:
        combined.add_argument("--" + producer, type=Path, action="append", default=[], metavar="REPORT")
    combined.add_argument("--run-manifest", type=Path, help="versioned scanner inputs and completion status")
    combined.add_argument("--revision", type=token, help="snapshot identity for correlation")
    combined.add_argument("--inventory", type=Path, help="link a CycloneDX JSON SBOM for this snapshot")
    combined.add_argument("--baseline", type=Path, help="reviewed exact-fingerprint suppressions")
    combined.add_argument("--fail-on", choices=LEVELS, default="unknown", help="minimum severity for exit 1")
    combined.add_argument("--format", choices=("json", "sarif"), default="json")
    combined.add_argument("--mojo-grammar", type=Path, help="absolute path to a trusted Mojo grammar library")
    inventory = sub.add_parser("sbom", help="catalog a local repository with Syft")
    inventory.add_argument("directory", type=Path)
    inventory.add_argument("--syft", type=Path, help="absolute path to a trusted Syft binary")
    inventory.add_argument("--output", type=Path, help="write CycloneDX JSON atomically to a file")
    args = parser.parse_args()
    if args.command == "rules":
        print(Path(__file__).with_name("opengrep-v1.yml").resolve())
        return 0
    if args.command == "sbom":
        try:
            bom = generate(args.directory, args.syft)
            if args.output:
                temp_path = None
                try:
                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False,
                                                     dir=args.output.parent) as stream:
                        temp_path = Path(stream.name)
                        json.dump(bom, stream, indent=2)
                        stream.write("\n")
                    temp_path.replace(args.output)
                finally:
                    if temp_path:
                        temp_path.unlink(missing_ok=True)
            else:
                print(json.dumps(bom, indent=2))
        except (OSError, subprocess.SubprocessError, ValueError, RecursionError) as exc:
            reason = str(exc) if type(exc) is ValueError else type(exc).__name__
            print(f"SBOM generation failed: {reason}", file=sys.stderr)
            return 2
        return 0
    if args.command == "collect":
        grammar = args.mojo_grammar
        if grammar and (not grammar.is_absolute() or not grammar.is_file()
                        or grammar.resolve().is_relative_to(args.directory.resolve())):
            combined.error("--mojo-grammar requires a trusted library outside the scanned directory")
        inputs = [(name, path, {}) for name in ADAPTERS
                  for path in getattr(args, name.replace("-", "_"))]
        report = collect(scan(args.directory, extended=True, grammar=grammar), root=args.directory,
                         inputs=inputs, run_manifest=args.run_manifest, revision=args.revision,
                         inventory=args.inventory, baseline=args.baseline, threshold=args.fail_on)
        print(json.dumps(sarif(report) if args.format == "sarif" else report, indent=2))
        return 2 if report["errors"] else int(report["policy"]["actionable"] > 0)
    report = scan(args.directory)
    print(json.dumps(report, indent=2))
    return 2 if report["errors"] else int(bool(report["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
