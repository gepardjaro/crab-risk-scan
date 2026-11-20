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
from .sbom import generate

EXCLUDE = {".git", ".venv", "__pycache__", "node_modules"}
LIMIT = 1024 * 1024


def scan(root):
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
                    findings.extend(dict(path=rel, **asdict(hit)) for hit in hits)
                    scanned += 1
                except (SyntaxError, ValueError, RecursionError, OSError) as exc:
                    errors.append({"path": rel, "reason": type(exc).__name__})
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    return {"schema_version": 1, "files_scanned": scanned, "findings": findings,
            "errors": sorted(errors, key=lambda e: e["path"])}


def main():
    parser = argparse.ArgumentParser(prog="crab-risk-scan", description="CRAB — Code Risk Analysis Bot")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("scan", help="scan a local repository snapshot")
    command.add_argument("directory", type=Path)
    combined = sub.add_parser("collect", help="combine source checks and saved dependency findings")
    combined.add_argument("directory", type=Path)
    combined.add_argument("--trivy", type=Path, action="append", default=[], metavar="REPORT")
    inventory = sub.add_parser("sbom", help="catalog a local repository with Syft")
    inventory.add_argument("directory", type=Path)
    inventory.add_argument("--syft", type=Path, help="absolute path to a trusted Syft binary")
    inventory.add_argument("--output", type=Path, help="write CycloneDX JSON atomically to a file")
    args = parser.parse_args()
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
    report = scan(args.directory)
    if args.command == "collect":
        report = collect(report, args.trivy)
    print(json.dumps(report, indent=2))
    return 2 if report["errors"] else int(bool(report["findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
