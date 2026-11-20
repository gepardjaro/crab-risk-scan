"""Trusted built-in rules. Each check receives text, never a running application."""
import ast
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    rule: str
    line: int
    severity: str
    message: str


def python_tls(source):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if isinstance(owner, ast.Name) and owner.id == "ssl" and node.func.attr == "_create_unverified_context":
            yield Hit("CRAB-PY-001", node.lineno, "medium",
                      "Review use of an unverified TLS context. Prefer ssl.create_default_context().")


def docker_user(source):
    last_user = None
    for line, instruction in enumerate(source.splitlines(), 1):
        if re.match(r"^\s*FROM\s", instruction, re.I):
            last_user = None
        match = re.fullmatch(r"\s*USER\s+([^\s]+)\s*", instruction, re.I)
        if match:
            last_user = (line, match[1].split(":")[0])
    if last_user and last_user[1] in {"root", "0"}:
        yield Hit("CRAB-CTR-001", last_user[0], "medium",
                  "Final stage explicitly selects root. Review whether a non-root USER is sufficient.")


def detector(path):
    if path.suffix == ".py":
        return python_tls
    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        return docker_user
    return None
