"""Validation shared by the saved-report adapters."""
import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote

LEVELS = ("critical", "high", "medium", "low", "info", "unknown")
INVALID = (KeyError, TypeError, AttributeError, ValueError, OSError, RecursionError, IndexError)


def load_json(path, limit=16 * 1024 * 1024):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("expected regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file size limit")
    return json.loads(raw)


def array(value):
    if not isinstance(value, list):
        raise ValueError("expected JSON array")
    return value


def token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[\w@.+:/~^!-]{1,256}", value, re.ASCII):
        raise ValueError("invalid identifier")
    return value


def relative_path(value, root=None):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid path")
    if ".." in PurePosixPath(value.replace("\\", "/")).parts:
        raise ValueError("parent traversal")
    if root is not None and Path(value).is_absolute():
        value = Path(value).relative_to(root.resolve()).as_posix()
    path = PurePosixPath(value.replace("\\", "/"))
    if not path.parts or path.is_absolute() or PureWindowsPath(value).drive or ":" in str(path):
        raise ValueError("invalid path")
    return path.as_posix()


def positive_integer(value):
    if type(value) is not int or value < 1:
        raise ValueError("invalid position")
    return value


def fingerprint(parts):
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def package_url(ecosystem, name, version):
    kind = {"npm": "npm", "pip": "pypi", "pypi": "pypi", "poetry": "pypi",
            "cargo": "cargo", "crates.io": "cargo", "yarn": "npm", "pnpm": "npm"}.get(ecosystem.lower())
    if kind is None:
        return None
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return "pkg:" + kind + "/" + quote(name, safe="/.-_") + "@" + quote(version, safe=".-_")
