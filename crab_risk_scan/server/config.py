"""Server settings from command-line arguments and the environment. Standard library only."""
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

UPLOAD_LIMIT = 32 * 1024 * 1024
STATIC_DIR = Path(__file__).with_name("static")


def default_data_dir():
    """Platform user data directory for the server database."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "crab-risk-scan"


def parse_scan_roots(value):
    """Split an os.pathsep-separated list of absolute directories."""
    roots = []
    for part in (value or "").split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        path = Path(part)
        if not path.is_absolute():
            raise ValueError(f"scan roots must be absolute paths: {part}")
        roots.append(Path(os.path.realpath(path)))
    return tuple(roots)


def _number(environ, name, default, kind=int, minimum=1):
    raw = environ.get(name)
    if raw in (None, ""):
        return default
    try:
        value = kind(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number") from None
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


@dataclass
class Settings:
    database_url: str
    data_dir: Path
    scan_roots: tuple = ()
    admin_username: str = "admin"
    admin_password: str | None = None
    session_hours: float = 12.0
    lease_seconds: int = 300
    max_attempts: int = 3
    scheduler: bool = True
    scheduler_interval: float = 30.0
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    upload_limit: int = UPLOAD_LIMIT
    static_dir: Path = field(default=STATIC_DIR)

    @classmethod
    def from_env(cls, *, database=None, data_dir=None, environ=None):
        environ = os.environ if environ is None else environ
        data = Path(data_dir or environ.get("CRAB_DATA_DIR") or default_data_dir())
        url = database or environ.get("CRAB_DATABASE_URL") or f"sqlite:///{(data / 'crab.db').as_posix()}"
        return cls(
            database_url=url,
            data_dir=data,
            scan_roots=parse_scan_roots(environ.get("CRAB_SCAN_ROOTS")),
            admin_username=(environ.get("CRAB_ADMIN_USERNAME") or "admin").strip().lower(),
            admin_password=environ.get("CRAB_ADMIN_PASSWORD") or None,
            session_hours=_number(environ, "CRAB_SESSION_HOURS", 12.0, float, 0.05),
            lease_seconds=_number(environ, "CRAB_LEASE_SECONDS", 300, int, 10),
            max_attempts=_number(environ, "CRAB_JOB_MAX_ATTEMPTS", 3, int, 1),
            scheduler=environ.get("CRAB_SCHEDULER", "1").strip().lower() not in ("0", "false", "no", "off"),
            scheduler_interval=_number(environ, "CRAB_SCHEDULER_INTERVAL", 30.0, float, 1),
        )
