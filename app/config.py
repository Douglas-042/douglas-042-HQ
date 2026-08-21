"""Runtime configuration, all overridable by environment variables."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file() -> None:
    """Read .env into the environment, without adding a dependency.

    A real environment variable always wins, so a systemd unit or a docker
    -e flag overrides the file rather than the other way round — the opposite
    is a long afternoon wondering why a change had no effect.
    """
    path = BASE_DIR / ".env"
    if not path.exists():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        # An unreadable .env should not stop the console starting; the
        # defaults below still produce a working install.
        pass


_load_env_file()


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _persistent_secret(data_dir: Path) -> str:
    """A session key that survives a restart without shipping one in the package.

    Generating a fresh key each start logs everybody out on every restart.
    Shipping a fixed key in .env is worse: every deployment that downloaded the
    same package would share it, and anyone holding it could forge a session
    cookie for someone else's console. So the key is generated once, here, and
    kept on disk with owner-only permissions.
    """
    path = Path(data_dir) / "session.key"
    try:
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if len(existing) >= 32:
                return existing
        path.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_hex(32)
        path.write_text(value, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass  # Windows and some mounts do not support this
        return value
    except OSError:
        # Read-only data directory: fall back to a per-process key. Sessions
        # will not survive a restart, which is visible and recoverable, rather
        # than silently sharing a key.
        return secrets.token_hex(32)


class Settings:
    app_name = "Douglas-042"
    version = "1.0"

    data_dir = Path(_env("DOUGLAS_DATA_DIR", str(BASE_DIR / "data")))
    bundle_dir = data_dir / "bundles"
    static_dir = BASE_DIR / "static"
    agent_dir = BASE_DIR / "agent"

    database_url = _env("DOUGLAS_DATABASE_URL", f"sqlite:///{data_dir / 'douglas.db'}")

    # Console login. Change these in production via env.
    console_user = _env("DOUGLAS_CONSOLE_USER", "admin")
    console_email = _env("DOUGLAS_CONSOLE_EMAIL", "admin@localhost")
    console_password = _env("DOUGLAS_CONSOLE_PASSWORD", "douglas042")
    session_secret = _env("DOUGLAS_SESSION_SECRET", "") or _persistent_secret(data_dir)
    session_hours = _env_int("DOUGLAS_SESSION_HOURS", 12)

    # Fixed enrollment token so deploy scripts stay stable across restarts.
    enrollment_token = _env("DOUGLAS_ENROLLMENT_TOKEN", "")

    # An agent that has not checked in for this long is marked offline.
    agent_timeout_seconds = _env_int("DOUGLAS_AGENT_TIMEOUT", 120)
    heartbeat_seconds = _env_int("DOUGLAS_HEARTBEAT_INTERVAL", 20)

    # Public URL agents call back on. Used when rendering deploy commands.
    public_url = _env("DOUGLAS_PUBLIC_URL", "")

    max_upload_mb = _env_int("DOUGLAS_MAX_UPLOAD_MB", 512)


def _compute_build_stamp() -> str:
    """A short hash of the front-end assets.

    Derived from the files themselves rather than a hand-maintained number, so
    it can never drift out of sync with what is actually being served.
    """
    import hashlib

    digest = hashlib.sha256()
    for name in ("index.html", "css/app.css", "js/api.js",
                 "js/ui.js", "js/views.js", "js/app.js"):
        path = Settings.static_dir / name
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(name.encode())
    return digest.hexdigest()[:10]


Settings.build_stamp = _compute_build_stamp()

settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
settings.bundle_dir.mkdir(parents=True, exist_ok=True)
