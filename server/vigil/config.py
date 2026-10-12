"""Runtime configuration, read once from environment variables.

Every setting has a safe default so `docker compose up` works with no input.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
BUNDLED_DATA = PACKAGE_DIR / "data"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"VIGIL_{name}", default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = _env(name, "1" if default else "0").strip().lower()
    return v in ("1", "true", "yes", "on")


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "./var")))
    rules_dirs: list[Path] = field(default_factory=list)

    # HTTP / TLS
    host: str = field(default_factory=lambda: _env("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("PORT", 8443))
    tls: bool = field(default_factory=lambda: _env_bool("TLS", True))
    tls_cert: str = field(default_factory=lambda: _env("TLS_CERT", ""))
    tls_key: str = field(default_factory=lambda: _env("TLS_KEY", ""))
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL", ""))

    # Auth
    admin_user: str = field(default_factory=lambda: _env("ADMIN_USER", "admin"))
    admin_password: str = field(default_factory=lambda: _env("ADMIN_PASSWORD", ""))
    enrollment_token: str = field(default_factory=lambda: _env("ENROLLMENT_TOKEN", ""))
    session_hours: int = field(default_factory=lambda: _env_int("SESSION_HOURS", 12))

    # Syslog receiver (for firewalls, routers, appliances)
    syslog_port: int = field(default_factory=lambda: _env_int("SYSLOG_PORT", 5514))
    syslog_enabled: bool = field(default_factory=lambda: _env_bool("SYSLOG", True))

    # Retention / pipeline
    retention_days: int = field(default_factory=lambda: _env_int("RETENTION_DAYS", 30))
    incident_window_minutes: int = field(default_factory=lambda: _env_int("INCIDENT_WINDOW_MIN", 60))
    alert_dedup_minutes: int = field(default_factory=lambda: _env_int("ALERT_DEDUP_MIN", 30))
    agent_silence_minutes: int = field(default_factory=lambda: _env_int("AGENT_SILENCE_MIN", 15))

    # Enrichment
    geoip_dir: str = field(default_factory=lambda: _env("GEOIP_DIR", ""))
    threatintel_enabled: bool = field(default_factory=lambda: _env_bool("THREATINTEL", True))
    threatintel_refresh_hours: int = field(default_factory=lambda: _env_int("THREATINTEL_REFRESH_H", 6))
    abuseipdb_key: str = field(default_factory=lambda: _env("ABUSEIPDB_KEY", ""))

    # UEBA
    ueba_enabled: bool = field(default_factory=lambda: _env_bool("UEBA", True))
    ueba_min_observations: int = field(default_factory=lambda: _env_int("UEBA_MIN_OBS", 20))
    ueba_threshold: int = field(default_factory=lambda: _env_int("UEBA_THRESHOLD", 70))

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.rules_dirs:
            extra = [Path(p) for p in _env("RULES_DIRS", "").split(os.pathsep) if p]
            default = PACKAGE_DIR.parent / "rules"
            self.rules_dirs = ([default] if default.exists() else []) + extra
        if not self.enrollment_token:
            self.enrollment_token = self._persisted_secret("enrollment_token")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "vigil.db"

    @property
    def secret_key(self) -> bytes:
        return self._persisted_secret("secret_key").encode()

    def _persisted_secret(self, name: str) -> str:
        """Generate a secret once and keep it in the data dir across restarts."""
        path = self.data_dir / f".{name}"
        if path.exists():
            return path.read_text().strip()
        value = secrets.token_urlsafe(32)
        path.write_text(value)
        path.chmod(0o600)
        return value


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def set_settings(s: Settings) -> None:
    global _settings
    _settings = s
