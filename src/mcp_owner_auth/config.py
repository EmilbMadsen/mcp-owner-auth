"""Configuration for one MCP server protected by mcp-owner-auth."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(RuntimeError):
    """The server cannot start with this configuration."""


@dataclass(frozen=True)
class OwnerAuthConfig:
    """Everything the auth layer needs to know about the server it protects.

    ``app_name`` appears on the login and consent pages and in the authenticator app.
    ``command`` is the console script, used in hints like ``<command> auth init``.
    ``scope`` is the single OAuth scope tokens get, e.g. ``garmin:read``.
    ``consent`` completes the sentence "Claude wants <consent>." on the consent page.
    """

    public_url: str
    state_dir: Path
    app_name: str
    command: str
    scope: str = "mcp:read"
    consent: str = "access to this server"
    auth_mode: str = "oauth"
    static_bearer_file: Path | None = None
    allowed_cidrs: tuple[Network, ...] = ()
    client_ip_header: str | None = None

    @property
    def resource(self) -> str:
        """The canonical MCP URL (RFC 8707 resource indicator)."""
        return f"{self.public_url}/mcp"

    @property
    def host(self) -> str:
        return urlsplit(self.public_url).netloc

    @property
    def auth_db(self) -> Path:
        return self.state_dir / "auth.db"

    @property
    def audit_log(self) -> Path:
        return self.state_dir / "audit.log"

    @classmethod
    def from_env(
        cls,
        prefix: str,
        *,
        state_dir: Path,
        app_name: str,
        command: str,
        scope: str = "mcp:read",
        consent: str = "access to this server",
        env: Mapping[str, str] | None = None,
    ) -> OwnerAuthConfig:
        """Read ``<prefix>_PUBLIC_URL``, ``_AUTH_MODE``, ``_STATIC_BEARER_FILE``,
        ``_ALLOWED_CIDRS`` and ``_CLIENT_IP_HEADER`` from the environment."""
        environment = os.environ if env is None else env

        def get(name: str) -> str:
            return environment.get(f"{prefix}_{name}", "").strip()

        public_url = get("PUBLIC_URL").rstrip("/")
        parts = urlsplit(public_url)
        local = parts.hostname in ("localhost", "127.0.0.1")
        if not parts.netloc or parts.path or (parts.scheme != "https" and not local):
            raise ConfigError(
                f"Set {prefix}_PUBLIC_URL to the public base URL, e.g. https://mcp.example.com "
                "(https, no path; http is allowed only for localhost)."
            )
        mode = get("AUTH_MODE") or "oauth"
        if mode not in ("oauth", "static_bearer"):
            raise ConfigError(f"{prefix}_AUTH_MODE must be 'oauth' or 'static_bearer'.")
        bearer_file = get("STATIC_BEARER_FILE")
        if mode == "static_bearer" and not bearer_file:
            raise ConfigError(f"static_bearer mode needs {prefix}_STATIC_BEARER_FILE.")
        cidrs: list[Network] = []
        for raw in get("ALLOWED_CIDRS").split(","):
            if raw.strip():
                try:
                    cidrs.append(ipaddress.ip_network(raw.strip(), strict=False))
                except ValueError as exc:
                    raise ConfigError(f"Invalid CIDR in {prefix}_ALLOWED_CIDRS: {raw!r}") from exc
        return cls(
            public_url=public_url,
            state_dir=state_dir,
            app_name=app_name,
            command=command,
            scope=scope,
            consent=consent,
            auth_mode=mode,
            static_bearer_file=Path(bearer_file).expanduser() if bearer_file else None,
            allowed_cidrs=tuple(cidrs),
            client_ip_header=get("CLIENT_IP_HEADER") or None,
        )
