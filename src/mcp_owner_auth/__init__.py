"""Single-user OAuth 2.1 for self-hosted MCP servers.

One owner, one static client (e.g. claude.ai), password + TOTP login, short-lived opaque tokens
with rotation and reuse detection, and an emergency ``auth revoke-all``. See the README.
"""

from .app import build_app, serve
from .config import ConfigError, OwnerAuthConfig

__all__ = ["ConfigError", "OwnerAuthConfig", "build_app", "serve"]
