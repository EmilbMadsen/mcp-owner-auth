"""The remote (Streamable HTTP) application: MCP endpoint, OAuth routes and security layers.

Routes:

- ``/mcp``: the MCP endpoint (bearer token required)
- ``/.well-known/oauth-protected-resource/mcp``: RFC 9728 metadata
- ``/.well-known/oauth-authorization-server``: RFC 8414 metadata
- ``/authorize``, ``/token``: OAuth 2.1 with PKCE (S256) for the one static client
- ``/login``, ``/consent``: password + TOTP sign-in and consent
- ``/healthz``: liveness for the container (returns ``ok``, nothing else)

Layers around everything: Host-header allowlist, request body limit, request timeout, optional IP
allowlist on ``/mcp`` and ``/token``, and a JSON-lines audit log of tool calls.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import anyio
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.routes import build_metadata
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import ConfigError, OwnerAuthConfig
from .provider import (
    OwnerOAuthProvider,
    StaticBearerVerifier,
    StaticClientAuthenticator,
    StoreTokenVerifier,
)
from .store import AuthStore
from .web import client_ip, login_routes

_LOGGER = logging.getLogger(__name__)

MAX_BODY_BYTES = 256 * 1024
REQUEST_TIMEOUT_SECONDS = 120.0
IP_RESTRICTED_PATHS = ("/mcp", "/token")


# -- ASGI layers ------------------------------------------------------------------------------


async def _plain(send: Send, status: int, text: str) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
    )
    await send({"type": "http.response.body", "body": text.encode()})


class GuardMiddleware:
    """Host allowlist, body size limit, timeout and optional IP allowlist for every request."""

    def __init__(self, app: ASGIApp, config: OwnerAuthConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        host = request.headers.get("host", "")
        path = scope.get("path", "")
        if host != self.config.host and path != "/healthz":  # container health check
            await _plain(send, 421, "Misdirected request")
            return
        if self.config.allowed_cidrs and path.startswith(IP_RESTRICTED_PATHS):
            try:
                ip = ipaddress.ip_address(client_ip(request, self.config.client_ip_header))
                allowed = any(ip in network for network in self.config.allowed_cidrs)
            except ValueError:
                allowed = False
            if not allowed:
                await _plain(send, 403, "Forbidden")
                return
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            await _plain(send, 413, "Request body too large")
            return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY_BYTES:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            with anyio.fail_after(REQUEST_TIMEOUT_SECONDS):
                await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await _plain(send, 413, "Request body too large")
        except TimeoutError:
            _LOGGER.warning("request timed out: %s", path)
            if not started:
                await _plain(send, 504, "Timeout")


class _BodyTooLarge(Exception):
    pass


class AuditMiddleware:
    """MCP middleware writing one JSON line per tool call: time, tool, arguments, status,
    duration. Tool arguments here are dates, IDs, limits and flags; results are never logged."""

    def __init__(self, path: Path) -> None:
        self.path = path

    async def __call__(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> Any:
        if getattr(ctx, "method", None) != "tools/call":
            return await call_next(ctx)
        params = ctx.params or {}
        started = time.monotonic()
        status = "ok"
        try:
            result = await call_next(ctx)
            if getattr(result, "is_error", False) or (
                isinstance(result, dict) and result.get("isError")
            ):
                status = "tool_error"
            return result
        except BaseException:
            status = "error"
            raise
        finally:
            self._write(
                {
                    "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "tool": str(params.get("name", "")),
                    "arguments": _safe_arguments(params.get("arguments")),
                    "status": status,
                    "ms": round((time.monotonic() - started) * 1000),
                }
            )

    def _write(self, entry: dict[str, Any]) -> None:
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            _LOGGER.warning("could not write the audit log")


def _safe_arguments(arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, bool | int | float) or (isinstance(value, str) and len(value) <= 40):
            safe[str(key)] = value
        else:
            safe[str(key)] = "<omitted>"
    return safe


# -- application ------------------------------------------------------------------------------


def build_app(server: MCPServer[Any], config: OwnerAuthConfig) -> ASGIApp:
    """The complete ASGI app for ``server``: MCP endpoint, OAuth routes and all layers."""
    # model_validate keeps the issuer exactly as configured (no trailing slash): RFC 8414 and
    # RFC 9207 compare issuers as plain strings.
    auth_settings = AuthSettings.model_validate(
        {
            "issuer_url": config.public_url,
            "resource_server_url": config.resource,
            "required_scopes": [config.scope],
            "validate_token_resource": True,
            "client_registration_options": ClientRegistrationOptions(enabled=False),
            "revocation_options": RevocationOptions(enabled=False),
        }
    )

    async def healthz(_: Request) -> Response:
        return PlainTextResponse("ok")

    routes: list[Route] = [Route("/healthz", healthz, methods=["GET"])]
    if config.auth_mode == "static_bearer":
        assert config.static_bearer_file is not None
        secret = config.static_bearer_file.read_text(encoding="utf-8").strip()
        verifier: Any = StaticBearerVerifier(secret, config.resource, config.scope)
    else:
        store = AuthStore(config.auth_db)
        if not store.initialized():
            raise ConfigError(f"OAuth is not set up. Run `{config.command} auth init` first.")
        provider = OwnerOAuthProvider(
            store, public_url=config.public_url, resource=config.resource, scope=config.scope
        )
        verifier = StoreTokenVerifier(provider)
        metadata = build_metadata(
            auth_settings.issuer_url,
            None,
            ClientRegistrationOptions(enabled=False),
            RevocationOptions(enabled=False),
        )
        token_handler = TokenHandler(provider, StaticClientAuthenticator(provider))  # type: ignore[arg-type]
        routes += [
            Route("/.well-known/oauth-authorization-server", MetadataHandler(metadata).handle),
            Route(
                "/authorize",
                AuthorizationHandler(provider).handle,  # type: ignore[arg-type]
                methods=["GET", "POST"],
            ),
            Route("/token", token_handler.handle, methods=["POST"]),
            *login_routes(store, provider, config),
        ]

    server.middleware[:] = [m for m in server.middleware if not isinstance(m, AuditMiddleware)]
    server.middleware.append(AuditMiddleware(config.audit_log))
    app = server._lowlevel_server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=MAX_BODY_BYTES,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[config.host],
            allowed_origins=[config.public_url, "https://claude.ai"],
        ),
        auth=auth_settings,
        token_verifier=verifier,
        custom_starlette_routes=routes,
    )
    return GuardMiddleware(app, config)


def serve(server: MCPServer[Any], config: OwnerAuthConfig, host: str, port: int) -> None:
    """Run ``server`` over Streamable HTTP with uvicorn (blocking)."""
    import uvicorn

    app = build_app(server, config)
    logging.getLogger(__name__).info("serving %s (auth: %s)", config.resource, config.auth_mode)
    uvicorn.run(
        app,
        host=host,
        port=port,
        proxy_headers=False,
        server_header=False,
        date_header=False,
        timeout_keep_alive=5,
        limit_concurrency=64,
        log_level="warning",
    )
