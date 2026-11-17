"""OAuth provider for the MCP SDK's authorize/token handlers, plus client auth and RS checks.

- Exactly one static client; dynamic client registration and CIMD are off.
- ``redirect_uri`` must match the allowlist character for character.
- ``resource`` (RFC 8707) must equal the canonical MCP URL.
- PKCE S256 is enforced by the SDK's handlers (plain and missing PKCE are rejected).
- Codes: one-shot, 60 s, bound to client, redirect URI, code challenge and resource.
- Access tokens: opaque, 1 h, bound to the resource. Refresh tokens: 30 days, rotated on every
  use; reuse of a used refresh token revokes the whole token family.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
from typing import Any
from urllib.parse import unquote

from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    TokenVerifier,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.requests import Request

from .store import ACCESS_TTL, AuthStore, verify_secret

_LOGGER = logging.getLogger(__name__)


class OwnerOAuthProvider:
    """Implements the SDK's ``OAuthAuthorizationServerProvider`` protocol."""

    def __init__(self, store: AuthStore, *, public_url: str, resource: str, scope: str) -> None:
        self.store = store
        self.public_url = public_url.rstrip("/")
        self.resource = resource
        self.scope = scope

    # -- client -------------------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        credentials = self.store.credentials()
        if credentials is None or not hmac.compare_digest(
            credentials.client_id.encode(), client_id.encode()
        ):
            return None
        return OAuthClientInformationFull(
            client_id=credentials.client_id,
            client_secret=None,  # verified against the argon2 hash by StaticClientAuthenticator
            token_endpoint_auth_method="client_secret_post",
            redirect_uris=[AnyUrl(uri) for uri in credentials.redirect_uris],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=self.scope,
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise NotImplementedError("dynamic client registration is disabled")

    # -- authorize ------------------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        credentials = self.store.credentials()
        allowed = credentials.redirect_uris if credentials else ()
        redirect_uri = str(params.redirect_uri)
        if redirect_uri not in allowed:
            raise AuthorizeError("invalid_request", "redirect_uri is not allowed")
        if params.resource != self.resource:
            raise AuthorizeError("invalid_target", "resource must be this server's MCP URL")
        scopes = params.scopes or [self.scope]
        if scopes != [self.scope]:
            raise AuthorizeError("invalid_scope", f"only {self.scope} is supported")
        request_id, _ = self.store.create_pending(
            {
                "client_id": client.client_id,
                "redirect_uri": redirect_uri,
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "code_challenge": params.code_challenge,
                "state": params.state,
                "scopes": scopes,
                "resource": params.resource,
            }
        )
        return f"{self.public_url}/login?request={request_id}"

    def issue_code(self, params: dict[str, Any]) -> str:
        """Called by the consent page after a successful login. Returns the redirect URL."""
        code, _ = self.store.create_code(params)
        return construct_redirect_uri(
            params["redirect_uri"], code=code, state=params.get("state"), iss=self.public_url
        )

    # -- token ----------------------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        consumed = self.store.consume_code(authorization_code)
        if consumed is None:
            return None
        family, data, expires_at = consumed
        return _Code(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=expires_at,
            client_id=data["client_id"],
            code_challenge=data["code_challenge"],
            redirect_uri=AnyUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
            resource=data["resource"],
            subject="owner",
            family=family,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        family = authorization_code.family if isinstance(authorization_code, _Code) else ""
        if not family or authorization_code.resource != self.resource:
            raise TokenError("invalid_grant", "authorization code is not valid")
        return self._tokens(family, client.client_id, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = self.store.token(refresh_token)
        if row is None or row.kind != "refresh":
            return None
        if row.revoked or row.used_at is not None:
            # A used or revoked refresh token is presented again: treat it as stolen.
            self.store.revoke_family(row.family)
            return None
        if row.client_id != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=row.client_id,
            scopes=row.scopes,
            expires_at=int(row.expires_at),
            resource=row.resource,
            subject="owner",
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        row = self.store.use_refresh_token(refresh_token.token)
        if row is None:
            raise TokenError("invalid_grant", "refresh token is not valid")
        return self._tokens(row.family, client.client_id, scopes or row.scopes)

    def _tokens(self, family: str, client_id: str, scopes: list[str]) -> OAuthToken:
        access, refresh = self.store.issue_tokens(
            family=family, client_id=client_id, scopes=scopes, resource=self.resource
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TTL,
            refresh_token=refresh,
            scope=" ".join(scopes),
        )

    # -- resource server --------------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = self.store.token(token)
        if (
            row is None
            or row.kind != "access"
            or row.revoked
            or row.expires_at < self.store.clock()
            or row.resource != self.resource
        ):
            return None
        return AccessToken(
            token=token,
            client_id=row.client_id,
            scopes=row.scopes,
            expires_at=int(row.expires_at),
            resource=row.resource,
            subject="owner",
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        row = self.store.token(token.token)
        if row is not None:
            self.store.revoke_family(row.family)


class _Code(AuthorizationCode):
    family: str


class StaticClientAuthenticator(ClientAuthenticator):
    """Client authentication at /token: ``client_secret_basic`` or ``client_secret_post``,
    verified against the argon2id hash. Unknown clients and wrong secrets look the same."""

    def __init__(self, provider: OwnerOAuthProvider) -> None:
        super().__init__(provider)  # type: ignore[arg-type]
        self.store = provider.store
        self._provider = provider

    async def authenticate_request(self, request: Request) -> OAuthClientInformationFull:
        form = await request.form()
        form_id = form.get("client_id")
        form_secret = form.get("client_secret")
        header = request.headers.get("Authorization", "")

        client_id: str | None = form_id if isinstance(form_id, str) else None
        secret: str | None = None
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode()
                basic_id, basic_secret = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError, binascii.Error):
                raise AuthenticationError("invalid client authentication") from None
            basic_id, secret = unquote(basic_id), unquote(basic_secret)
            if client_id is not None and client_id != basic_id:
                raise AuthenticationError("invalid client authentication")
            client_id = basic_id
            if isinstance(form_secret, str):
                raise AuthenticationError("use one client authentication method")
            method = "client_secret_basic"
        elif isinstance(form_secret, str):
            secret = form_secret
            method = "client_secret_post"
        else:
            method = "none"

        credentials = self.store.credentials()
        id_ok = bool(
            credentials
            and client_id
            and hmac.compare_digest(credentials.client_id.encode(), client_id.encode())
        )
        secret_ok = verify_secret(
            credentials.client_secret_hash if credentials else None, secret or ""
        )
        if not (id_ok and secret_ok and secret):
            raise AuthenticationError("invalid client authentication")
        _LOGGER.info("token request authenticated with %s", method)
        client = await self._provider.get_client(str(client_id))
        if client is None:  # pragma: no cover - checked above
            raise AuthenticationError("invalid client authentication")
        return client


class StoreTokenVerifier(TokenVerifier):
    def __init__(self, provider: OwnerOAuthProvider) -> None:
        self._provider = provider

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self._provider.load_access_token(token)


class StaticBearerVerifier(TokenVerifier):
    """Fallback mode for clients that can send a fixed Authorization header."""

    def __init__(self, secret: str, resource: str, scope: str) -> None:
        if len(secret) < 32:
            raise ValueError("the static bearer token must be at least 32 characters")
        self._secret = secret.encode()
        self._resource = resource
        self._scope = scope

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(self._secret, token.encode()):
            return None
        return AccessToken(
            token="static", client_id="static", scopes=[self._scope], resource=self._resource
        )
