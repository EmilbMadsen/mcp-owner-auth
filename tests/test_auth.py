"""Remote access: OAuth flow, login, token lifecycle and the security layers.

Everything runs in-process through Starlette's TestClient against https://mcp.test.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
from collections.abc import Generator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest
from starlette.testclient import TestClient

from mcp_owner_auth import ConfigError, OwnerAuthConfig, build_app
from mcp_owner_auth.store import AuthStore

from .dummy import server as dummy_server

PUBLIC = "https://mcp.test"
RESOURCE = f"{PUBLIC}/mcp"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"
USERNAME = "owner"
PASSWORD = "correct horse battery staple"
CLIENT_ID = "client-" + "a" * 30
CLIENT_SECRET = "secret-" + "b" * 40
TOTP_SECRET = pyotp.random_base32()

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


class Clock:
    """Store clock that moves 31 s on every login, so each TOTP code is fresh."""

    def __init__(self) -> None:
        import time

        self.now = time.time()

    def __call__(self) -> float:
        return self.now


@dataclass
class Env:
    client: TestClient
    store: AuthStore
    clock: Clock
    state: Path

    def totp(self) -> str:
        self.clock.now += 31
        return pyotp.TOTP(TOTP_SECRET).at(self.clock.now)


def make_config(state: Path, **overrides: Any) -> OwnerAuthConfig:
    values: dict[str, Any] = {
        "public_url": PUBLIC,
        "state_dir": state,
        "app_name": "Dummy",
        "command": "dummy-mcp",
        "scope": "dummy:read",
        "consent": "read-only access to your dummy data",
        "client_ip_header": "X-Test-IP",
    }
    values.update(overrides)
    return OwnerAuthConfig(**values)


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


def build_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **config: Any) -> Generator[Env]:
    state = tmp_path / "state"
    clock = Clock()
    store = AuthStore(state / "auth.db", clock=clock)
    store.save_credentials(
        username=USERNAME,
        password=PASSWORD,
        totp_secret=TOTP_SECRET,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    monkeypatch.setattr("mcp_owner_auth.app.AuthStore", lambda path: store)
    app = build_app(dummy_server, make_config(state, **config))
    with TestClient(app, base_url=PUBLIC, follow_redirects=False) as client:
        yield Env(client, store, clock, state)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield from build_env(tmp_path, monkeypatch)


def authorize_params(challenge: str, **overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz",
        "resource": RESOURCE,
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v != ""}


def csrf_of(html: str) -> str:
    match = re.search(r'name=csrf value="([^"]+)"', html)
    assert match, html
    return match.group(1)


def login(env: Env, challenge: str, *, password: str = PASSWORD) -> tuple[str, Any]:
    """Authorize -> login page -> submit credentials. Returns (request id, response)."""
    response = env.client.get("/authorize", params=authorize_params(challenge))
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(f"{PUBLIC}/login?request=")
    request_id = parse_qs(urlsplit(location).query)["request"][0]
    page = env.client.get(f"/login?request={request_id}")
    assert page.status_code == 200
    form = {
        "request": request_id,
        "csrf": csrf_of(page.text),
        "username": USERNAME,
        "password": password,
        "totp": env.totp(),
    }
    return request_id, env.client.post("/login", data=form)


def get_code(env: Env, challenge: str) -> str:
    request_id, response = login(env, challenge)
    assert response.status_code == 200, response.text
    consent = env.client.post(
        "/consent",
        data={"request": request_id, "csrf": csrf_of(response.text), "decision": "allow"},
    )
    assert consent.status_code == 302
    query = parse_qs(urlsplit(consent.headers["location"]).query)
    assert consent.headers["location"].startswith(CALLBACK)
    assert query["state"] == ["xyz"] and query["iss"] == [PUBLIC]
    return query["code"][0]


def exchange(env: Env, code: str, verifier: str, *, basic: bool = False) -> Any:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CALLBACK,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }
    headers = {}
    if basic:
        raw = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        headers["Authorization"] = f"Basic {raw}"
    else:
        data["client_secret"] = CLIENT_SECRET
    return env.client.post("/token", data=data, headers=headers)


def refresh(env: Env, token: str) -> Any:
    return env.client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )


def tokens(env: Env) -> dict[str, Any]:
    verifier, challenge = pkce()
    response = exchange(env, get_code(env, challenge), verifier)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def mcp(env: Env, access_token: str | None) -> Any:
    headers = dict(MCP_HEADERS)
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return env.client.post("/mcp", json=INIT, headers=headers)


# -- metadata and the protected resource --------------------------------------------------------


def test_metadata(env: Env) -> None:
    server = env.client.get("/.well-known/oauth-authorization-server").json()
    assert server["issuer"] == PUBLIC
    assert server["authorization_endpoint"] == f"{PUBLIC}/authorize"
    assert server["token_endpoint"] == f"{PUBLIC}/token"
    assert server["code_challenge_methods_supported"] == ["S256"]
    assert "registration_endpoint" not in server
    assert set(server["token_endpoint_auth_methods_supported"]) == {
        "client_secret_post",
        "client_secret_basic",
    }
    resource = env.client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource["resource"] == RESOURCE
    assert resource["authorization_servers"] == [PUBLIC]


def test_mcp_without_token_is_401_with_resource_metadata(env: Env) -> None:
    response = mcp(env, None)
    assert response.status_code == 401
    header = response.headers["www-authenticate"]
    assert header.startswith("Bearer") and "oauth-protected-resource/mcp" in header
    assert mcp(env, "not-a-token").status_code == 401


def test_dynamic_registration_is_off(env: Env) -> None:
    assert env.client.post("/register", json={"redirect_uris": [CALLBACK]}).status_code in (
        404,
        405,
    )


# -- the happy path -------------------------------------------------------------------------------


def test_full_flow_with_client_secret_post(env: Env) -> None:
    body = tokens(env)
    assert body["token_type"].lower() == "bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "dummy:read"
    response = mcp(env, body["access_token"])
    assert response.status_code == 200, response.text
    assert response.json()["result"]["serverInfo"]["name"] == "dummy"


def test_full_flow_with_client_secret_basic(env: Env) -> None:
    verifier, challenge = pkce()
    response = exchange(env, get_code(env, challenge), verifier, basic=True)
    assert response.status_code == 200, response.text


def test_deny_redirects_with_access_denied(env: Env) -> None:
    _, challenge = pkce()
    request_id, response = login(env, challenge)
    consent = env.client.post(
        "/consent",
        data={"request": request_id, "csrf": csrf_of(response.text), "decision": "deny"},
    )
    query = parse_qs(urlsplit(consent.headers["location"]).query)
    assert query["error"] == ["access_denied"] and "code" not in query


# -- /authorize validation ------------------------------------------------------------------------


def test_missing_pkce_is_rejected(env: Env) -> None:
    response = env.client.get("/authorize", params=authorize_params(""))
    assert response.status_code in (302, 400)
    assert "login" not in response.headers.get("location", "")
    assert "invalid_request" in (response.headers.get("location", "") + response.text)


def test_plain_pkce_is_rejected(env: Env) -> None:
    _, challenge = pkce()
    response = env.client.get(
        "/authorize", params=authorize_params(challenge, code_challenge_method="plain")
    )
    assert "login" not in response.headers.get("location", "")
    assert "invalid_request" in (response.headers.get("location", "") + response.text)


@pytest.mark.parametrize(
    "redirect",
    [
        "https://evil.example/callback",
        "https://claude.ai/api/mcp/auth_callback/",
        "https://claude.ai/api/mcp/auth_callback?x=1",
        "http://claude.ai/api/mcp/auth_callback",
    ],
)
def test_wrong_redirect_uri_never_redirects(env: Env, redirect: str) -> None:
    _, challenge = pkce()
    response = env.client.get(
        "/authorize", params=authorize_params(challenge, redirect_uri=redirect)
    )
    assert response.status_code == 400
    assert "location" not in response.headers


@pytest.mark.parametrize("resource", ["https://mcp.test", "https://other.test/mcp", ""])
def test_wrong_resource_is_rejected(env: Env, resource: str) -> None:
    _, challenge = pkce()
    response = env.client.get("/authorize", params=authorize_params(challenge, resource=resource))
    assert "login" not in response.headers.get("location", "")
    assert "invalid_target" in response.headers.get("location", "")


def test_unknown_client_is_rejected(env: Env) -> None:
    _, challenge = pkce()
    response = env.client.get("/authorize", params=authorize_params(challenge, client_id="nope"))
    assert response.status_code == 400


# -- /token -------------------------------------------------------------------------------------


def test_wrong_code_verifier_burns_the_code(env: Env) -> None:
    verifier, challenge = pkce()
    code = get_code(env, challenge)
    wrong = exchange(env, code, pkce()[0])
    assert wrong.status_code == 400 and wrong.json()["error"] == "invalid_grant"
    retry = exchange(env, code, verifier)
    assert retry.status_code == 400 and retry.json()["error"] == "invalid_grant"


def test_code_reuse_revokes_issued_tokens(env: Env) -> None:
    verifier, challenge = pkce()
    code = get_code(env, challenge)
    first = exchange(env, code, verifier).json()
    assert mcp(env, first["access_token"]).status_code == 200
    second = exchange(env, code, verifier)
    assert second.status_code == 400 and second.json()["error"] == "invalid_grant"
    assert mcp(env, first["access_token"]).status_code == 401
    assert refresh(env, first["refresh_token"]).status_code == 400


def test_expired_code(env: Env) -> None:
    verifier, challenge = pkce()
    env.clock.now -= 3600  # codes created now expired an hour ago in real time
    code = get_code(env, challenge)
    response = exchange(env, code, verifier)
    assert response.status_code == 400 and "expired" in response.json()["error_description"]


def test_code_bound_to_redirect_uri(env: Env) -> None:
    verifier, challenge = pkce()
    code = get_code(env, challenge)
    response = env.client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://evil.example/callback",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("client_id", "secret"),
    [(CLIENT_ID, "wrong"), ("someone-else", CLIENT_SECRET), (CLIENT_ID, "")],
)
def test_client_authentication(env: Env, client_id: str, secret: str) -> None:
    verifier, challenge = pkce()
    code = get_code(env, challenge)
    response = env.client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CALLBACK,
            "client_id": client_id,
            "client_secret": secret,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 401 and response.json()["error"] == "invalid_client"


def test_refresh_rotation_and_reuse_detection(env: Env) -> None:
    first = tokens(env)
    rotated = refresh(env, first["refresh_token"])
    assert rotated.status_code == 200, rotated.text
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert mcp(env, second["access_token"]).status_code == 200

    reuse = refresh(env, first["refresh_token"])  # an attacker replays the old refresh token
    assert reuse.status_code == 400 and reuse.json()["error"] == "invalid_grant"
    assert mcp(env, second["access_token"]).status_code == 401  # whole family revoked
    assert refresh(env, second["refresh_token"]).status_code == 400


def test_access_token_expires(env: Env) -> None:
    body = tokens(env)
    env.clock.now += 3601
    assert mcp(env, body["access_token"]).status_code == 401


def test_revoke_all_takes_effect_immediately(env: Env) -> None:
    body = tokens(env)
    assert mcp(env, body["access_token"]).status_code == 200
    AuthStore(env.store.path).revoke_all()  # what `auth revoke-all` does, from another process
    assert mcp(env, body["access_token"]).status_code == 401
    assert refresh(env, body["refresh_token"]).status_code == 400


def test_secrets_are_stored_as_hashes(env: Env) -> None:
    body = tokens(env)
    raw = b"".join(p.read_bytes() for p in env.state.glob("auth.db*"))
    for secret in (PASSWORD, CLIENT_SECRET, body["access_token"], body["refresh_token"]):
        assert secret.encode() not in raw
    assert env.store.path.stat().st_mode & 0o077 == 0


# -- login ----------------------------------------------------------------------------------------


def test_wrong_password_gives_generic_error(env: Env) -> None:
    _, challenge = pkce()
    _, response = login(env, challenge, password="wrong password!")
    assert response.status_code == 401
    assert "Sign-in failed" in response.text
    assert "password" not in re.sub(r"<input[^>]*>|<label>[^<]*", "", response.text).lower()


def test_wrong_username_looks_the_same(env: Env) -> None:
    _, challenge = pkce()
    response = env.client.get("/authorize", params=authorize_params(challenge))
    request_id = parse_qs(urlsplit(response.headers["location"]).query)["request"][0]
    page = env.client.get(f"/login?request={request_id}")
    result = env.client.post(
        "/login",
        data={
            "request": request_id,
            "csrf": csrf_of(page.text),
            "username": "admin",
            "password": PASSWORD,
            "totp": env.totp(),
        },
    )
    assert result.status_code == 401 and "Sign-in failed" in result.text


def test_totp_code_cannot_be_replayed(env: Env) -> None:
    _, challenge = pkce()
    _, response = login(env, challenge)
    assert response.status_code == 200
    code = pyotp.TOTP(TOTP_SECRET).at(env.clock.now)  # the code that was just used
    page = env.client.get(
        "/login?request="
        + parse_qs(
            urlsplit(
                env.client.get("/authorize", params=authorize_params(challenge)).headers["location"]
            ).query
        )["request"][0]
    )
    request_2 = re.search(r'name=request value="([^"]+)"', page.text)
    assert request_2
    replay = env.client.post(
        "/login",
        data={
            "request": request_2.group(1),
            "csrf": csrf_of(page.text),
            "username": USERNAME,
            "password": PASSWORD,
            "totp": code,
        },
    )
    assert replay.status_code == 401


@pytest.mark.parametrize("tamper", ["form", "cookie"])
def test_csrf_is_required(env: Env, tamper: str) -> None:
    _, challenge = pkce()
    response = env.client.get("/authorize", params=authorize_params(challenge))
    request_id = parse_qs(urlsplit(response.headers["location"]).query)["request"][0]
    page = env.client.get(f"/login?request={request_id}")
    form = {
        "request": request_id,
        "csrf": csrf_of(page.text),
        "username": USERNAME,
        "password": PASSWORD,
        "totp": env.totp(),
    }
    if tamper == "form":
        form["csrf"] = "forged"
    else:
        env.client.cookies.clear()
    assert env.client.post("/login", data=form).status_code == 403


def test_consent_requires_login(env: Env) -> None:
    _, challenge = pkce()
    response = env.client.get("/authorize", params=authorize_params(challenge))
    request_id = parse_qs(urlsplit(response.headers["location"]).query)["request"][0]
    page = env.client.get(f"/login?request={request_id}")
    consent = env.client.post(
        "/consent", data={"request": request_id, "csrf": csrf_of(page.text), "decision": "allow"}
    )
    assert consent.status_code == 400 and "code=" not in consent.headers.get("location", "")


def test_rate_limit_per_ip(env: Env) -> None:
    _, challenge = pkce()
    for _ in range(5):
        _, response = login(env, challenge, password="wrong password!")
        assert response.status_code == 401
    _, blocked = login(env, challenge)  # correct credentials, but rate limited
    assert blocked.status_code == 429


def test_global_lockout_and_unlock(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    _, challenge = pkce()
    for attempt in range(20):
        env.client.headers["X-Test-IP"] = f"10.0.0.{attempt}"
        _, response = login(env, challenge, password="wrong password!")
        assert response.status_code == 401
    env.client.headers["X-Test-IP"] = "10.0.1.1"
    response = env.client.get("/authorize", params=authorize_params(challenge))
    assert env.client.get(response.headers["location"].removeprefix(PUBLIC)).status_code == 423
    env.store.unlock()
    _, ok = login(env, challenge)
    assert ok.status_code == 200


def test_login_page_security_headers(env: Env) -> None:
    _, challenge = pkce()
    response = env.client.get("/authorize", params=authorize_params(challenge))
    page = env.client.get(response.headers["location"].removeprefix(PUBLIC))
    assert page.headers["x-frame-options"] == "DENY"
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "form-action 'self'" in csp
    assert "<script" not in page.text
    cookie = page.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie


def test_expired_request_id(env: Env) -> None:
    assert env.client.get("/login?request=unknown").status_code == 400


# -- layers ---------------------------------------------------------------------------------------


def test_wrong_host_is_refused(env: Env) -> None:
    response = env.client.get("/token", headers={"Host": "evil.test"})
    assert response.status_code == 421
    assert mcp(env, None).status_code == 401
    assert (
        env.client.post("/mcp", json=INIT, headers={**MCP_HEADERS, "Host": "evil.test"}).status_code
        == 421
    )
    assert env.client.get("/healthz").text == "ok"


def test_body_limit(env: Env) -> None:
    response = env.client.post("/token", content=b"x" * 300_000)
    assert response.status_code == 413


def test_ip_allowlist_covers_mcp_and_token_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ipaddress

    gen = build_env(tmp_path, monkeypatch, allowed_cidrs=(ipaddress.ip_network("160.79.104.0/21"),))
    env = next(gen)
    try:
        env.client.headers["X-Test-IP"] = "203.0.113.9"
        assert mcp(env, None).status_code == 403
        assert env.client.post("/token", data={}).status_code == 403
        _, challenge = pkce()
        assert env.client.get("/authorize", params=authorize_params(challenge)).status_code == 302
        env.client.headers["X-Test-IP"] = "160.79.105.10"
        assert mcp(env, None).status_code == 401  # allowed through, then needs a token
    finally:
        gen.close()


def test_no_secrets_in_logs(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        body = tokens(env)
        mcp(env, body["access_token"])
        refresh(env, body["refresh_token"])
    text = caplog.text + "".join(p.read_text() for p in env.state.glob("audit.log"))
    for secret in (
        PASSWORD,
        CLIENT_SECRET,
        TOTP_SECRET,
        body["access_token"],
        body["refresh_token"],
    ):
        assert secret not in text


def test_audit_log_records_tool_calls(env: Env) -> None:
    import json

    body = tokens(env)
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {body['access_token']}"}
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"text": "x" * 100, "start_date": "2024-01-04"},
        },
    }
    env.client.post("/mcp", json=INIT, headers=headers)
    response = env.client.post("/mcp", json=call, headers=headers)
    assert response.status_code == 200, response.text
    lines = [json.loads(line) for line in (env.state / "audit.log").read_text().splitlines()]
    entry = lines[-1]
    assert entry["tool"] == "echo"
    assert entry["arguments"] == {"text": "<omitted>", "start_date": "2024-01-04"}
    assert entry["status"] == "ok" and isinstance(entry["ms"], int)
    assert body["access_token"] not in json.dumps(lines)


# -- static bearer fallback -----------------------------------------------------------------------


def test_static_bearer_mode(tmp_path: Path) -> None:
    secret_file = tmp_path / "bearer"
    token = secrets.token_urlsafe(48)
    secret_file.write_text(token)
    config = make_config(
        tmp_path / "state", auth_mode="static_bearer", static_bearer_file=secret_file
    )
    app = build_app(dummy_server, config)
    with TestClient(app, base_url=PUBLIC) as client:
        auth = {**MCP_HEADERS, "Authorization": f"Bearer {token}"}
        assert client.post("/mcp", json=INIT, headers=auth).status_code == 200
        bad = {**MCP_HEADERS, "Authorization": "Bearer " + "x" * 48}
        assert client.post("/mcp", json=INIT, headers=bad).status_code == 401
        assert client.get("/authorize").status_code == 404


def test_config_from_env(tmp_path: Path) -> None:
    def load(env: dict[str, str]) -> OwnerAuthConfig:
        return OwnerAuthConfig.from_env(
            "DUMMY", state_dir=tmp_path, app_name="Dummy", command="dummy-mcp", env=env
        )

    config = load(
        {
            "DUMMY_PUBLIC_URL": "https://g.example/",
            "DUMMY_CLIENT_IP_HEADER": "CF-Connecting-IP",
            "DUMMY_ALLOWED_CIDRS": "160.79.104.0/21, 10.0.0.1",
        }
    )
    assert config.resource == "https://g.example/mcp"
    assert config.client_ip_header == "CF-Connecting-IP"
    assert len(config.allowed_cidrs) == 2
    assert load({"DUMMY_PUBLIC_URL": "http://localhost:8000"}).auth_mode == "oauth"
    for bad in ("", "http://g.example", "https://g.example/sub", "g.example"):
        with pytest.raises(ConfigError):
            load({"DUMMY_PUBLIC_URL": bad})
    with pytest.raises(ConfigError):
        load({"DUMMY_PUBLIC_URL": "https://g.example", "DUMMY_AUTH_MODE": "static_bearer"})


def test_token_request_logs_the_client_auth_method(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="mcp_owner_auth.provider"):
        verifier, challenge = pkce()
        exchange(env, get_code(env, challenge), verifier, basic=True)
    assert "token request authenticated with client_secret_basic" in caplog.text
