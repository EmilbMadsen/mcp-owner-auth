"""Login (username + password + TOTP) and consent pages. Server-rendered HTML, no JavaScript.

CSRF: a per-request token is stored with the pending authorization request, set in a
``Secure; HttpOnly; SameSite=Strict`` cookie and embedded in the form; all three must match.
Errors are generic (no user enumeration). Failed logins are rate limited per IP (5 per 15 min),
and 20 failures in 24 h lock login entirely until ``<command> auth unlock``.
"""

from __future__ import annotations

import hmac
import html
import logging
from urllib.parse import urlsplit

import pyotp
from mcp.server.auth.provider import construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from .config import OwnerAuthConfig
from .provider import OwnerOAuthProvider
from .store import CONSENT_WINDOW, RATE_LIMIT_ATTEMPTS, AuthStore, verify_secret

_LOGGER = logging.getLogger(__name__)

CSRF_COOKIE = "__Host-ghm_csrf"
GENERIC_ERROR = "Sign-in failed. Check your details and try again."

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem;"
    "color:#222}label{display:block;margin-top:.8rem}input{width:100%;padding:.5rem;"
    "box-sizing:border-box;font-size:1rem}button{margin-top:1.2rem;padding:.6rem 1rem;"
    "font-size:1rem;margin-right:.5rem}.error{color:#b00020}"
    "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}"
)


def client_ip(request: Request, header: str | None = None) -> str:
    """The caller's IP. Behind a proxy (Cloudflare Tunnel) set CLIENT_IP_HEADER, e.g.
    ``CF-Connecting-IP``; only do that when the server is not reachable except via the proxy."""
    if header:
        value = request.headers.get(header, "").split(",")[0].strip()
        if value:
            return value
    return request.client.host if request.client else "unknown"


def _headers(form_targets: tuple[str, ...] = ()) -> dict[str, str]:
    """Security headers. ``form_targets`` are extra origins a form submission may end up at:
    browsers apply CSP ``form-action`` to the redirect after a POST too, so the consent page
    must allow the OAuth redirect URI's origin (e.g. https://claude.ai)."""
    if not form_targets:
        return dict(SECURITY_HEADERS)
    csp = SECURITY_HEADERS["Content-Security-Policy"].replace(
        "form-action 'self'", "form-action 'self' " + " ".join(form_targets)
    )
    return {**SECURITY_HEADERS, "Content-Security-Policy": csp}


def _origins(uris: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for uri in uris:
        parts = urlsplit(uri)
        origin = f"{parts.scheme}://{parts.netloc}"
        if parts.scheme in ("https", "http") and parts.netloc and origin not in out:
            out.append(origin)
    return tuple(out)


def _page(
    title: str,
    body: str,
    status: int = 200,
    csrf: str | None = None,
    form_targets: tuple[str, ...] = (),
) -> HTMLResponse:
    document = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )
    response = HTMLResponse(document, status_code=status, headers=_headers(form_targets))
    if csrf is not None:
        response.set_cookie(
            CSRF_COOKIE, csrf, max_age=600, path="/", secure=True, httponly=True, samesite="strict"
        )
    return response


def _login_form(request_id: str, csrf: str, error: str | None = None) -> str:
    message = f"<p class=error role=alert>{html.escape(error)}</p>" if error else ""
    return (
        f"{message}<form method=post action=/login>"
        f'<input type=hidden name=request value="{html.escape(request_id)}">'
        f'<input type=hidden name=csrf value="{html.escape(csrf)}">'
        "<label>Username<input name=username autocomplete=username required></label>"
        "<label>Password<input name=password type=password autocomplete=current-password "
        "required></label>"
        "<label>Authenticator code<input name=totp inputmode=numeric autocomplete=one-time-code "
        'pattern="[0-9]{6}" maxlength=6 required></label>'
        "<button type=submit>Sign in</button></form>"
    )


def _consent_form(request_id: str, csrf: str, consent: str) -> str:
    return (
        f"<p>Claude wants {html.escape(consent)}.</p>"
        "<form method=post action=/consent>"
        f'<input type=hidden name=request value="{html.escape(request_id)}">'
        f'<input type=hidden name=csrf value="{html.escape(csrf)}">'
        "<button type=submit name=decision value=allow>Allow</button>"
        "<button type=submit name=decision value=deny>Deny</button></form>"
    )


def _expired() -> HTMLResponse:
    return _page(
        "Request expired",
        "<p>This sign-in request is no longer valid. Start again from Claude.</p>",
        status=400,
    )


def _csrf_ok(request: Request, form_csrf: object, stored: str) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return (
        isinstance(form_csrf, str)
        and bool(cookie)
        and hmac.compare_digest(form_csrf.encode(), stored.encode())
        and hmac.compare_digest(cookie.encode(), stored.encode())
    )


def login_routes(
    store: AuthStore, provider: OwnerOAuthProvider, config: OwnerAuthConfig
) -> list[Route]:
    title = config.app_name

    async def login_page(request: Request) -> Response:
        request_id = request.query_params.get("request", "")
        pending = store.pending(request_id)
        if pending is None:
            return _expired()
        csrf, _, _ = pending
        if store.locked():
            return _page("Sign-in locked", "<p>Sign-in is locked.</p>", status=423)
        return _page(title, _login_form(request_id, csrf), csrf=csrf)

    async def login_submit(request: Request) -> Response:
        form = await request.form()
        request_id = str(form.get("request", ""))
        pending = store.pending(request_id)
        if pending is None:
            return _expired()
        csrf, _, _ = pending
        if not _csrf_ok(request, form.get("csrf"), csrf):
            return _page(title, "<p>Invalid form submission.</p>", status=403)
        ip = client_ip(request, config.client_ip_header)
        if store.locked():
            _LOGGER.warning("login refused: locked")
            return _page("Sign-in locked", "<p>Sign-in is locked.</p>", status=423)
        if store.recent_failures(ip) >= RATE_LIMIT_ATTEMPTS:
            _LOGGER.warning("login refused: rate limited")
            return _page(
                title,
                _login_form(request_id, csrf, "Too many attempts. Try again later."),
                status=429,
            )

        credentials = store.credentials()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        code = str(form.get("totp", "")).strip()
        user_ok = bool(credentials) and hmac.compare_digest(
            (credentials.username if credentials else "").encode(), username.encode()
        )
        password_ok = verify_secret(credentials.password_hash if credentials else None, password)
        totp_ok = False
        if credentials and code.isdigit() and len(code) == 6:
            totp = pyotp.TOTP(credentials.totp_secret)
            now = store.clock()
            for offset in (-1, 0, 1):  # one step of clock drift either way
                step = int(now // 30) + offset
                if hmac.compare_digest(totp.at(step * 30), code):
                    totp_ok = user_ok and password_ok and store.claim_totp_step(step)
                    break

        if not (user_ok and password_ok and totp_ok):
            store.record_failure(ip)
            _LOGGER.warning("login failed")
            return _page(title, _login_form(request_id, csrf, GENERIC_ERROR), status=401)
        store.mark_authenticated(request_id)
        _LOGGER.info("login succeeded")
        targets = _origins(credentials.redirect_uris if credentials else ())
        return _page(
            "Allow access?",
            _consent_form(request_id, csrf, config.consent),
            csrf=csrf,
            form_targets=targets,
        )

    async def consent_submit(request: Request) -> Response:
        form = await request.form()
        request_id = str(form.get("request", ""))
        pending = store.pending(request_id)
        if pending is None:
            return _expired()
        csrf, params, authenticated_at = pending
        if not _csrf_ok(request, form.get("csrf"), csrf):
            return _page(title, "<p>Invalid form submission.</p>", status=403)
        if authenticated_at is None or store.clock() - authenticated_at > CONSENT_WINDOW:
            return _expired()
        store.delete_pending(request_id)
        if form.get("decision") != "allow":
            target = construct_redirect_uri(
                params["redirect_uri"], error="access_denied", state=params.get("state")
            )
        else:
            target = provider.issue_code(params)
            _LOGGER.info("authorization code issued")
        response = RedirectResponse(target, status_code=302, headers=_headers())
        response.delete_cookie(CSRF_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    return [
        Route("/login", login_page, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/consent", consent_submit, methods=["POST"]),
    ]
