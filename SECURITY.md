# Security

## Threat model

- The protected MCP server exposes personal data (health, home devices, shopping). Even when it
  only reads, a breach is serious.
- Remote use must be reachable from the public internet: claude.ai calls the MCP endpoint from
  Anthropic's infrastructure, not from the user's phone. A VPN-only setup (Tailscale) is therefore
  not possible.
- There is exactly one user (the owner of the data and of the upstream credentials) and one
  legitimate client (Claude). This is for self-hosted, single-user servers; never run it as a
  shared service.

Local stdio mode has no network surface and no auth: the MCP client starts the process.

## Design: built-in single-user OAuth 2.1

The server is both the authorization server (AS) and the resource server (RS), on separate
routes in one process. It reuses the MCP SDK's handlers for `/authorize`, `/token`, PKCE checks
and the metadata documents, and supplies its own provider, client authentication, login and
storage. No cryptography is implemented here: secrets come from `secrets`, hashing from
`argon2-cffi` (argon2id) and `hashlib` (SHA-256), TOTP from `pyotp`.

### Client

- Exactly one static client. Dynamic client registration and client ID metadata documents are
  off (`/register` does not exist).
- `<command> auth init` generates `client_id` and `client_secret` with
  `secrets.token_urlsafe(32)`. The secret is shown once and stored only as an argon2id hash.
- In claude.ai: Add custom connector -> URL -> **Use your own OAuth client** -> client ID and
  secret.
- `redirect_uri` must match the allowlist exactly. Default: `https://claude.ai/api/mcp/auth_callback`
  (change with `auth init --redirect-uri ...`).
- The token endpoint accepts `client_secret_post` and `client_secret_basic` (both advertised in
  the metadata). claude.ai uses `client_secret_post` (observed November 2026); the
  method used is logged at INFO for every token request. Sending both at once is rejected. Unknown client and wrong secret give the same
  `invalid_client` answer.

### Flow

1. Metadata: `/.well-known/oauth-protected-resource/mcp` (RFC 9728) and
   `/.well-known/oauth-authorization-server` (RFC 8414). The issuer is
   `<PREFIX>_PUBLIC_URL`, exactly (no trailing slash).
2. `/authorize` checks the client, the exact `redirect_uri`, `response_type=code`, PKCE with
   `S256` (plain and missing PKCE are rejected) and `resource`, which must equal the canonical
   MCP URL (`<public url>/mcp`). An invalid redirect URI is never redirected to.
3. Login: username, password (argon2id) and TOTP (one step of clock drift; each time step is
   accepted once, so a code cannot be replayed).
   - CSRF token in the form, matched against the pending request and a
     `__Host-` cookie with `Secure; HttpOnly; SameSite=Strict`.
   - One generic error message; no user enumeration.
   - At most 5 failed attempts per IP per 15 minutes; 20 failures in 24 hours lock login entirely
     until `<command> auth unlock`.
   - Minimal server-rendered HTML, no JavaScript, strict CSP.
   - After login a consent page ("Claude wants read-only access ..."), then a redirect with
     `code`, `state` and `iss` (RFC 9207).
4. Authorization code: single use, 60 seconds, bound to the client, redirect URI, code challenge
   and resource. A failed exchange (wrong verifier) burns the code. A second use of a code revokes
   every token issued from it.
5. `/token`: `authorization_code` (with the PKCE verifier) and `refresh_token`.
   - Access token: opaque, 32 random bytes, **1 hour**, bound to the resource.
   - Refresh token: opaque, **30 days**, **rotated on every use**. Presenting an already used
     refresh token revokes the whole token family (the stolen-token case).
   - Tokens are stored only as SHA-256 hashes in SQLite (`<state dir>/auth.db`, mode 0600).
6. RS: the bearer middleware looks up the hash, checks expiry, resource (audience) and the
   `the configured` scope. Failures get 401 with `WWW-Authenticate: Bearer ... resource_metadata=...`.

### CLI

| Command | Effect |
|---|---|
| `auth init [--force] [--redirect-uri URI]` | username, password, TOTP (QR in the terminal), new client |
| `auth rotate-client` | new client ID and secret; revokes all tokens |
| `auth revoke-all` | emergency brake: revokes every token at once, no restart needed |
| `auth unlock` | lifts the login lockout |
| `auth status` | setup, active tokens, failed logins, lockout |

Every request reads the database, so `revoke-all` from another process takes effect on the next
request.

### Fallback: static bearer token

Only for accounts where claude.ai's "Request headers" option is available (beta, selected
organisations). `<PREFIX>_AUTH_MODE=static_bearer` with
`<PREFIX>_STATIC_BEARER_FILE` pointing to a file with a long random token (at least 32
characters; generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"`). The
comparison uses `hmac.compare_digest`. OAuth is the recommended mode: tokens expire, rotate and
can be revoked.

## Additional layers

- **Host header allowlist:** requests whose `Host` is not the public hostname get 421 (DNS
  rebinding protection; the SDK's transport security also checks `/mcp`).
- **Body limit** of 256 kB and a **request timeout** of 120 s on every route.
- **Audit log** (`<state dir>/audit.log`, JSON lines, 0600): time, tool name, arguments (dates,
  IDs, limits, flags; anything longer is omitted), status and duration. Never tokens, keys or
  response bodies.
- **Security headers** on HTML routes: `Content-Security-Policy: default-src 'none';
  form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`,
  `no-referrer`, `no-store`.
- **Optional IP allowlist** `<PREFIX>_ALLOWED_CIDRS` on `/mcp` and `/token`, which only
  Anthropic's backend calls. Not on `/authorize` and the login, which open in the user's browser.
  Anthropic's published egress range for MCP calls is `160.79.104.0/21`, but traffic from outside
  it has been reported, so this is an extra layer, never the primary control. Test without it
  first.
- **Client IP behind a proxy:** set `<PREFIX>_CLIENT_IP_HEADER=CF-Connecting-IP` only
  when the app is reachable exclusively through the Cloudflare Tunnel (as in `compose.yaml`).
  Otherwise the header could be forged.
- **Logs** contain method, path and status, never response bodies, tokens or keys.

## What is stored where

| Data | Location | Protection |
|---|---|---|
| Password, client secret | `<state dir>/auth.db` | argon2id hash |
| TOTP seed | `auth.db` | stored as-is (needed to verify codes); file mode 0600 |
| Codes, access and refresh tokens | `auth.db` | SHA-256 hash |
| Audit log | `<state dir>/audit.log` | 0600; no secrets, no results |
