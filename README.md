# mcp-owner-auth

Single-user OAuth 2.1 for self-hosted [MCP](https://modelcontextprotocol.io) servers that you use
from claude.ai and the Claude mobile app.

It turns an `MCPServer` (MCP Python SDK v2) into a Streamable HTTP app where the server is both
authorization server and resource server, for **exactly one owner and one client**:

- One static OAuth client (for claude.ai: *Add custom connector → Use your own OAuth client*).
  No dynamic client registration, no client ID metadata documents.
- Login with username + password (argon2id) + TOTP, CSRF protection, no JavaScript, rate limit
  (5 failures per IP per 15 min) and a lockout after 20 failures in 24 h.
- PKCE S256 only, exact `redirect_uri` allowlist, RFC 8707 `resource` binding, RFC 9207 `iss`.
- Opaque tokens stored only as SHA-256 hashes: access tokens 1 h, refresh tokens 30 days, rotated
  on every use, reuse of a used refresh token revokes the whole family.
- `auth revoke-all` takes effect on the next request, without a restart.
- Host-header allowlist, body limit, timeout, optional IP allowlist on `/mcp` and `/token`,
  JSON-lines audit log of tool calls (no results, no secrets), strict security headers.
- Fallback `static_bearer` mode for clients that can send a fixed `Authorization` header.

It is meant for personal, self-hosted servers. It is not a general-purpose identity provider.
See [SECURITY.md](SECURITY.md) for the threat model and design.

## Use

```python
from pathlib import Path
from mcp_owner_auth import OwnerAuthConfig, serve
from mcp_owner_auth import cli as auth_cli

config = OwnerAuthConfig.from_env(
    "MY_MCP",  # reads MY_MCP_PUBLIC_URL, MY_MCP_AUTH_MODE, ...
    state_dir=Path("/data"),
    app_name="My Data",
    command="my-mcp",
    scope="mydata:read",
    consent="read-only access to your data",
)
serve(server, config, host="0.0.0.0", port=8000)  # server: your MCPServer
```

Add the CLI to your own argparse:

```python
auth_cli.add_parser(subcommands)
...
if args.command == "auth":
    sys.exit(
        auth_cli.run(
            args.action,
            auth_db=state / "auth.db",
            app_name="My Data",
            command="my-mcp",
            force=args.force,
            redirect_uris=args.redirect_uri,
        )
    )
```

Then `my-mcp auth init` (username, password, TOTP QR code, prints the client ID and secret once),
`auth status`, `auth rotate-client`, `auth revoke-all`, `auth unlock`.

### Environment

| Variable | Meaning |
|---|---|
| `<PREFIX>_PUBLIC_URL` | public base URL, e.g. `https://mcp.example.com` (https; http only for localhost) |
| `<PREFIX>_AUTH_MODE` | `oauth` (default) or `static_bearer` |
| `<PREFIX>_STATIC_BEARER_FILE` | file with the static token (at least 32 characters) |
| `<PREFIX>_ALLOWED_CIDRS` | optional comma-separated allowlist for `/mcp` and `/token` |
| `<PREFIX>_CLIENT_IP_HEADER` | e.g. `CF-Connecting-IP`; only when the app is reachable solely through that proxy |

### Routes

`/mcp`, `/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-authorization-server`,
`/authorize`, `/token`, `/login`, `/consent`, `/healthz`.

## License

Apache-2.0

## Releasing

Releases go to PyPI from GitHub Actions with trusted publishing (no API token anywhere). Bump
`version` in `pyproject.toml`, commit, then push a matching tag (`git tag v0.1.1 && git push
origin v0.1.1`). One-time setup on pypi.org: a trusted publisher for project `mcp-owner-auth`,
owner `EmilbMadsen`, repository `mcp-owner-auth`, workflow `release.yml`, environment `pypi`.
