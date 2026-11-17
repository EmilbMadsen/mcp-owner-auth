"""``<command> auth init | rotate-client | revoke-all | unlock | status``.

Wire it into a server's argparse with :func:`add_parser` and :func:`run`.
"""

from __future__ import annotations

import argparse
import getpass
import io
import secrets
import sys
from pathlib import Path

import pyotp
import qrcode

from .store import DEFAULT_REDIRECT_URIS, LOCKOUT_FAILURES, AuthStore

MIN_PASSWORD_LENGTH = 12


ACTIONS = ("init", "rotate-client", "revoke-all", "unlock", "status")


def _print_qr(uri: str) -> None:
    code = qrcode.QRCode(border=1)
    code.add_data(uri)
    buffer = io.StringIO()
    code.print_ascii(out=buffer, invert=True)
    print(buffer.getvalue())


def _new_client() -> tuple[str, str]:
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)


def _show_client(client_id: str, client_secret: str) -> None:
    print("\nOAuth client for claude.ai (Add custom connector -> Use your own OAuth client):")
    print(f"  Client ID:     {client_id}")
    print(f"  Client secret: {client_secret}")
    print("The secret is shown only now and stored only as a hash. Paste it into claude.ai.")


def init(store: AuthStore, app_name: str, *, force: bool, redirect_uris: list[str]) -> int:
    if store.initialized() and not force:
        print("Auth is already set up. Use --force to replace it (revokes all tokens).")
        return 1
    print("Set up the login for the remote server (single user).")
    username = input("Username: ").strip()
    password = getpass.getpass(f"Password (at least {MIN_PASSWORD_LENGTH} characters): ")
    if not username or len(password) < MIN_PASSWORD_LENGTH:
        print("A username and a password of at least 12 characters are required.", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat password: ") != password:
        print("The passwords do not match.", file=sys.stderr)
        return 1

    totp_secret = pyotp.random_base32()
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=app_name)
    print("\nScan this QR code with your authenticator app:\n")
    _print_qr(uri)
    print(f"Or enter this key manually: {totp_secret}\n")
    code = input("Enter the 6-digit code from the app to confirm: ").strip()
    if not pyotp.TOTP(totp_secret).verify(code, valid_window=1):
        print("That code is not valid. Nothing was saved; run auth init again.", file=sys.stderr)
        return 1

    client_id, client_secret = _new_client()
    store.revoke_all()
    store.save_credentials(
        username=username,
        password=password,
        totp_secret=totp_secret,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=tuple(redirect_uris or DEFAULT_REDIRECT_URIS),
    )
    store.unlock()
    _show_client(client_id, client_secret)
    print(f"\nSaved to {store.path} (mode 0600).")
    return 0


def rotate_client(store: AuthStore, command: str) -> int:
    if not store.initialized():
        print(f"Auth is not set up. Run `{command} auth init`.", file=sys.stderr)
        return 1
    client_id, client_secret = _new_client()
    store.replace_client(client_id, client_secret)
    revoked = store.revoke_all()
    print(f"New client created; {revoked} tokens revoked.")
    print("In claude.ai, remove the connector and add it again with the new client.")
    _show_client(client_id, client_secret)
    return 0


def revoke_all(store: AuthStore) -> int:
    revoked = store.revoke_all()
    print(f"Revoked {revoked} tokens. Claude must sign in again (takes effect immediately).")
    return 0


def unlock(store: AuthStore) -> int:
    store.unlock()
    print("Login unlocked and failure counters cleared.")
    return 0


def status(store: AuthStore, command: str) -> int:
    credentials = store.credentials()
    if credentials is None:
        print(f"Auth: not set up (run `{command} auth init`).")
        return 1
    counts = store.active_token_counts()
    print(f"Auth database:   {store.path}")
    print(f"Username:        {credentials.username}")
    print(f"Client ID:       {credentials.client_id[:6]}... (secret stored as argon2id hash)")
    print(f"Redirect URIs:   {', '.join(credentials.redirect_uris)}")
    print(f"Active tokens:   {counts.get('access', 0)} access, {counts.get('refresh', 0)} refresh")
    print(f"Failed logins:   {store.recent_failures()} in 24 h (lockout at {LOCKOUT_FAILURES})")
    print(f"Login locked:    {'YES - run auth unlock' if store.locked() else 'no'}")
    return 0


def add_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Add the ``auth`` subcommand to a server's argparse subparsers."""
    auth = subparsers.add_parser("auth", help="manage remote-access login and tokens")
    auth.add_argument("action", choices=ACTIONS)
    auth.add_argument("--force", action="store_true", help="init: replace an existing setup")
    auth.add_argument(
        "--redirect-uri",
        action="append",
        default=[],
        help="init: allowed OAuth redirect URI (repeatable; default: claude.ai's callback)",
    )


def run(
    action: str,
    *,
    auth_db: Path,
    app_name: str,
    command: str,
    force: bool = False,
    redirect_uris: list[str] | None = None,
) -> int:
    store = AuthStore(auth_db)
    if action == "init":
        return init(store, app_name, force=force, redirect_uris=redirect_uris or [])
    if action == "rotate-client":
        return rotate_client(store, command)
    if action == "revoke-all":
        return revoke_all(store)
    if action == "unlock":
        return unlock(store)
    return status(store, command)
