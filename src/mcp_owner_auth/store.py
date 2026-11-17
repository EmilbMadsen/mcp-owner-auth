"""Persistent auth state in SQLite (``<state dir>/auth.db``, mode 0600).

Secrets are stored as hashes only:

- client secret and password: argon2id
- authorization codes, access and refresh tokens, pending-request IDs: SHA-256

The TOTP seed has to be stored as-is (it is needed to compute codes); the file permissions are its
protection. Every call opens its own short connection, so ``auth revoke-all`` from the CLI takes
effect immediately in a running server.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

DEFAULT_REDIRECT_URIS = ("https://claude.ai/api/mcp/auth_callback",)

CODE_TTL = 60
ACCESS_TTL = 60 * 60
REFRESH_TTL = 30 * 24 * 60 * 60
PENDING_TTL = 10 * 60
CONSENT_WINDOW = 5 * 60

RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 15 * 60
LOCKOUT_FAILURES = 20
LOCKOUT_WINDOW = 24 * 60 * 60

_HASHER = PasswordHasher()  # argon2id with the library's current recommended parameters

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending (
    id_hash TEXT PRIMARY KEY,
    csrf TEXT NOT NULL,
    params TEXT NOT NULL,
    expires_at REAL NOT NULL,
    authenticated_at REAL
);
CREATE TABLE IF NOT EXISTS codes (
    code_hash TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    data TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    family TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires_at REAL NOT NULL,
    used_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family);
CREATE TABLE IF NOT EXISTS login_failures (ip TEXT NOT NULL, at REAL NOT NULL);
"""


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hash_secret(value: str) -> str:
    return _HASHER.hash(value)


def verify_secret(stored_hash: str | None, candidate: str) -> bool:
    """Constant-time argon2 verification. A missing hash still costs one verification."""
    try:
        return _HASHER.verify(stored_hash or _DUMMY_HASH, candidate) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


_DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(16))


@dataclass(frozen=True)
class Credentials:
    username: str
    password_hash: str
    totp_secret: str
    client_id: str
    client_secret_hash: str
    redirect_uris: tuple[str, ...]
    last_totp_step: int


@dataclass(frozen=True)
class TokenRow:
    kind: str
    family: str
    client_id: str
    scopes: list[str]
    resource: str | None
    expires_at: float
    used_at: float | None
    revoked: bool


class AuthStore:
    def __init__(self, path: Path, clock: Any = time.time) -> None:
        self.path = path
        self.clock = clock
        self._init()

    def _init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(descriptor)
        if os.name == "posix":
            self.path.chmod(0o600)
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(_SCHEMA)
        finally:
            connection.close()

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    # -- settings ---------------------------------------------------------------------------

    def _get(self, db: sqlite3.Connection, key: str) -> str | None:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def _set(self, db: sqlite3.Connection, key: str, value: str) -> None:
        db.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def initialized(self) -> bool:
        return self.credentials() is not None

    def credentials(self) -> Credentials | None:
        with self._db() as db:
            raw = self._get(db, "credentials")
            step = int(self._get(db, "last_totp_step") or 0)
        if raw is None:
            return None
        data = json.loads(raw)
        return Credentials(
            username=data["username"],
            password_hash=data["password_hash"],
            totp_secret=data["totp_secret"],
            client_id=data["client_id"],
            client_secret_hash=data["client_secret_hash"],
            redirect_uris=tuple(data["redirect_uris"]),
            last_totp_step=step,
        )

    def save_credentials(
        self,
        *,
        username: str,
        password: str,
        totp_secret: str,
        client_id: str,
        client_secret: str,
        redirect_uris: tuple[str, ...] = DEFAULT_REDIRECT_URIS,
    ) -> None:
        data = {
            "username": username,
            "password_hash": hash_secret(password),
            "totp_secret": totp_secret,
            "client_id": client_id,
            "client_secret_hash": hash_secret(client_secret),
            "redirect_uris": list(redirect_uris),
        }
        with self._db() as db:
            self._set(db, "credentials", json.dumps(data))
            self._set(db, "last_totp_step", "0")

    def replace_client(self, client_id: str, client_secret: str) -> None:
        with self._db() as db:
            raw = self._get(db, "credentials")
            if raw is None:
                raise RuntimeError("auth is not initialized")
            data = json.loads(raw)
            data["client_id"] = client_id
            data["client_secret_hash"] = hash_secret(client_secret)
            self._set(db, "credentials", json.dumps(data))

    def set_redirect_uris(self, uris: tuple[str, ...]) -> None:
        with self._db() as db:
            raw = self._get(db, "credentials")
            if raw is None:
                raise RuntimeError("auth is not initialized")
            data = json.loads(raw)
            data["redirect_uris"] = list(uris)
            self._set(db, "credentials", json.dumps(data))

    def claim_totp_step(self, step: int) -> bool:
        """Accept each TOTP time step at most once (no replay of a seen code)."""
        with self._db() as db:
            last = int(self._get(db, "last_totp_step") or 0)
            if step <= last:
                return False
            self._set(db, "last_totp_step", str(step))
            return True

    # -- lockout and rate limit ---------------------------------------------------------------

    def locked(self) -> bool:
        with self._db() as db:
            return self._get(db, "locked") == "1"

    def unlock(self) -> None:
        with self._db() as db:
            self._set(db, "locked", "0")
            db.execute("DELETE FROM login_failures")

    def recent_failures(self, ip: str | None = None) -> int:
        now = self.clock()
        with self._db() as db:
            if ip is None:
                row = db.execute(
                    "SELECT COUNT(*) FROM login_failures WHERE at > ?", (now - LOCKOUT_WINDOW,)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT COUNT(*) FROM login_failures WHERE ip = ? AND at > ?",
                    (ip, now - RATE_LIMIT_WINDOW),
                ).fetchone()
        return int(row[0])

    def record_failure(self, ip: str) -> None:
        now = self.clock()
        with self._db() as db:
            db.execute("INSERT INTO login_failures(ip, at) VALUES(?, ?)", (ip, now))
            db.execute("DELETE FROM login_failures WHERE at < ?", (now - LOCKOUT_WINDOW,))
            total = db.execute("SELECT COUNT(*) FROM login_failures").fetchone()[0]
            if total >= LOCKOUT_FAILURES:
                self._set(db, "locked", "1")

    # -- pending authorization requests -------------------------------------------------------

    def create_pending(self, params: dict[str, Any]) -> tuple[str, str]:
        request_id = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = self.clock()
        with self._db() as db:
            db.execute("DELETE FROM pending WHERE expires_at < ?", (now,))
            db.execute(
                "INSERT INTO pending(id_hash, csrf, params, expires_at) VALUES(?, ?, ?, ?)",
                (sha256(request_id), csrf, json.dumps(params), now + PENDING_TTL),
            )
        return request_id, csrf

    def pending(self, request_id: str) -> tuple[str, dict[str, Any], float | None] | None:
        with self._db() as db:
            row = db.execute(
                "SELECT csrf, params, expires_at, authenticated_at FROM pending WHERE id_hash = ?",
                (sha256(request_id),),
            ).fetchone()
        if row is None or row[2] < self.clock():
            return None
        return row[0], json.loads(row[1]), row[3]

    def mark_authenticated(self, request_id: str) -> None:
        with self._db() as db:
            db.execute(
                "UPDATE pending SET authenticated_at = ? WHERE id_hash = ?",
                (self.clock(), sha256(request_id)),
            )

    def delete_pending(self, request_id: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM pending WHERE id_hash = ?", (sha256(request_id),))

    # -- authorization codes --------------------------------------------------------------------

    def create_code(self, data: dict[str, Any]) -> tuple[str, float]:
        code = secrets.token_urlsafe(32)
        expires_at = self.clock() + CODE_TTL
        with self._db() as db:
            db.execute(
                "INSERT INTO codes(code_hash, family, data, expires_at) VALUES(?, ?, ?, ?)",
                (sha256(code), secrets.token_hex(16), json.dumps(data), expires_at),
            )
        return code, expires_at

    def consume_code(self, code: str) -> tuple[str, dict[str, Any], float] | None:
        """One-shot: returns (family, data, expires_at) the first time. A second use of the same
        code revokes every token issued from it (RFC 6749 section 4.1.2)."""
        with self._db() as db:
            row = db.execute(
                "SELECT family, data, expires_at, used FROM codes WHERE code_hash = ?",
                (sha256(code),),
            ).fetchone()
            if row is None:
                return None
            family, data, expires_at, used = row
            if used:
                db.execute("UPDATE tokens SET revoked = 1 WHERE family = ?", (family,))
                return None
            db.execute("UPDATE codes SET used = 1 WHERE code_hash = ?", (sha256(code),))
            db.execute(
                "DELETE FROM codes WHERE expires_at < ? AND used = 1", (self.clock() - 3600,)
            )
        return family, json.loads(data), expires_at

    # -- tokens -----------------------------------------------------------------------------------

    def issue_tokens(
        self, *, family: str, client_id: str, scopes: list[str], resource: str | None
    ) -> tuple[str, str]:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = self.clock()
        rows = [
            (sha256(access), "access", now + ACCESS_TTL),
            (sha256(refresh), "refresh", now + REFRESH_TTL),
        ]
        with self._db() as db:
            for token_hash, kind, expires_at in rows:
                db.execute(
                    "INSERT INTO tokens(token_hash, kind, family, client_id, scopes, resource, "
                    "expires_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (token_hash, kind, family, client_id, " ".join(scopes), resource, expires_at),
                )
            db.execute("DELETE FROM tokens WHERE expires_at < ?", (now - 86400,))
        return access, refresh

    def token(self, token: str) -> TokenRow | None:
        with self._db() as db:
            row = db.execute(
                "SELECT kind, family, client_id, scopes, resource, expires_at, used_at, revoked "
                "FROM tokens WHERE token_hash = ?",
                (sha256(token),),
            ).fetchone()
        if row is None:
            return None
        return TokenRow(
            kind=row[0],
            family=row[1],
            client_id=row[2],
            scopes=row[3].split(),
            resource=row[4],
            expires_at=row[5],
            used_at=row[6],
            revoked=bool(row[7]),
        )

    def use_refresh_token(self, token: str) -> TokenRow | None:
        """Mark a refresh token used. Reuse of a used token revokes its whole family."""
        with self._db() as db:
            row = db.execute(
                "SELECT family, used_at, revoked FROM tokens "
                "WHERE token_hash = ? AND kind = 'refresh'",
                (sha256(token),),
            ).fetchone()
            if row is None:
                return None
            family, used_at, revoked = row
            if used_at is not None or revoked:
                db.execute("UPDATE tokens SET revoked = 1 WHERE family = ?", (family,))
                return None
            db.execute(
                "UPDATE tokens SET used_at = ? WHERE token_hash = ?", (self.clock(), sha256(token))
            )
        return self.token(token)

    def revoke_family(self, family: str) -> None:
        with self._db() as db:
            db.execute("UPDATE tokens SET revoked = 1 WHERE family = ?", (family,))

    def revoke_all(self) -> int:
        with self._db() as db:
            cursor = db.execute("UPDATE tokens SET revoked = 1 WHERE revoked = 0")
            db.execute("DELETE FROM pending")
            db.execute("UPDATE codes SET used = 1")
            return cursor.rowcount

    def active_token_counts(self) -> dict[str, int]:
        now = self.clock()
        with self._db() as db:
            rows = db.execute(
                "SELECT kind, COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at > ? "
                "AND (kind = 'access' OR used_at IS NULL) GROUP BY kind",
                (now,),
            ).fetchall()
        return {kind: count for kind, count in rows}
