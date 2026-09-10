"""SQLite persistence for OAuth clients, grants, and opaque tokens."""

import json
import hmac
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.auth.provider import AccessToken, AuthorizationCode, AuthorizationParams, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from .security import new_secret, secret_digest


@dataclass(frozen=True)
class PendingAuthorization:
    request_id: str
    client_id: str
    state: str | None
    scopes: list[str]
    code_challenge: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    resource: str
    expires_at: int
    csrf_digest: str | None
    failed_attempts: int


class StoredRefreshToken(RefreshToken):
    resource: str
    family_id: str


class StoredAccessToken(AccessToken):
    family_id: str


@dataclass(frozen=True)
class IssuedTokenPair:
    access_token: str
    refresh_token: str
    scopes: list[str]
    access_expires_in: int


class OAuthStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    data_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pending_authorizations (
                    request_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    state TEXT,
                    scopes_json TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_explicit INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    csrf_digest TEXT,
                    failed_attempts INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS authorization_codes (
                    code_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_explicit INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    subject TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_tokens (
                    token_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    family_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    family_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS used_refresh_tokens (
                    token_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    family_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS access_token_expiry ON access_tokens(expires_at);
                CREATE INDEX IF NOT EXISTS refresh_token_expiry ON refresh_tokens(expires_at);
                CREATE INDEX IF NOT EXISTS token_family_access ON access_tokens(family_id);
                CREATE INDEX IF NOT EXISTS token_family_refresh ON refresh_tokens(family_id);
                CREATE INDEX IF NOT EXISTS used_refresh_token_expiry ON used_refresh_tokens(expires_at);
                """
            )
        os.chmod(self.path, 0o600)

    @staticmethod
    def _client_from_row(row: sqlite3.Row | None) -> OAuthClientInformationFull | None:
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate_json(row["data_json"])

    def save_client(self, client: OAuthClientInformationFull) -> None:
        payload = client.model_dump_json(by_alias=True, exclude_none=True)
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO oauth_clients(client_id, data_json, created_at) VALUES (?, ?, ?)",
                (client.client_id, payload, int(time.time())),
            )

    def load_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT data_json FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        return self._client_from_row(row)

    def create_pending_authorization(
        self,
        client_id: str,
        params: AuthorizationParams,
        ttl_seconds: int,
    ) -> str:
        request_id = new_secret()
        now = int(time.time())
        self.cleanup_expired(now)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            client_count = connection.execute(
                "SELECT COUNT(*) FROM pending_authorizations WHERE client_id = ?",
                (client_id,),
            ).fetchone()[0]
            total_count = connection.execute("SELECT COUNT(*) FROM pending_authorizations").fetchone()[0]
            if client_count >= 20 or total_count >= 200:
                raise RuntimeError("Too many pending OAuth authorization requests")
            connection.execute(
                """
                INSERT INTO pending_authorizations(
                    request_digest, client_id, state, scopes_json, code_challenge,
                    redirect_uri, redirect_uri_explicit, resource, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    secret_digest(request_id),
                    client_id,
                    params.state,
                    json.dumps(params.scopes or []),
                    params.code_challenge,
                    str(params.redirect_uri),
                    int(params.redirect_uri_provided_explicitly),
                    str(params.resource),
                    now + ttl_seconds,
                ),
            )
        return request_id

    @staticmethod
    def _pending_from_row(request_id: str, row: sqlite3.Row | None) -> PendingAuthorization | None:
        if row is None:
            return None
        return PendingAuthorization(
            request_id=request_id,
            client_id=row["client_id"],
            state=row["state"],
            scopes=json.loads(row["scopes_json"]),
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_explicit"]),
            resource=row["resource"],
            expires_at=row["expires_at"],
            csrf_digest=row["csrf_digest"],
            failed_attempts=row["failed_attempts"],
        )

    def load_pending_authorization(self, request_id: str) -> PendingAuthorization | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_authorizations WHERE request_digest = ? AND expires_at >= ?",
                (secret_digest(request_id), int(time.time())),
            ).fetchone()
        return self._pending_from_row(request_id, row)

    def set_pending_csrf(self, request_id: str) -> str | None:
        csrf_token = new_secret()
        with self._lock, self._connect() as connection:
            result = connection.execute(
                """
                UPDATE pending_authorizations SET csrf_digest = ?
                WHERE request_digest = ? AND expires_at >= ?
                """,
                (secret_digest(csrf_token), secret_digest(request_id), int(time.time())),
            )
        return csrf_token if result.rowcount == 1 else None

    def verify_pending_csrf(self, pending: PendingAuthorization, csrf_token: str) -> bool:
        return bool(pending.csrf_digest and hmac.compare_digest(pending.csrf_digest, secret_digest(csrf_token)))

    def record_failed_login(self, request_id: str) -> int:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE pending_authorizations SET failed_attempts = failed_attempts + 1 WHERE request_digest = ?",
                (secret_digest(request_id),),
            )
            row = connection.execute(
                "SELECT failed_attempts FROM pending_authorizations WHERE request_digest = ?",
                (secret_digest(request_id),),
            ).fetchone()
        return int(row["failed_attempts"]) if row else 0

    def discard_pending_authorization(self, request_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM pending_authorizations WHERE request_digest = ?",
                (secret_digest(request_id),),
            )

    def approve_pending_authorization(self, request_id: str, subject: str, code_ttl_seconds: int) -> tuple[str, PendingAuthorization] | None:
        now = int(time.time())
        code = new_secret()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM pending_authorizations WHERE request_digest = ? AND expires_at >= ?",
                (secret_digest(request_id), now),
            ).fetchone()
            pending = self._pending_from_row(request_id, row)
            if pending is None:
                return None
            deleted = connection.execute(
                "DELETE FROM pending_authorizations WHERE request_digest = ?",
                (secret_digest(request_id),),
            )
            if deleted.rowcount != 1:
                return None
            connection.execute(
                """
                INSERT INTO authorization_codes(
                    code_digest, client_id, scopes_json, expires_at, code_challenge,
                    redirect_uri, redirect_uri_explicit, resource, subject
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    secret_digest(code),
                    pending.client_id,
                    json.dumps(pending.scopes),
                    now + code_ttl_seconds,
                    pending.code_challenge,
                    pending.redirect_uri,
                    int(pending.redirect_uri_provided_explicitly),
                    pending.resource,
                    subject,
                ),
            )
        return code, pending

    def load_authorization_code(self, code: str, client_id: str) -> AuthorizationCode | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM authorization_codes
                WHERE code_digest = ? AND client_id = ? AND expires_at >= ?
                """,
                (secret_digest(code), client_id, int(time.time())),
            ).fetchone()
        if row is None:
            return None
        return AuthorizationCode(
            code=code,
            scopes=json.loads(row["scopes_json"]),
            expires_at=row["expires_at"],
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_explicit"]),
            resource=row["resource"],
            subject=row["subject"],
        )

    def exchange_authorization_code(
        self,
        code: str,
        access_ttl_seconds: int,
        refresh_ttl_seconds: int,
    ) -> IssuedTokenPair | None:
        now = int(time.time())
        access_token, refresh_token, family_id = new_secret(), new_secret(), new_secret(18)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM authorization_codes WHERE code_digest = ? AND expires_at >= ?",
                (secret_digest(code), now),
            ).fetchone()
            if row is None:
                return None
            deleted = connection.execute(
                "DELETE FROM authorization_codes WHERE code_digest = ?",
                (secret_digest(code),),
            )
            if deleted.rowcount != 1:
                return None
            values = (
                row["client_id"],
                row["scopes_json"],
                row["resource"],
                row["subject"],
                family_id,
            )
            connection.execute(
                """
                INSERT INTO access_tokens(token_digest, client_id, scopes_json, expires_at, resource, subject, family_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (secret_digest(access_token), values[0], values[1], now + access_ttl_seconds, *values[2:]),
            )
            connection.execute(
                """
                INSERT INTO refresh_tokens(token_digest, client_id, scopes_json, expires_at, resource, subject, family_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (secret_digest(refresh_token), values[0], values[1], now + refresh_ttl_seconds, *values[2:]),
            )
        return IssuedTokenPair(access_token, refresh_token, json.loads(row["scopes_json"]), access_ttl_seconds)

    def load_access_token(self, token: str) -> StoredAccessToken | None:
        now = int(time.time())
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM access_tokens WHERE token_digest = ? AND expires_at >= ?",
                (secret_digest(token), now),
            ).fetchone()
        if row is None:
            return None
        return StoredAccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["subject"],
            family_id=row["family_id"],
        )

    def load_refresh_token(self, token: str, client_id: str) -> StoredRefreshToken | None:
        now = int(time.time())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            digest = secret_digest(token)
            row = connection.execute(
                """
                SELECT * FROM refresh_tokens
                WHERE token_digest = ? AND client_id = ? AND expires_at >= ?
                """,
                (digest, client_id, now),
            ).fetchone()
            if row is None:
                reused = connection.execute(
                    """
                    SELECT family_id FROM used_refresh_tokens
                    WHERE token_digest = ? AND client_id = ? AND expires_at >= ?
                    """,
                    (digest, client_id, now),
                ).fetchone()
                if reused is not None:
                    self._revoke_family(connection, reused["family_id"])
        if row is None:
            return None
        return StoredRefreshToken(
            token=token,
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            expires_at=row["expires_at"],
            subject=row["subject"],
            resource=row["resource"],
            family_id=row["family_id"],
        )

    def rotate_refresh_token(
        self,
        token: StoredRefreshToken,
        scopes: list[str],
        access_ttl_seconds: int,
        refresh_ttl_seconds: int,
    ) -> IssuedTokenPair | None:
        now = int(time.time())
        new_access, new_refresh = new_secret(), new_secret()
        with self._lock, self._connect() as connection:
            deleted = connection.execute(
                "DELETE FROM refresh_tokens WHERE token_digest = ? AND family_id = ?",
                (secret_digest(token.token), token.family_id),
            )
            if deleted.rowcount != 1:
                reused = connection.execute(
                    """
                    SELECT family_id FROM used_refresh_tokens
                    WHERE token_digest = ? AND client_id = ? AND expires_at >= ?
                    """,
                    (secret_digest(token.token), token.client_id, now),
                ).fetchone()
                if reused is not None:
                    self._revoke_family(connection, reused["family_id"])
                return None
            connection.execute("DELETE FROM access_tokens WHERE family_id = ?", (token.family_id,))
            connection.execute(
                """
                INSERT OR REPLACE INTO used_refresh_tokens(token_digest, client_id, family_id, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (secret_digest(token.token), token.client_id, token.family_id, token.expires_at),
            )
            scopes_json = json.dumps(scopes)
            common: tuple[Any, ...] = (
                token.client_id,
                scopes_json,
                token.resource,
                token.subject or "admin",
                token.family_id,
            )
            connection.execute(
                """
                INSERT INTO access_tokens(token_digest, client_id, scopes_json, expires_at, resource, subject, family_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (secret_digest(new_access), common[0], common[1], now + access_ttl_seconds, *common[2:]),
            )
            connection.execute(
                """
                INSERT INTO refresh_tokens(token_digest, client_id, scopes_json, expires_at, resource, subject, family_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (secret_digest(new_refresh), common[0], common[1], now + refresh_ttl_seconds, *common[2:]),
            )
        return IssuedTokenPair(new_access, new_refresh, scopes, access_ttl_seconds)

    @staticmethod
    def _revoke_family(connection: sqlite3.Connection, family_id: str) -> None:
        connection.execute("DELETE FROM access_tokens WHERE family_id = ?", (family_id,))
        connection.execute("DELETE FROM refresh_tokens WHERE family_id = ?", (family_id,))
        connection.execute("DELETE FROM used_refresh_tokens WHERE family_id = ?", (family_id,))

    def revoke_raw_token(self, token: str, client_id: str) -> None:
        digest = secret_digest(token)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT family_id FROM access_tokens WHERE token_digest = ? AND client_id = ?",
                (digest, client_id),
            ).fetchone()
            if row is None:
                row = connection.execute(
                    "SELECT family_id FROM refresh_tokens WHERE token_digest = ? AND client_id = ?",
                    (digest, client_id),
                ).fetchone()
            if row is None:
                row = connection.execute(
                    "SELECT family_id FROM used_refresh_tokens WHERE token_digest = ? AND client_id = ?",
                    (digest, client_id),
                ).fetchone()
            if row is not None:
                self._revoke_family(connection, row["family_id"])

    def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        family_id = getattr(token, "family_id", None)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if family_id:
                self._revoke_family(connection, family_id)
                return
            digest = secret_digest(token.token)
            row = connection.execute(
                "SELECT family_id FROM access_tokens WHERE token_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                row = connection.execute(
                    "SELECT family_id FROM refresh_tokens WHERE token_digest = ?",
                    (digest,),
                ).fetchone()
            if row is not None:
                self._revoke_family(connection, row["family_id"])

    def cleanup_expired(self, now: int | None = None) -> None:
        cutoff = now or int(time.time())
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM pending_authorizations WHERE expires_at < ?", (cutoff,))
            connection.execute("DELETE FROM authorization_codes WHERE expires_at < ?", (cutoff,))
            connection.execute("DELETE FROM access_tokens WHERE expires_at < ?", (cutoff,))
            connection.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (cutoff,))
            connection.execute("DELETE FROM used_refresh_tokens WHERE expires_at < ?", (cutoff,))
