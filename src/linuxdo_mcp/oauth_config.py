"""Configuration for the single-user MCP OAuth service."""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit


DEFAULT_SCOPE = "linuxdo:access"


def _normalize_url(value: str) -> tuple[str, SplitResult]:
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL must include a host and must not contain credentials")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if port in {443 if scheme == "https" else 80}:
        port = None
    displayed_host = f"[{host}]" if ":" in host else host
    netloc = f"{displayed_host}:{port}" if port is not None else displayed_host
    normalized = urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    return normalized, urlsplit(normalized)


@dataclass(frozen=True)
class OAuthConfig:
    public_url: str
    issuer_url: str
    password_hash: str
    database_path: Path
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    admin_username: str = "admin"
    access_token_ttl_seconds: int = 30 * 60
    refresh_token_ttl_seconds: int = 30 * 24 * 60 * 60
    authorization_code_ttl_seconds: int = 60
    pending_authorization_ttl_seconds: int = 10 * 60
    scopes: tuple[str, ...] = (DEFAULT_SCOPE,)

    @property
    def resource_path(self) -> str:
        return urlsplit(self.public_url).path

    @classmethod
    def from_env(cls) -> "OAuthConfig":
        public_url = os.getenv("MCP_PUBLIC_URL", "").strip().rstrip("/")
        password_hash = os.getenv("MCP_OAUTH_PASSWORD_HASH", "").strip()
        if not public_url:
            raise ValueError("MCP_PUBLIC_URL is required for streamable-http mode")
        if not password_hash:
            raise ValueError("MCP_OAUTH_PASSWORD_HASH is required for streamable-http mode")

        public_url, parsed = _normalize_url(public_url)
        is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
            raise ValueError("MCP_PUBLIC_URL must use HTTPS (HTTP is allowed only for loopback testing)")
        if not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("MCP_PUBLIC_URL must be an absolute URL without query parameters or fragments")
        if not parsed.path or parsed.path == "/":
            raise ValueError("MCP_PUBLIC_URL must include the MCP endpoint path, for example /mcp")
        if (
            not parsed.path.isascii()
            or "%" in parsed.path
            or "//" in parsed.path
            or any(segment in {".", ".."} for segment in parsed.path.split("/"))
            or re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]+", parsed.path) is None
        ):
            raise ValueError("MCP_PUBLIC_URL must use a canonical ASCII path without encoded or dot segments")
        reserved_paths = {"/authorize", "/token", "/revoke", "/oauth/consent"}
        if parsed.path in reserved_paths or parsed.path.startswith("/.well-known/") or parsed.path.startswith("/oauth/"):
            raise ValueError("MCP_PUBLIC_URL path conflicts with an OAuth endpoint")

        issuer_url = os.getenv("MCP_OAUTH_ISSUER_URL", "").strip().rstrip("/")
        if not issuer_url:
            issuer_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        issuer_url, issuer = _normalize_url(issuer_url)
        if issuer.scheme != parsed.scheme or issuer.netloc != parsed.netloc:
            raise ValueError("MCP_OAUTH_ISSUER_URL must use the same origin as MCP_PUBLIC_URL")
        if issuer.path not in {"", "/"} or issuer.query or issuer.fragment:
            raise ValueError("MCP_OAUTH_ISSUER_URL must be an origin without a path, query, or fragment")

        config_dir = Path(os.getenv("MCP_CONFIG_DIR", "~/.linuxdo-mcp")).expanduser()
        database_path = Path(os.getenv("MCP_OAUTH_DATABASE", str(config_dir / "oauth.db"))).expanduser()

        bind_host = os.getenv("MCP_HTTP_HOST", "127.0.0.1").strip() or "127.0.0.1"
        if bind_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("MCP_HTTP_HOST must be a loopback address when using Cloudflare Tunnel")

        try:
            bind_port = int(os.getenv("MCP_HTTP_PORT", "8000"))
        except ValueError as exc:
            raise ValueError("MCP_HTTP_PORT must be an integer") from exc
        if not 1 <= bind_port <= 65535:
            raise ValueError("MCP_HTTP_PORT must be between 1 and 65535")

        return cls(
            public_url=public_url,
            issuer_url=issuer_url,
            password_hash=password_hash,
            database_path=database_path,
            bind_host=bind_host,
            bind_port=bind_port,
            admin_username=os.getenv("MCP_OAUTH_ADMIN_USERNAME", "admin").strip() or "admin",
        )


def load_oauth_config() -> OAuthConfig:
    return OAuthConfig.from_env()
