"""OAuth provider backed by the local SQLite store."""

import json
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import quote, urlsplit

import anyio
import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from ..oauth_config import OAuthConfig
from .store import OAuthStore, StoredRefreshToken


ClientDocumentFetcher = Callable[[str], Awaitable[dict[str, Any]]]


@dataclass
class CachedClient:
    client: OAuthClientInformationFull | None
    expires_at: float


class ChatGPTClientResolver:
    """Resolve only OpenAI-hosted CIMD documents and reject arbitrary fetch targets."""

    MAX_CACHE_ENTRIES = 512

    def __init__(self, scopes: tuple[str, ...], fetcher: ClientDocumentFetcher | None = None):
        self.scopes = scopes
        self.fetcher = fetcher or self._fetch_document
        self._cache: dict[str, CachedClient] = {}
        self._fetch_semaphore = anyio.Semaphore(4)
        self._fetch_times: deque[float] = deque()
        self._fetch_times_lock = threading.Lock()

    @staticmethod
    def _validate_client_id_url(client_id: str) -> bool:
        try:
            parsed = urlsplit(client_id)
            return (
                parsed.scheme == "https"
                and parsed.hostname == "chatgpt.com"
                and parsed.port in {None, 443}
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and parsed.path.startswith("/oauth/")
                and parsed.path.endswith("/client.json")
            )
        except ValueError:
            return False

    @staticmethod
    async def _fetch_document(client_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
            async with client.stream("GET", client_id, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared_length = int(content_length)
                    except ValueError as exc:
                        raise ValueError("Client metadata document has an invalid Content-Length") from exc
                    if declared_length < 0 or declared_length > 64 * 1024:
                        raise ValueError("Client metadata document is too large")

                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 64 * 1024:
                        raise ValueError("Client metadata document is too large")

        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("Client metadata document must contain a JSON object")
        return payload

    @staticmethod
    def _valid_chatgpt_redirect(uri: str) -> bool:
        try:
            parsed = urlsplit(uri)
            return (
                parsed.scheme == "https"
                and parsed.hostname == "chatgpt.com"
                and parsed.port in {None, 443}
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and (
                    parsed.path.startswith("/connector/oauth/")
                    or parsed.path == "/connector_platform_oauth_redirect"
                )
            )
        except ValueError:
            return False

    def _cached(self, client_id: str) -> tuple[bool, OAuthClientInformationFull | None]:
        cached = self._cache.get(client_id)
        if cached and cached.expires_at > time.monotonic():
            return True, cached.client
        if cached:
            self._cache.pop(client_id, None)
        return False, None

    def _cache_result(self, client_id: str, client: OAuthClientInformationFull | None) -> None:
        ttl = 300 if client is not None else 30
        self._cache.pop(client_id, None)
        self._cache[client_id] = CachedClient(client=client, expires_at=time.monotonic() + ttl)
        now = time.monotonic()
        expired = [key for key, cached in self._cache.items() if cached.expires_at <= now]
        for key in expired:
            self._cache.pop(key, None)
        while len(self._cache) > self.MAX_CACHE_ENTRIES:
            self._cache.pop(next(iter(self._cache)))

    def _fetch_allowed(self) -> bool:
        now = time.monotonic()
        with self._fetch_times_lock:
            cutoff = now - 60
            while self._fetch_times and self._fetch_times[0] < cutoff:
                self._fetch_times.popleft()
            if len(self._fetch_times) >= 20:
                return False
            self._fetch_times.append(now)
            return True

    async def resolve(self, client_id: str) -> OAuthClientInformationFull | None:
        if not self._validate_client_id_url(client_id):
            return None
        found, cached_client = self._cached(client_id)
        if found:
            return cached_client

        async with self._fetch_semaphore:
            found, cached_client = self._cached(client_id)
            if found:
                return cached_client
            if not self._fetch_allowed():
                return None
            try:
                payload = await self.fetcher(client_id)
                if payload.get("client_id") != client_id:
                    raise ValueError("Client metadata document has an invalid client_id")
                redirects = payload.get("redirect_uris")
                if not isinstance(redirects, list) or not redirects:
                    raise ValueError("Client metadata document has no redirect URI")
                if not all(isinstance(uri, str) and self._valid_chatgpt_redirect(uri) for uri in redirects):
                    raise ValueError("Client metadata document has an invalid redirect URI")

                supported_methods = payload.get("token_endpoint_auth_methods_supported", [])
                legacy_method = payload.get("token_endpoint_auth_method")
                if not isinstance(supported_methods, list):
                    supported_methods = []
                if "none" not in supported_methods and legacy_method != "none":
                    raise ValueError("Client metadata document does not support public clients")

                metadata_payload = dict(payload)
                metadata_payload.pop("client_id", None)
                metadata_payload.pop("token_endpoint_auth_methods_supported", None)
                metadata_payload["token_endpoint_auth_method"] = "none"
                metadata_payload["scope"] = " ".join(self.scopes)
                metadata = OAuthClientMetadata.model_validate(metadata_payload)
                if "authorization_code" not in metadata.grant_types or "code" not in metadata.response_types:
                    raise ValueError("Client metadata document does not support the authorization code flow")
                client = OAuthClientInformationFull.model_validate(
                    {**metadata.model_dump(), "client_id": client_id, "client_secret": None}
                )
            except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError):
                self._cache_result(client_id, None)
                return None

        self._cache_result(client_id, client)
        return client


class SingleUserOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, StoredRefreshToken, AccessToken]
):
    def __init__(
        self,
        config: OAuthConfig,
        store: OAuthStore,
        client_resolver: ChatGPTClientResolver | None = None,
    ):
        self.config = config
        self.store = store
        self.client_resolver = client_resolver or ChatGPTClientResolver(config.scopes)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        stored = self.store.load_client(client_id)
        if stored is not None:
            return stored
        return await self.client_resolver.resolve(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise RegistrationError(
            error="invalid_client_metadata",
            error_description="Dynamic client registration is disabled; use ChatGPT CIMD",
        )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource != self.config.public_url:
            raise AuthorizeError(error="invalid_target", error_description="Invalid MCP resource")
        requested_scopes = set(params.scopes or [])
        if not requested_scopes or not requested_scopes.issubset(self.config.scopes):
            raise AuthorizeError(error="invalid_scope", error_description="Invalid MCP scope")
        try:
            request_id = self.store.create_pending_authorization(
                client.client_id,
                params,
                self.config.pending_authorization_ttl_seconds,
            )
        except RuntimeError as exc:
            raise AuthorizeError(
                error="temporarily_unavailable",
                error_description="Too many pending authorization requests; try again later",
            ) from exc
        return f"{self.config.issuer_url}/oauth/consent?request={quote(request_id, safe='')}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        return self.store.load_authorization_code(authorization_code, client.client_id)

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        if authorization_code.client_id != client.client_id or authorization_code.resource != self.config.public_url:
            raise TokenError(error="invalid_grant", error_description="Authorization code is not valid for this MCP server")
        issued = self.store.exchange_authorization_code(
            authorization_code.code,
            self.config.access_token_ttl_seconds,
            self.config.refresh_token_ttl_seconds,
        )
        if issued is None:
            raise TokenError(error="invalid_grant", error_description="Authorization code has already been used")
        return OAuthToken(
            access_token=issued.access_token,
            refresh_token=issued.refresh_token,
            expires_in=issued.access_expires_in,
            scope=" ".join(issued.scopes),
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> StoredRefreshToken | None:
        token = self.store.load_refresh_token(refresh_token, client.client_id)
        if token is None or token.resource != self.config.public_url:
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: StoredRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if refresh_token.client_id != client.client_id or refresh_token.resource != self.config.public_url:
            raise TokenError(error="invalid_grant", error_description="Refresh token is not valid for this MCP server")
        issued = self.store.rotate_refresh_token(
            refresh_token,
            scopes,
            self.config.access_token_ttl_seconds,
            self.config.refresh_token_ttl_seconds,
        )
        if issued is None:
            raise TokenError(error="invalid_grant", error_description="Refresh token has already been used")
        return OAuthToken(
            access_token=issued.access_token,
            refresh_token=issued.refresh_token,
            expires_in=issued.access_expires_in,
            scope=" ".join(issued.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self.store.load_access_token(token)
        if access_token is None or access_token.resource != self.config.public_url:
            return None
        access_token.claims = {"iss": self.config.issuer_url}
        return access_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.store.revoke_token(token)

    def authorization_success_redirect(self, request_id: str) -> str | None:
        approved = self.store.approve_pending_authorization(
            request_id,
            subject=self.config.admin_username,
            code_ttl_seconds=self.config.authorization_code_ttl_seconds,
        )
        if approved is None:
            return None
        code, pending = approved
        return construct_redirect_uri(
            pending.redirect_uri,
            code=code,
            state=pending.state,
            iss=self.config.issuer_url,
        )

    def authorization_denied_redirect(self, request_id: str) -> str | None:
        pending = self.store.load_pending_authorization(request_id)
        if pending is None:
            return None
        self.store.discard_pending_authorization(request_id)
        return construct_redirect_uri(
            pending.redirect_uri,
            error="access_denied",
            error_description="The user denied the request",
            state=pending.state,
            iss=self.config.issuer_url,
        )


class StoreTokenVerifier:
    def __init__(self, provider: SingleUserOAuthProvider):
        self.provider = provider

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self.provider.load_access_token(token)
