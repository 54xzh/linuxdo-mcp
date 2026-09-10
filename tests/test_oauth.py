"""OAuth / streamable-http 远程模式的测试，写法沿用 miot-mcp 的 tests/test_oauth.py。"""

import asyncio
import base64
import hashlib
import html
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from mcp.server.auth.settings import AuthSettings

from linuxdo_mcp.oauth.app import RequiredResourceParameterMiddleware, build_remote_app
from linuxdo_mcp.oauth.provider import ChatGPTClientResolver, SingleUserOAuthProvider, StoreTokenVerifier
from linuxdo_mcp.oauth.security import hash_password, secret_digest, verify_password
from linuxdo_mcp.oauth.store import OAuthStore
from linuxdo_mcp.oauth_config import OAuthConfig, load_oauth_config
from linuxdo_mcp.server import create_remote_server, mcp

PASSWORD = "correct horse battery staple"
CLIENT_ID = "https://chatgpt.com/oauth/test-connector/client.json"
REDIRECT_URI = "https://chatgpt.com/connector/oauth/test-callback"
PUBLIC_URL = "https://mcp.example.com/mcp"
ISSUER_URL = "https://mcp.example.com"
SCOPE = "linuxdo:access"


def make_config(tmp_path: Path) -> OAuthConfig:
    return OAuthConfig(
        public_url=PUBLIC_URL,
        issuer_url=ISSUER_URL,
        password_hash=hash_password(PASSWORD),
        database_path=tmp_path / "oauth.db",
    )


async def fetch_chatgpt_client(_: str) -> dict:
    return {
        "client_id": CLIENT_ID,
        "client_name": "ChatGPT",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "application_type": "web",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "token_endpoint_auth_method": "private_key_jwt",
    }


def build_test_service(tmp_path: Path):
    config = make_config(tmp_path)
    store = OAuthStore(config.database_path)
    resolver = ChatGPTClientResolver(config.scopes, fetcher=fetch_chatgpt_client)
    provider = SingleUserOAuthProvider(config, store, resolver)
    verifier = StoreTokenVerifier(provider)
    auth = AuthSettings(
        issuer_url=config.issuer_url,
        resource_server_url=config.public_url,
        required_scopes=list(config.scopes),
        validate_token_resource=False,
    )
    server = create_remote_server(auth, verifier)
    app = build_remote_app(config, server, provider, auth)
    return config, store, provider, server, app


def pkce_pair() -> tuple[str, str]:
    verifier = "test-verifier-" + "x" * 64
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def hidden_value(page: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]+)"', page)
    assert match
    return match.group(1)


def authorize_query(challenge: str, state: str = "state-123") -> str:
    return urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": PUBLIC_URL,
        }
    )


def test_password_hash_round_trip():
    encoded = hash_password(PASSWORD)
    assert verify_password(PASSWORD, encoded)
    assert not verify_password("incorrect password", encoded)
    assert not verify_password(PASSWORD, "not-a-password-hash")


def test_remote_server_has_same_tools_as_local(tmp_path: Path):
    """linuxdo 没有登录管理类工具，远程与本地工具集应完全一致。"""
    _, _, _, remote, _ = build_test_service(tmp_path)
    local_tool_names = {tool.name for tool in asyncio.run(mcp.list_tools())}
    remote_tool_names = {tool.name for tool in asyncio.run(remote.list_tools())}
    assert local_tool_names == remote_tool_names
    assert "whoami" in remote_tool_names and "search" in remote_tool_names


def test_refresh_token_replay_revokes_rotated_family(tmp_path: Path):
    store = OAuthStore(tmp_path / "oauth.db")
    now = int(time.time())
    family_id = "family-1"
    old_access = "old-access-token"
    old_refresh = "old-refresh-token"
    common = (CLIENT_ID, f'["{SCOPE}"]', now + 3600, PUBLIC_URL, "admin", family_id)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            INSERT INTO access_tokens(token_digest, client_id, scopes_json, expires_at, resource, subject, family_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (secret_digest(old_access), *common),
        )
        connection.execute(
            """
            INSERT INTO refresh_tokens(token_digest, client_id, scopes_json, expires_at, resource, subject, family_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (secret_digest(old_refresh), *common),
        )

    loaded = store.load_refresh_token(old_refresh, CLIENT_ID)
    assert loaded is not None
    rotated = store.rotate_refresh_token(loaded, [SCOPE], 1800, 3600)
    assert rotated is not None
    assert store.load_access_token(rotated.access_token) is not None

    # 重放旧 refresh token 应作废整条 token family
    assert store.load_refresh_token(old_refresh, CLIENT_ID) is None
    assert store.load_access_token(rotated.access_token) is None
    assert store.load_refresh_token(rotated.refresh_token, CLIENT_ID) is None


@pytest.mark.asyncio
async def test_discovery_and_unauthorized_challenge(tmp_path: Path):
    _, _, _, _, app = build_test_service(tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=ISSUER_URL,
    ) as client:
        auth_metadata = await client.get("/.well-known/oauth-authorization-server")
        resource_metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
        root_metadata = await client.get("/.well-known/oauth-protected-resource")
        unauthorized = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        )

    assert auth_metadata.status_code == 200
    assert auth_metadata.json()["client_id_metadata_document_supported"] is True
    assert auth_metadata.json()["token_endpoint_auth_methods_supported"] == ["none"]
    assert auth_metadata.json()["revocation_endpoint"] == f"{ISSUER_URL}/revoke"
    assert auth_metadata.json()["code_challenge_methods_supported"] == ["S256"]
    assert resource_metadata.status_code == 200
    assert resource_metadata.json()["resource"] == PUBLIC_URL
    assert resource_metadata.json()["scopes_supported"] == [SCOPE]
    assert resource_metadata.json()["authorization_servers"] == [ISSUER_URL]
    # resource_name 只出现在根路径的发现文档里（带 /mcp 的那份由 MCP SDK 生成）
    assert root_metadata.status_code == 200
    assert root_metadata.json()["resource_name"] == "Linux.do MCP Server"
    assert unauthorized.status_code == 401
    assert "resource_metadata=" in unauthorized.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_chatgpt_authorization_code_and_refresh_flow(tmp_path: Path):
    _, _, provider, _, app = build_test_service(tmp_path)
    verifier, challenge = pkce_pair()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=ISSUER_URL,
        follow_redirects=False,
    ) as client:
        authorize = await client.get(f"/authorize?{authorize_query(challenge)}")
        assert authorize.status_code == 302
        consent_url = authorize.headers["location"]

        consent = await client.get(consent_url)
        assert consent.status_code == 200
        assert "linux.do MCP" in consent.text
        request_id = hidden_value(consent.text, "request")
        csrf = hidden_value(consent.text, "csrf")

        bad_password = await client.post(
            "/oauth/consent",
            data={
                "request": request_id,
                "csrf": csrf,
                "username": "admin",
                "password": "wrong-password-here",
                "decision": "approve",
            },
        )
        assert bad_password.status_code == 200
        assert "用户名或密码不正确" in bad_password.text

        approved = await client.post(
            "/oauth/consent",
            data={
                "request": request_id,
                "csrf": csrf,
                "username": "admin",
                "password": PASSWORD,
                "decision": "approve",
            },
        )
        assert approved.status_code == 200
        assert "window.location.replace(" in approved.text
        assert f'href="{REDIRECT_URI}?code=' in approved.text
        callback_match = re.search(r'<a id="continue" href="([^"]+)"', approved.text)
        assert callback_match is not None
        callback = urlsplit(html.unescape(callback_match.group(1)))
        callback_params = parse_qs(callback.query)
        assert callback_params["state"] == ["state-123"]
        assert callback_params["iss"] == [ISSUER_URL]
        code = callback_params["code"][0]

        token_response = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
                "resource": PUBLIC_URL,
            },
        )
        assert token_response.status_code == 200, token_response.text
        tokens = token_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        assert (await provider.load_access_token(access_token)) is not None

        lifespan_app = app
        while not hasattr(lifespan_app, "router"):
            lifespan_app = lifespan_app.app
        async with lifespan_app.router.lifespan_context(lifespan_app):
            initialized = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "ChatGPT test", "version": "1"},
                    },
                },
            )
            assert initialized.status_code == 200, initialized.text
            assert initialized.json()["result"]["serverInfo"]["name"] == "linuxdo"

            tools = await client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json, text/event-stream",
                },
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            assert tools.status_code == 200, tools.text
            assert {t["name"] for t in tools.json()["result"]["tools"]} >= {"search", "get_topic"}

        reused_code = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
                "resource": PUBLIC_URL,
            },
        )
        assert reused_code.status_code == 400
        assert reused_code.json()["error"] == "invalid_grant"

        refreshed = await client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
                "scope": SCOPE,
                "resource": PUBLIC_URL,
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["refresh_token"] != refresh_token
        assert (await provider.load_access_token(access_token)) is None

        revoked = await client.post(
            "/revoke",
            data={
                "client_id": CLIENT_ID,
                "token": refresh_token,
                "token_type_hint": "refresh_token",
            },
        )
        assert revoked.status_code == 200

        refresh_after_revoke = await client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refreshed.json()["refresh_token"],
                "scope": SCOPE,
                "resource": PUBLIC_URL,
            },
        )
        assert refresh_after_revoke.status_code == 400
        assert refresh_after_revoke.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_deny_redirects_with_access_denied(tmp_path: Path):
    _, _, _, _, app = build_test_service(tmp_path)
    _, challenge = pkce_pair()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ISSUER_URL, follow_redirects=False
    ) as client:
        authorize = await client.get(f"/authorize?{authorize_query(challenge)}")
        consent = await client.get(authorize.headers["location"])
        denied = await client.post(
            "/oauth/consent",
            data={
                "request": hidden_value(consent.text, "request"),
                "csrf": hidden_value(consent.text, "csrf"),
                "decision": "deny",
            },
        )
    assert denied.status_code == 303
    location = urlsplit(denied.headers["location"])
    assert location.scheme == "https" and location.netloc == "chatgpt.com"
    assert parse_qs(location.query)["error"] == ["access_denied"]


@pytest.mark.asyncio
async def test_authorize_rejects_wrong_resource_and_scope(tmp_path: Path):
    """resource / scope 不合法时，按 OAuth 规范重定向回客户端并带 error。"""
    _, _, _, _, app = build_test_service(tmp_path)
    _, challenge = pkce_pair()
    base = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": "x",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ISSUER_URL, follow_redirects=False
    ) as client:
        wrong_resource = await client.get(
            f"/authorize?{urlencode({**base, 'scope': SCOPE, 'resource': 'https://evil.example/mcp'})}"
        )
        wrong_scope = await client.get(
            f"/authorize?{urlencode({**base, 'scope': 'other:scope', 'resource': PUBLIC_URL})}"
        )
        no_resource = await client.get(
            f"/authorize?{urlencode({**base, 'scope': SCOPE})}"
        )

    for response, expected in (
        (wrong_resource, "invalid_target"),
        (wrong_scope, "invalid_scope"),
        (no_resource, "invalid_target"),
    ):
        assert response.status_code == 302
        location = urlsplit(response.headers["location"])
        assert location.netloc == "chatgpt.com", location
        params = parse_qs(location.query)
        assert params["error"] == [expected]
        assert params["state"] == ["x"]


@pytest.mark.asyncio
async def test_token_endpoint_requires_exact_resource(tmp_path: Path):
    _, _, _, _, app = build_test_service(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ISSUER_URL) as client:
        response = await client.post(
            "/token",
            data={"grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": "invalid"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"


@pytest.mark.asyncio
async def test_authorize_rate_limit_and_form_body_limit(tmp_path: Path):
    _, _, _, _, app = build_test_service(tmp_path)
    _, challenge = pkce_pair()
    query = authorize_query(challenge, state="rate-limit-test")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ISSUER_URL) as client:
        oversized_query = await client.get("/authorize?state=" + "x" * 8192)
        for _ in range(12):
            assert (await client.get(f"/authorize?{query}")).status_code == 302
        limited = await client.get(f"/authorize?{query}")
        oversized = await client.post(
            "/oauth/consent",
            content=b"x" * (64 * 1024 + 1),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert oversized_query.status_code == 400
    assert oversized_query.json()["error"] == "invalid_request"
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
    assert oversized.status_code == 400
    assert oversized.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_cimd_rejects_non_chatgpt_targets(tmp_path: Path):
    config = make_config(tmp_path)
    resolver = ChatGPTClientResolver(config.scopes, fetcher=fetch_chatgpt_client)
    assert await resolver.resolve("https://example.com/oauth/x/client.json") is None
    assert await resolver.resolve("https://chatgpt.com:444/oauth/x/client.json") is None
    assert await resolver.resolve("https://chatgpt.com/oauth/x/not-client.json") is None


@pytest.mark.asyncio
async def test_cimd_requires_matching_client_id_and_caches_failures(tmp_path: Path):
    config = make_config(tmp_path)
    calls = 0

    async def fetch_without_client_id(_: str) -> dict:
        nonlocal calls
        calls += 1
        document = await fetch_chatgpt_client(CLIENT_ID)
        document.pop("client_id")
        return document

    resolver = ChatGPTClientResolver(config.scopes, fetcher=fetch_without_client_id)
    assert await resolver.resolve(CLIENT_ID) is None
    assert await resolver.resolve(CLIENT_ID) is None
    assert calls == 1


@pytest.mark.asyncio
async def test_cimd_accepts_legacy_chatgpt_callback(tmp_path: Path):
    config = make_config(tmp_path)

    async def fetch_legacy_client(_: str) -> dict:
        document = await fetch_chatgpt_client(CLIENT_ID)
        document["redirect_uris"] = ["https://chatgpt.com/connector_platform_oauth_redirect"]
        return document

    resolver = ChatGPTClientResolver(config.scopes, fetcher=fetch_legacy_client)
    assert await resolver.resolve(CLIENT_ID) is not None


def test_cimd_cache_is_bounded(tmp_path: Path):
    config = make_config(tmp_path)
    resolver = ChatGPTClientResolver(config.scopes, fetcher=fetch_chatgpt_client)
    for index in range(resolver.MAX_CACHE_ENTRIES + 20):
        resolver._cache_result(f"https://chatgpt.com/oauth/{index}/client.json", None)
    assert len(resolver._cache) == resolver.MAX_CACHE_ENTRIES


@pytest.mark.asyncio
async def test_token_body_middleware_stops_when_client_disconnects():
    downstream_called = False
    sent = False

    async def downstream(scope, receive, send):
        nonlocal downstream_called
        downstream_called = True

    async def receive():
        return {"type": "http.disconnect"}

    async def send(_):
        nonlocal sent
        sent = True

    middleware = RequiredResourceParameterMiddleware(downstream, PUBLIC_URL)
    await asyncio.wait_for(
        middleware({"type": "http", "method": "POST", "path": "/token"}, receive, send),
        timeout=1,
    )
    assert not downstream_called
    assert not sent


def test_oauth_config_normalizes_public_origin(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://EXAMPLE.com:443/mcp/")
    monkeypatch.setenv("MCP_OAUTH_PASSWORD_HASH", hash_password(PASSWORD))
    monkeypatch.setenv("MCP_CONFIG_DIR", str(tmp_path))
    config = load_oauth_config()
    assert config.public_url == "https://example.com/mcp"
    assert config.issuer_url == "https://example.com"
    assert config.scopes == (SCOPE,)
    assert config.database_path == tmp_path / "oauth.db"


@pytest.mark.parametrize("public_url", [
    "https://example.com/authorize",
    "https://example.com/.well-known/oauth-authorization-server",
    "https://example.com/oauth/consent",
    "https://example.com",
    "http://example.com/mcp",
    "https://example.com/mcp?x=1",
])
def test_oauth_config_rejects_noncanonical_or_reserved_paths(monkeypatch, public_url: str):
    monkeypatch.setenv("MCP_PUBLIC_URL", public_url)
    monkeypatch.setenv("MCP_OAUTH_PASSWORD_HASH", hash_password(PASSWORD))
    with pytest.raises(ValueError):
        load_oauth_config()


def test_oauth_config_requires_loopback_bind(monkeypatch):
    monkeypatch.setenv("MCP_PUBLIC_URL", PUBLIC_URL)
    monkeypatch.setenv("MCP_OAUTH_PASSWORD_HASH", hash_password(PASSWORD))
    monkeypatch.setenv("MCP_HTTP_HOST", "0.0.0.0")
    with pytest.raises(ValueError):
        load_oauth_config()
