"""ASGI application assembly and the single-user consent screen."""

import html
import hmac
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from mcp.server import MCPServer
from mcp.server.auth.handlers.metadata import MetadataHandler, ProtectedResourceMetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import ProtectedResourceMetadata
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..oauth_config import OAuthConfig
from .provider import SingleUserOAuthProvider
from .security import verify_password


SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


@dataclass
class LoginAttemptLimiter:
    max_failures: int = 10
    window_seconds: int = 15 * 60
    _failures: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def _trim(self, key: str, now: float) -> deque[float]:
        failures = self._failures[key]
        cutoff = now - self.window_seconds
        while failures and failures[0] < cutoff:
            failures.popleft()
        return failures

    def blocked(self, key: str) -> bool:
        return len(self._trim(key, time.monotonic())) >= self.max_failures

    def failed(self, key: str) -> None:
        self._trim(key, time.monotonic()).append(time.monotonic())

    def succeeded(self, key: str) -> None:
        self._failures.pop(key, None)


class ConsentEndpoint:
    def __init__(self, config: OAuthConfig, provider: SingleUserOAuthProvider):
        self.config = config
        self.provider = provider
        self.limiter = LoginAttemptLimiter()

    @staticmethod
    def _client_key(request: Request) -> str:
        connecting_ip = request.headers.get("cf-connecting-ip", "").strip()
        if connecting_ip:
            return connecting_ip[:128]
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _error_page(message: str, status_code: int = 400) -> HTMLResponse:
        body = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权失败</title><style>{PAGE_CSS}</style></head>
<body><main><h1>授权失败</h1><p>{html.escape(message)}</p></main></body></html>"""
        return HTMLResponse(body, status_code=status_code, headers=SECURITY_HEADERS)

    async def _render(self, request_id: str, csrf: str, error: str = "") -> HTMLResponse:
        pending = self.provider.store.load_pending_authorization(request_id)
        if pending is None:
            return self._error_page("授权请求已过期，请返回 ChatGPT 重新连接。")
        client = await self.provider.get_client(pending.client_id)
        client_name = client.client_name if client and client.client_name else "ChatGPT"
        scope_text = "、".join(pending.scopes)
        error_html = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
        body = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权 linux.do MCP</title><style>{PAGE_CSS}</style></head>
<body><main>
  <p class="eyebrow">linux.do MCP</p>
  <h1>允许 {html.escape(client_name)} 访问？</h1>
  <p>授权后可搜索、阅读 linux.do（Discourse 论坛）内容，使用服务器上已配置的登录身份。</p>
  <dl><dt>登录账号</dt><dd>{html.escape(self.config.admin_username)}</dd><dt>授权范围</dt><dd>{html.escape(scope_text)}</dd></dl>
  {error_html}
  <form method="post" action="/oauth/consent">
    <input type="hidden" name="request" value="{html.escape(request_id, quote=True)}">
    <input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">
    <label for="username">用户名</label>
    <input id="username" name="username" value="{html.escape(self.config.admin_username, quote=True)}" autocomplete="username" required>
    <label for="password">密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
    <div class="actions">
      <button class="secondary" type="submit" name="decision" value="deny" formnovalidate>拒绝</button>
      <button type="submit" name="decision" value="approve">允许</button>
    </div>
  </form>
</main></body></html>"""
        return HTMLResponse(body, headers=SECURITY_HEADERS)

    async def handle(self, request: Request) -> Response:
        if request.method == "GET":
            request_id = request.query_params.get("request", "")
            csrf = self.provider.store.set_pending_csrf(request_id)
            if not csrf:
                return self._error_page("授权请求已过期，请返回 ChatGPT 重新连接。")
            return await self._render(request_id, csrf)

        form = await request.form()
        request_id = str(form.get("request", ""))
        csrf = str(form.get("csrf", ""))
        pending = self.provider.store.load_pending_authorization(request_id)
        if pending is None or not self.provider.store.verify_pending_csrf(pending, csrf):
            return self._error_page("授权请求无效或已过期。")

        decision = str(form.get("decision", ""))
        if decision == "deny":
            redirect = self.provider.authorization_denied_redirect(request_id)
            return RedirectResponse(redirect, status_code=303, headers=SECURITY_HEADERS) if redirect else self._error_page("授权请求已过期。")
        if decision != "approve":
            return self._error_page("无效的授权操作。")

        client_key = self._client_key(request)
        if self.limiter.blocked(client_key):
            return self._error_page("登录尝试过多，请稍后重新连接。", status_code=429)

        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        valid_username = hmac.compare_digest(username.encode("utf-8"), self.config.admin_username.encode("utf-8"))
        valid_password = verify_password(password, self.config.password_hash)
        if not (valid_username and valid_password):
            self.limiter.failed(client_key)
            attempts = self.provider.store.record_failed_login(request_id)
            if attempts >= 5:
                self.provider.store.discard_pending_authorization(request_id)
                return self._error_page("登录失败次数过多，请返回 ChatGPT 重新连接。", status_code=429)
            return await self._render(request_id, csrf, "用户名或密码不正确。")

        self.limiter.succeeded(client_key)
        redirect = self.provider.authorization_success_redirect(request_id)
        return HTMLResponse(
            self._callback_handoff_page(redirect),
            status_code=200,
            headers=SECURITY_HEADERS,
        ) if redirect else self._error_page("授权请求已过期。")

    @staticmethod
    def _callback_handoff_page(redirect: str) -> str:
        safe_redirect = html.escape(redirect, quote=True)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>正在返回 ChatGPT</title><style>{PAGE_CSS}</style></head>
<body><main><p class="eyebrow">linux.do MCP</p><h1>授权成功</h1><p>正在返回 ChatGPT，请勿关闭此页面。</p>
<p><a id="continue" href="{safe_redirect}">若未自动返回，请点此继续</a></p></main>
<script>window.location.replace({json.dumps(redirect)});</script></body></html>"""


class RequiredResourceParameterMiddleware:
    """Require the configured RFC 8707 resource on every token request."""

    def __init__(self, app: ASGIApp, resource: str):
        self.app = app
        self.resource = resource

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") != "/token":
            await self.app(scope, receive, send)
            return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                return
            body.extend(message.get("body", b""))
            more_body = message.get("more_body", False)
            if len(body) > 64 * 1024:
                response = JSONResponse({"error": "invalid_request", "error_description": "Request body is too large"}, status_code=400)
                await response(scope, receive, send)
                return

        parameters = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        if parameters.get("resource") != [self.resource]:
            response = JSONResponse(
                {"error": "invalid_target", "error_description": "The MCP resource parameter is required"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
            await response(scope, receive, send)
            return

        replayed = False

        async def replay_body() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, send)


class OAuthBodyLimitMiddleware:
    """Bound form bodies before OAuth handlers parse them."""

    LIMITED_PATHS = {"/authorize", "/token", "/revoke", "/oauth/consent"}

    def __init__(self, app: ASGIApp, max_bytes: int = 64 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") not in self.LIMITED_PATHS:
            await self.app(scope, receive, send)
            return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                return
            body.extend(message.get("body", b""))
            more_body = message.get("more_body", False)
            if len(body) > self.max_bytes:
                response = JSONResponse(
                    {"error": "invalid_request", "error_description": "Request body is too large"},
                    status_code=400,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
                )
                await response(scope, receive, send)
                return

        replayed = False

        async def replay_body() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, send)


@dataclass
class OAuthRequestRateLimitMiddleware:
    """Limit unauthenticated OAuth requests by their Cloudflare source."""

    app: ASGIApp
    max_requests: int = 12
    window_seconds: int = 60
    _requests: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    @staticmethod
    def _client_key(scope: Scope) -> str:
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        connecting_ip = headers.get(b"cf-connecting-ip", b"").decode("ascii", errors="ignore").strip()
        if connecting_ip:
            return connecting_ip[:128]
        client = scope.get("client")
        return str(client[0])[:128] if client else "unknown"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        oauth_paths = {"/authorize", "/token", "/revoke", "/oauth/consent"}
        if scope["type"] == "http" and scope.get("path") in oauth_paths and len(scope.get("query_string", b"")) > 8192:
            response = JSONResponse(
                {"error": "invalid_request", "error_description": "Request query is too large"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
            await response(scope, receive, send)
            return
        if scope["type"] == "http" and scope.get("path") in {"/authorize", "/token", "/revoke"}:
            now = time.monotonic()
            key = self._client_key(scope)
            if key not in self._requests and len(self._requests) >= 4096:
                stale_before = now - self.window_seconds
                stale_keys = [
                    existing_key
                    for existing_key, timestamps in self._requests.items()
                    if not timestamps or timestamps[-1] < stale_before
                ]
                for stale_key in stale_keys:
                    self._requests.pop(stale_key, None)
                if len(self._requests) >= 4096:
                    self._requests.pop(next(iter(self._requests)))
            attempts = self._requests[key]
            cutoff = now - self.window_seconds
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            if len(attempts) >= self.max_requests:
                response = JSONResponse(
                    {"error": "temporarily_unavailable", "error_description": "Too many authorization requests"},
                    status_code=429,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Retry-After": "60"},
                )
                await response(scope, receive, send)
                return
            attempts.append(now)
        await self.app(scope, receive, send)


class PublicRevocationEndpoint:
    """Revoke public-client tokens without requiring a meaningless client secret."""

    def __init__(self, provider: SingleUserOAuthProvider):
        self.provider = provider

    async def handle(self, request: Request) -> Response:
        form = await request.form()
        token = str(form.get("token", ""))
        client_id = str(form.get("client_id", ""))
        if not token or not client_id:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "token and client_id are required"},
                status_code=400,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        client = await self.provider.get_client(client_id)
        if client is None:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Unknown OAuth client"},
                status_code=401,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

        self.provider.store.revoke_raw_token(token, client_id)
        return Response(status_code=200, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _authorization_metadata_route(config: OAuthConfig, auth: AuthSettings) -> Route:
    metadata = build_metadata(
        auth.issuer_url,
        auth.service_documentation_url,
        ClientRegistrationOptions(enabled=False, valid_scopes=list(config.scopes), default_scopes=list(config.scopes)),
        RevocationOptions(enabled=True),
    )
    metadata.client_id_metadata_document_supported = True
    metadata.authorization_response_iss_parameter_supported = True
    metadata.token_endpoint_auth_methods_supported = ["none"]
    metadata.revocation_endpoint_auth_methods_supported = ["none"]
    return Route(
        "/.well-known/oauth-authorization-server",
        endpoint=cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
        methods=["GET", "OPTIONS"],
    )


def _root_resource_metadata_route(config: OAuthConfig, auth: AuthSettings) -> Route:
    metadata = ProtectedResourceMetadata(
        resource=auth.resource_server_url,
        authorization_servers=[auth.issuer_url],
        scopes_supported=list(config.scopes),
        resource_name="Linux.do MCP Server",
    )
    return Route(
        "/.well-known/oauth-protected-resource",
        endpoint=cors_middleware(ProtectedResourceMetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
        methods=["GET", "OPTIONS"],
    )


def build_remote_app(
    config: OAuthConfig,
    remote_server: MCPServer,
    provider: SingleUserOAuthProvider,
    auth: AuthSettings,
) -> ASGIApp:
    public = urlsplit(config.public_url)
    public_host = public.netloc
    public_origin = f"{public.scheme}://{public.netloc}"
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[public_host, "127.0.0.1:*", "localhost:*", "[::1]:*"],
        allowed_origins=[public_origin],
    )
    app = remote_server.streamable_http_app(
        streamable_http_path=config.resource_path,
        json_response=True,
        stateless_http=True,
        transport_security=transport_security,
        host=config.bind_host,
    )

    auth_routes = create_auth_routes(
        provider=provider,
        issuer_url=auth.issuer_url,
        service_documentation_url=auth.service_documentation_url,
        client_registration_options=ClientRegistrationOptions(enabled=False),
        revocation_options=RevocationOptions(enabled=False),
    )
    auth_routes = [route for route in auth_routes if getattr(route, "path", "") != "/.well-known/oauth-authorization-server"]
    consent = ConsentEndpoint(config, provider)
    revocation = PublicRevocationEndpoint(provider)
    app.router.routes = [
        _authorization_metadata_route(config, auth),
        _root_resource_metadata_route(config, auth),
        Route("/oauth/consent", endpoint=consent.handle, methods=["GET", "POST"]),
        Route("/revoke", endpoint=revocation.handle, methods=["POST"]),
        *auth_routes,
        *app.router.routes,
    ]
    protected_app = RequiredResourceParameterMiddleware(app, config.public_url)
    limited_app = OAuthBodyLimitMiddleware(protected_app)
    return OAuthRequestRateLimitMiddleware(limited_app)


PAGE_CSS = """
:root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; color: #17202a; background: #f4f6f7; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; }
main { width: min(100%, 440px); background: #fff; border: 1px solid #d5d8dc; border-radius: 8px; padding: 28px; box-shadow: 0 12px 30px rgba(23,32,42,.08); }
h1 { margin: 6px 0 10px; font-size: 24px; line-height: 1.25; letter-spacing: 0; }
p { color: #566573; line-height: 1.55; }
.eyebrow { margin: 0; color: #117864; font-size: 13px; font-weight: 700; }
dl { display: grid; grid-template-columns: 88px 1fr; gap: 8px 12px; margin: 22px 0; padding: 14px 0; border-block: 1px solid #e5e7e9; }
dt { color: #7b7d7d; } dd { margin: 0; overflow-wrap: anywhere; }
label { display: block; margin: 14px 0 6px; font-weight: 650; }
input { width: 100%; min-height: 44px; padding: 10px 12px; border: 1px solid #aeb6bf; border-radius: 6px; font: inherit; }
input:focus { outline: 3px solid rgba(17,120,100,.18); border-color: #117864; }
.actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 22px; }
button { min-height: 44px; border: 1px solid #117864; border-radius: 6px; background: #117864; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
button.secondary { background: #fff; color: #34495e; border-color: #aeb6bf; }
.error { padding: 10px 12px; border-left: 3px solid #c0392b; background: #fdf2f0; color: #922b21; }
"""
