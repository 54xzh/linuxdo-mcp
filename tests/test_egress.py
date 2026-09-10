"""直连/备用出口自动切换的单元测试（假 creq.get，不打网络、不碰真实 cookie 缓存）。"""

import json
import time

import pytest

from linuxdo_mcp import server as S

PROXY = "socks5h://127.0.0.1:25344"
CHALLENGE = "<html><head><title>Just a moment...</title></head></html>"
OK = json.dumps({"topic_list": {"topics": [{"id": 1}]}})


class FakeResponse:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.cookies = None


class FakeCurl:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append({"url": url, "proxies": kwargs.get("proxies")})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(S.time, "sleep", lambda _s: None)
    monkeypatch.setattr(S.cookies, "get_cookie", lambda: "_t=test")
    monkeypatch.setattr(S.cookies, "absorb_rotation", lambda r: None)
    monkeypatch.setattr(S.cookies, "clear_cache", lambda: None)
    monkeypatch.setattr(S, "_proxy_state", {"until": 0.0})
    S._proxy_state["until"] = 0.0
    yield
    S._proxy_state["until"] = 0.0


def use(monkeypatch, script, proxy=PROXY):
    fake = FakeCurl(script)
    monkeypatch.setattr(S, "PROXY_URL", proxy)
    monkeypatch.setattr(S, "creq", fake)
    return fake


def test_no_proxy_configured_keeps_old_behaviour(monkeypatch):
    fake = use(monkeypatch, [FakeResponse(429, '{"errors":["slow down"]}')], proxy="")

    with pytest.raises(RuntimeError, match="429"):
        S._fetch("/search.json?q=x")

    assert len(fake.calls) == 1
    assert fake.calls[0]["proxies"] is None


def test_challenge_switches_to_proxy_and_returns(monkeypatch):
    fake = use(monkeypatch, [FakeResponse(403, CHALLENGE), FakeResponse(200, OK)])

    assert S._fetch("/search.json?q=x")["topic_list"]["topics"] == [{"id": 1}]

    assert fake.calls[0]["proxies"] is None
    assert fake.calls[1]["proxies"] == {"http": PROXY, "https": PROXY}
    assert S._proxy_state["until"] > time.monotonic()


def test_429_also_switches_to_proxy(monkeypatch):
    fake = use(monkeypatch, [FakeResponse(429, CHALLENGE), FakeResponse(200, OK)])

    S._fetch("/site.json")

    assert fake.calls[1]["proxies"] == {"http": PROXY, "https": PROXY}


def test_during_cooldown_goes_straight_to_proxy(monkeypatch):
    fake = use(monkeypatch, [FakeResponse(200, OK)])
    S._proxy_state["until"] = time.monotonic() + 100

    S._fetch("/site.json")

    assert fake.calls[0]["proxies"] == {"http": PROXY, "https": PROXY}


def test_after_cooldown_tries_direct_first(monkeypatch):
    fake = use(monkeypatch, [FakeResponse(200, OK)])
    S._proxy_state["until"] = time.monotonic() - 1

    S._fetch("/site.json")

    assert fake.calls[0]["proxies"] is None


def test_direct_then_proxy_both_blocked_raises(monkeypatch):
    fake = use(monkeypatch, [FakeResponse(403, CHALLENGE)] * 3)

    with pytest.raises(RuntimeError, match="Cloudflare"):
        S._fetch("/site.json")

    assert len(fake.calls) == 3
    assert fake.calls[0]["proxies"] is None
    assert all(c["proxies"] is not None for c in fake.calls[1:])


def test_proxy_own_429_raises_immediately(monkeypatch):
    """备用出口自己被限流时直接报错，不要来回横跳回直连。"""
    fake = use(monkeypatch, [FakeResponse(429, '{"errors":["x"]}')])
    S._proxy_state["until"] = time.monotonic() + 100

    with pytest.raises(RuntimeError, match="429"):
        S._fetch("/site.json")

    assert len(fake.calls) == 1
    assert fake.calls[0]["proxies"] is not None


def test_proxy_challenge_retries_within_proxy_then_raises(monkeypatch):
    """备用出口也被挑战时，重试也只在备用出口上重试，不会回直连。"""
    fake = use(monkeypatch, [FakeResponse(403, CHALLENGE)] * 3)
    S._proxy_state["until"] = time.monotonic() + 100

    with pytest.raises(RuntimeError, match="Cloudflare"):
        S._fetch("/site.json")

    assert len(fake.calls) == 3
    assert all(c["proxies"] is not None for c in fake.calls)


def test_auth_failure_clears_cache_and_raises(monkeypatch):
    cleared = []
    monkeypatch.setattr(S.cookies, "clear_cache", lambda: cleared.append(True))
    fake = use(monkeypatch, [FakeResponse(401, '{"errors":["invalid"]}')])

    with pytest.raises(RuntimeError, match="认证失败"):
        S._fetch("/session/current.json")

    assert cleared == [True]
    assert len(fake.calls) == 1


def test_transport_error_retries_three_times(monkeypatch):
    fake = use(monkeypatch, [RuntimeError("连接超时")] * 3)

    with pytest.raises(RuntimeError, match="请求失败"):
        S._fetch("/site.json")

    assert len(fake.calls) == 3


def test_non_json_200_raises(monkeypatch):
    use(monkeypatch, [FakeResponse(200, "<html>hello</html>")])

    with pytest.raises(RuntimeError, match="异常响应"):
        S._fetch("/site.json")


def test_rotation_is_absorbed_on_success(monkeypatch):
    absorbed = []
    monkeypatch.setattr(S.cookies, "absorb_rotation", lambda r: absorbed.append(r))
    response = FakeResponse(200, OK)
    use(monkeypatch, [response])

    S._fetch("/site.json")

    assert absorbed == [response]
