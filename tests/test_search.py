"""search 翻页与分类解析的单元测试（用假 _fetch，不打真网络）。"""

import pytest

from linuxdo_mcp import server as S


def page_payload(topics, term="lebara", more=None, categories=None):
    """topics: [(topic_id, category_id), ...]"""
    return {
        "posts": [{"topic_id": tid, "blurb": f"<p>blurb {tid}</p>"} for tid, _ in topics],
        "topics": [
            {
                "id": tid,
                "title": f"title {tid}",
                "slug": f"slug-{tid}",
                "category_id": cid,
                "tags": [{"name": "人工智能"}] if tid % 2 else [],
                "posts_count": 3,
                "created_at": "2026-09-10T00:00:00Z",
            }
            for tid, cid in topics
        ],
        "grouped_search_result": ({"term": term} if more is None else {"term": term, "more_full_page_results": more}),
        **({"categories": categories} if categories is not None else {}),
    }


def make_fetch(payloads, calls):
    def fetch(path):
        calls.append(path)
        number = int(path.rsplit("page=", 1)[1])
        value = payloads.get(number, {"posts": [], "topics": [], "grouped_search_result": {}})
        if isinstance(value, Exception):
            raise value
        return value

    return fetch


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(S.time, "sleep", lambda _seconds: None)


@pytest.fixture(autouse=True)
def site_index(monkeypatch):
    """默认让 /site.json 索引可用；单个用例可再次 patch 覆盖。"""
    monkeypatch.setattr(S, "_category_index", lambda: {4: {"name": "开发调优", "trust_level": None},
                                                      5: {"name": "搞七捻三", "trust_level": 1}})


def test_pages_accumulate_and_dedupe(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({
        1: page_payload([(1, 4), (2, 4)], more=True),
        2: page_payload([(2, 4), (3, 5)]),
    }, calls))

    out = S._search("lebara", 1, 2)

    assert [r["topic_id"] for r in out["results"]] == [1, 2, 3]
    assert out["count"] == 3
    assert calls == ["/search.json?q=lebara&page=1", "/search.json?q=lebara&page=2"]
    assert out["more_results"] is True
    assert "truncated" not in out


def test_stops_when_page_brings_no_new_topics(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({
        1: page_payload([(1, 4), (2, 4)]),
        2: page_payload([(1, 4), (2, 4)]),  # 全是重复话题
        3: page_payload([(9, 4)]),
    }, calls))

    out = S._search("lebara", 1, 3)

    assert out["count"] == 2
    assert len(calls) == 2, calls
    assert out["more_results"] is False


def test_stops_on_empty_page(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: page_payload([(1, 4)])}, calls))

    out = S._search("lebara", 1, 3)

    assert out["count"] == 1
    assert len(calls) == 2
    assert out["more_results"] is False


def test_more_results_respects_explicit_false(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: page_payload([(1, 4)], more=False)}, calls))

    out = S._search("lebara", 1, 1)

    assert out["more_results"] is False


def test_more_results_true_when_page_limit_reached(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: page_payload([(1, 4)])}, calls))

    out = S._search("lebara", 1, 1)

    assert out["more_results"] is True


def test_category_falls_back_to_site_index(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: page_payload([(1, 4), (2, 5)])}, calls))

    out = S._search("lebara", 1, 1)

    assert [r["category"] for r in out["results"]] == ["开发调优", "搞七捻三"]


def test_category_prefers_response_categories(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({
        1: page_payload([(1, 4)], categories=[{"id": 4, "name": "响应里的名字"}]),
    }, calls))

    out = S._search("lebara", 1, 1)

    assert out["results"][0]["category"] == "响应里的名字"


def test_category_none_when_unknown(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: page_payload([(1, None), (2, 99)])}, calls))

    out = S._search("lebara", 1, 1)

    assert [r["category"] for r in out["results"]] == [None, None]


def test_rate_limited_second_page_keeps_first_page_results(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({
        1: page_payload([(1, 4), (2, 4)]),
        2: RuntimeError("被限流(429)：请降低频率，稍后重试。"),
    }, calls))

    out = S._search("lebara", 1, 3)

    assert out["count"] == 2
    assert len(calls) == 2
    assert out["truncated"] == "被限流(429)：请降低频率，稍后重试。"


def test_cloudflare_block_on_second_page_keeps_first_page_results(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({
        1: page_payload([(1, 4)]),
        2: RuntimeError("被 Cloudflare 拦截（已重试 3 次）。"),
    }, calls))

    out = S._search("lebara", 1, 2)

    assert out["count"] == 1
    assert "Cloudflare" in out["truncated"]


def test_first_page_error_propagates(monkeypatch):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: RuntimeError("被限流(429)")}, calls))

    with pytest.raises(RuntimeError, match="429"):
        S._search("lebara", 1, 3)


@pytest.mark.parametrize("page,pages,expected_paths", [
    (0, 0, ["/search.json?q=x&page=1"]),
    ("abc", "abc", ["/search.json?q=x&page=1"]),
    (2, -5, ["/search.json?q=x&page=2"]),
])
def test_page_and_pages_are_clamped(monkeypatch, page, pages, expected_paths):
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({1: page_payload([(1, 4)]), 2: page_payload([(5, 4)])}, calls))

    out = S._search("x", page, pages)

    assert calls == expected_paths
    assert out["count"] == 1


def test_delay_between_pages(monkeypatch):
    sleeps = []
    monkeypatch.setattr(S.time, "sleep", sleeps.append)
    calls = []
    monkeypatch.setattr(S, "_fetch", make_fetch({
        1: page_payload([(1, 4)]),
        2: page_payload([(2, 4)]),
        3: page_payload([(3, 4)]),
    }, calls))

    out = S._search("x", 1, 3)

    assert out["count"] == 3
    assert sleeps == [S.PAGE_DELAY, S.PAGE_DELAY]
