"""linux.do (Discourse) MCP 服务器。

通过 curl_cffi 模拟 Chrome TLS 指纹绕过 Cloudflare，用 _t cookie 认证。
认证：默认自动从本机浏览器读取 linux.do 的 _t cookie（见 cookies.py），
也可用环境变量 LINUXDO_COOKIE = "_t=你的token值" 显式指定。

暴露工具：whoami / search / get_topic。
"""
import html
import json
import os
import re
import time
import urllib.parse

from curl_cffi import requests as creq

try:  # mcp >= 2：FastMCP 更名为 MCPServer
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp < 2
    from mcp.server.fastmcp import FastMCP as _Server

from . import cookies

BASE = "https://linux.do"
IMPERSONATE = os.environ.get("LINUXDO_IMPERSONATE", "chrome")
# 连续翻页之间的间隔。linux.do 前面就是 Cloudflare，抓太快会直接吃 429。
PAGE_DELAY = 1.5

mcp = _Server("linuxdo")

# 远程（streamable-http + OAuth）服务器要复用同一批工具函数，这里登记一份。
_REMOTE_TOOLS = []


def _tool():
    """注册工具：既挂到本机 stdio 服务器，也记入远程服务器复用列表。"""

    def decorator(fn):
        mcp.tool()(fn)
        _REMOTE_TOOLS.append(fn)
        return fn

    return decorator


def create_remote_server(auth, token_verifier):
    """构造带 OAuth 令牌校验的远程 MCP 服务器，暴露与本机完全相同的工具集。

    远程模式只做只读检索，没有登录管理类工具，因此无需按工具名做远程裁剪。
    """
    server = _Server("linuxdo", auth=auth, token_verifier=token_verifier)
    for fn in _REMOTE_TOOLS:
        server.tool()(fn)
    return server


def _cookie_header():
    return cookies.get_cookie()


def _blocked(body):
    return "Just a moment" in body[:600] or "challenge-platform" in body[:2000]


def _fetch(path):
    url = path if path.startswith("http") else BASE + path
    headers = {"Accept": "application/json", "Cookie": _cookie_header()}
    last = ""
    for attempt in range(3):
        try:
            r = creq.get(url, headers=headers, impersonate=IMPERSONATE, timeout=30)
        except Exception as e:
            last = f"请求失败：{e}"
            time.sleep(0.8 * (attempt + 1))
            continue
        body = r.text
        if _blocked(body):
            last = "被 Cloudflare 拦截"
            time.sleep(0.8 * (attempt + 1))
            continue
        if r.status_code in (401, 403):
            cookies.clear_cache()  # 失效即清缓存，下次用 env 重新 bootstrap；不重读浏览器
            raise RuntimeError(
                f"认证失败({r.status_code})：cookie 已失效，"
                "请更新 LINUXDO_COOKIE（独立 _t）后重试。"
            )
        if r.status_code == 429:
            raise RuntimeError("被限流(429)：请降低频率，稍后重试。")
        if r.status_code != 200 or not body.lstrip().startswith(("{", "[")):
            raise RuntimeError(f"异常响应 HTTP {r.status_code}: {body[:200]}")
        cookies.absorb_rotation(r)  # 接收轮换后的新 _t，自续期
        return json.loads(body)
    raise RuntimeError(f"{last}（已重试 3 次）。可设 LINUXDO_IMPERSONATE=chrome131 换指纹。")


def _strip_html(s):
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


def _html_to_text(s):
    """把 Discourse 渲染后的 cooked HTML 转成可读文本：
    保留段落换行、把代码块转成 ``` 围栏、列表转 - 项、数学转 $..$/$$..$$、加粗转 **。"""
    if not s:
        return ""
    t = s

    def _code(m):
        lang = (m.group(1) or "").strip().lower()
        if lang in ("plaintext", "text", "auto", "nohighlight", "none"):
            lang = ""
        body = html.unescape(re.sub(r"<[^>]+>", "", m.group(2))).strip("\n")
        return f"\n\n```{lang}\n{body}\n```\n\n"

    # 代码块：<pre><code class="... lang-xxx ...">...</code></pre>
    t = re.sub(
        r'<pre><code(?:\s+class="[^"]*?lang-([\w+#.-]+)[^"]*")?[^>]*>(.*?)</code></pre>',
        _code, t, flags=re.S)
    # 行内代码
    t = re.sub(r"<code>(.*?)</code>",
               lambda m: "`" + html.unescape(re.sub(r"<[^>]+>", "", m.group(1))) + "`",
               t, flags=re.S)
    # 数学：块级 $$..$$、行内 $..$
    t = re.sub(r'<div class="math">(.*?)</div>',
               lambda m: "\n\n$$" + m.group(1).strip() + "$$\n\n", t, flags=re.S)
    t = re.sub(r'<span class="math">(.*?)</span>',
               lambda m: "$" + m.group(1).strip() + "$", t, flags=re.S)
    # 加粗
    t = re.sub(r"</?(?:strong|b)>", "**", t)
    # 列表
    t = re.sub(r"<li>", "\n- ", t)
    t = re.sub(r"</li>", "", t)
    t = re.sub(r"</?[uo]l>", "\n", t)
    # 段落 / 换行 / 标题 / 引用 / 块边界
    t = re.sub(r"<br\s*/?>", "\n", t)
    t = re.sub(r"</p>", "\n\n", t)
    t = re.sub(r"</h[1-6]>", "\n\n", t)
    t = re.sub(r"</blockquote>", "\n", t)
    t = re.sub(r"</div>", "\n", t)
    # 删除其余标签（如 <a>、<p>、<span> 等，保留其内部文本）
    t = re.sub(r"<[^>]+>", "", t)
    t = html.unescape(t)
    # 收敛空白
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _topic_url(slug, tid):
    return f"{BASE}/t/{slug or 'topic'}/{tid}"


def _as_topic_id(topic):
    """接受话题 id（int/数字串）或 linux.do 话题 URL，返回整数 id。
    URL 形如 https://linux.do/t/<slug>/<id>[/<楼层>]，取路径里 /t/ 后的数字段。"""
    if isinstance(topic, int):
        return topic
    t = str(topic).strip()
    if t.isdigit():
        return int(t)
    m = re.search(r"/t/(?:[^/]+/)?(\d+)", t)
    if m:
        return int(m.group(1))
    m = re.search(r"\d+", t)
    if m:
        return int(m.group(0))
    raise RuntimeError(f"无法从 {topic!r} 解析出话题 id（给数字 id 或话题 URL）。")


def _whoami():
    u = _fetch("/session/current.json").get("current_user") or {}
    if not u:
        raise RuntimeError("未登录（cookie 无效或为空）。")
    return {k: u.get(k) for k in ("username", "name", "trust_level", "admin", "moderator")}


def _category_name(category_id, cats=None):
    """解析分类名：优先用本次响应里的 categories（有的站点会回填），
    否则回退到 /site.json 的索引（linux.do 的 search.json 不回填 categories）。"""
    if category_id is None:
        return None
    if cats and cats.get(category_id):
        return cats[category_id]
    return (_category_index().get(category_id) or {}).get("name")


def _search(query, page, pages):
    """连续抓取 pages 页（从 page 开始）。

    续页判断不依赖 grouped_search_result.more_full_page_results——linux.do 只在
    部分页回填该字段，末页常常没有。改为按「本页是否带来新话题」判断：
    整页没有新话题即视为到底，停止继续抓。
    后续某一页被限流/被 Cloudflare 拦时，已抓到的结果照常返回，并带 truncated 说明。
    """
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        pages = max(1, int(pages))
    except (TypeError, ValueError):
        pages = 1

    seen, results, term, last = set(), [], None, None
    exhausted, truncated = False, None
    for i in range(pages):
        q = urllib.parse.quote(query)
        try:
            last = _fetch(f"/search.json?q={q}&page={page + i}")
        except RuntimeError as e:
            # 第 1 页失败就直接抛；后续页失败则保留已有结果
            if i == 0:
                raise
            truncated = str(e)
            break
        gsr = last.get("grouped_search_result") or {}
        term = term or gsr.get("term")
        topics = {t["id"]: t for t in last.get("topics", [])}
        cats = {c["id"]: c.get("name") for c in (last.get("categories") or []) if c.get("name")}
        added = 0
        for p in last.get("posts", []):
            tid = p.get("topic_id")
            if tid in seen:
                continue
            seen.add(tid)
            added += 1
            t = topics.get(tid, {})
            results.append({
                "topic_id": tid,
                "title": t.get("title"),
                "category": _category_name(t.get("category_id"), cats),
                "tags": [tag.get("name") for tag in (t.get("tags") or [])],
                "blurb": _strip_html(p.get("blurb")),
                "posts_count": t.get("posts_count"),
                "created_at": t.get("created_at"),
                "url": _topic_url(t.get("slug"), tid),
            })
        if not last.get("posts") or added == 0:
            exhausted = True
            break
        if i + 1 < pages:
            time.sleep(PAGE_DELAY)

    more = bool(last and last.get("posts")) and not exhausted
    if more:
        explicit = (last.get("grouped_search_result") or {}).get("more_full_page_results")
        if explicit is False:
            more = False
    out = {"term": term, "count": len(results), "more_results": more, "results": results}
    if truncated:
        out["truncated"] = truncated
    return out


def _topic(topic_id, posts, start):
    topic_id = _as_topic_id(topic_id)
    j = _fetch(f"/t/{topic_id}.json")
    stream = (j.get("post_stream") or {}).get("stream", [])
    have = {p["id"]: p for p in (j.get("post_stream") or {}).get("posts", [])}
    # 从第 start 楼(1-based)起取 posts 个楼层；Discourse 首批只回前 ~20 楼，
    # 其余按 stream 里的 id 分批补抓（每批 20 个）。
    want_ids = stream[max(start - 1, 0):max(start - 1, 0) + posts]
    missing = [pid for pid in want_ids if pid not in have]
    for i in range(0, len(missing), 20):
        chunk = missing[i:i + 20]
        qs = "&".join(f"post_ids[]={pid}" for pid in chunk)
        extra = _fetch(f"/t/{topic_id}/posts.json?{qs}")
        for p in (extra.get("post_stream") or {}).get("posts", []):
            have[p["id"]] = p
        if i + 20 < len(missing):
            time.sleep(0.4)
    ordered = [have[pid] for pid in want_ids if pid in have]
    return {
        "id": j.get("id"),
        "title": j.get("title"),
        "category_id": j.get("category_id"),
        "tags": [t.get("name") if isinstance(t, dict) else t for t in (j.get("tags") or [])],
        "posts_count": j.get("posts_count"),
        "total_posts": len(stream),
        "start": start,
        "returned": len(ordered),
        "views": j.get("views"),
        "like_count": j.get("like_count"),
        "url": _topic_url(j.get("slug"), j.get("id")),
        "posts": [{
            "floor": p.get("post_number"),
            "username": p.get("username"),
            "created_at": p.get("created_at"),
            "content": _html_to_text(p.get("cooked")),
        } for p in ordered],
    }


def _categories():
    cats = (_fetch("/categories.json").get("category_list") or {}).get("categories", [])
    return [{
        "id": c.get("id"),
        "slug": c.get("slug"),
        "name": c.get("name"),
        "topic_count": c.get("topic_count"),
        "post_count": c.get("post_count"),
        "minimum_required_trust_level": c.get("minimum_required_trust_level"),
        "description": _strip_html(c.get("description_text") or c.get("description")),
    } for c in cats]


def _category_topics(category_id, page):
    cat = next((c for c in _categories() if c["id"] == category_id), None)
    if not cat:
        raise RuntimeError(f"找不到类别 id={category_id}，请先用 list_categories 查看可用类别。")
    idx = _category_index()
    tl = _fetch(f"/c/{cat['slug']}/{category_id}.json?page={page}").get("topic_list") or {}
    topics = tl.get("topics", [])
    return {
        "category": cat["name"],
        "category_id": category_id,
        "topic_count": cat["topic_count"],
        "page": page,
        "returned": len(topics),
        "more": bool(tl.get("more_topics_url")),
        "topics": [_topic_brief(t, idx) for t in topics],
    }


_SITE_CACHE = {"ts": 0.0, "cats": {}}
_LV_RE = re.compile(r"^(.*?)[,，]\s*Lv\s*([0-3])\s*$", re.I)


def _split_level(name):
    """从分类名解析等级：'开发调优, Lv1' -> ('开发调优', 1)；无后缀则 (name, None)。
    linux.do 不暴露 minimum_required_trust_level，等级信息写在子板名的 ', LvN' 后缀里。"""
    m = _LV_RE.match(name or "")
    if m:
        return m.group(1).strip(), int(m.group(2))
    return (name or "").strip() or None, None


def _category_index():
    """{category_id: {"name"(去掉 LvN 后缀), "trust_level"(int 或 None)}}，含子分类；
    缓存 5 分钟。取自 /site.json（覆盖父板+子板）；失败时退回旧缓存，不阻断列表请求。"""
    now = time.time()
    if _SITE_CACHE["cats"] and now - _SITE_CACHE["ts"] < 300:
        return _SITE_CACHE["cats"]
    try:
        cats = _fetch("/site.json").get("categories", [])
    except Exception:
        return _SITE_CACHE["cats"]
    idx = {}
    for c in cats:
        base, lv = _split_level(c.get("name"))
        if lv is None:
            lv = c.get("minimum_required_trust_level")
        idx[c.get("id")] = {"name": base, "trust_level": lv}
    _SITE_CACHE.update(ts=now, cats=idx)
    return idx


def _topic_brief(t, idx=None):
    idx = idx if idx is not None else {}
    cid = t.get("category_id")
    cat = idx.get(cid) or {}
    return {
        "id": t.get("id"),
        "title": t.get("title"),
        "category_id": cid,
        "category": cat.get("name"),
        "min_trust_level": cat.get("trust_level"),
        "posts_count": t.get("posts_count"),
        "views": t.get("views"),
        "like_count": t.get("like_count"),
        "created_at": t.get("created_at"),
        "url": _topic_url(t.get("slug"), t.get("id")),
    }


def _topics_page(path, extra):
    idx = _category_index()
    tl = _fetch(path).get("topic_list") or {}
    topics = tl.get("topics", [])
    return {**extra, "returned": len(topics),
            "more": bool(tl.get("more_topics_url")),
            "topics": [_topic_brief(t, idx) for t in topics]}


def _tags():
    tags = _fetch("/tags.json").get("tags", [])
    return [{"name": t.get("name"), "count": t.get("count"),
             "description": t.get("description")} for t in tags]


def _tag_topics(tag, page):
    return _topics_page(f"/tag/{urllib.parse.quote(tag)}.json?page={page}",
                        {"tag": tag, "page": page})


def _user_info(username):
    uq = urllib.parse.quote(username)
    u = _fetch(f"/u/{uq}.json").get("user") or {}
    if not u:
        raise RuntimeError(f"找不到用户 {username}。")
    info = {k: u.get(k) for k in
            ("username", "name", "trust_level", "title", "created_at", "last_seen_at", "badge_count")}
    summary = _fetch(f"/u/{uq}/summary.json").get("user_summary") or {}
    info.update({k: summary.get(k) for k in
                 ("topic_count", "post_count", "likes_given", "likes_received",
                  "days_visited", "solved_count")})
    return info


TOP_PERIODS = ("daily", "weekly", "monthly", "quarterly", "yearly", "all")


def _top(period, page):
    if period not in TOP_PERIODS:
        raise RuntimeError(f"period 须为 {list(TOP_PERIODS)} 之一。")
    return _topics_page(f"/top.json?period={period}&page={page}",
                        {"period": period, "page": page})


def _user_actions(username, limit):
    u = urllib.parse.quote(username)
    acts = _fetch(f"/user_actions.json?offset=0&username={u}&filter=4,5").get("user_actions", [])[:limit]
    return {"username": username, "count": len(acts), "actions": [{
        "action_type": a.get("action_type"),
        "created_at": a.get("created_at"),
        "topic_id": a.get("topic_id"),
        "post_number": a.get("post_number"),
        "excerpt": _strip_html(a.get("excerpt")),
        "url": (f"{BASE}/t/{a.get('slug')}/{a.get('topic_id')}/{a.get('post_number')}"
                if a.get("slug") else None),
    } for a in acts]}


def _format_search(query, page, pages):
    d = _search(query, page, pages)
    more = "（还有更多结果）" if d["more_results"] else ""
    lines = [f'搜索「{d["term"]}」命中 {d["count"]} 条{more}：', ""]
    for r in d["results"]:
        tags = " ".join(f"#{t}" for t in (r["tags"] or []))
        lines.append(f'- **{r["title"]}** {tags}'.rstrip())
        lines.append(f'  📍 {r["url"]}')
        if r["blurb"]:
            lines.append(f'  {r["blurb"]}')
    return "\n".join(lines)


def _format_topic(topic_id, posts, start):
    d = _topic(topic_id, posts, start)
    end = d.get("start", 1) + d.get("returned", 0) - 1
    out = [
        f'> **{d["title"]}**',
        f'> 📍 {d["url"]} ｜ {d.get("views", 0)}浏览 · {d.get("like_count", 0)}赞 · '
        f'{d.get("posts_count", 0)}回复（共 {d.get("total_posts", 0)} 楼，'
        f'本次 {d.get("start", 1)}–{end}）',
    ]
    for p in d["posts"]:
        who = f'@{p["username"]}（楼主）' if p["floor"] == 1 else f'@{p["username"]}'
        out += ["", f'## #{p["floor"]} · {who}', "", p["content"], "", "---"]
    if out and out[-1] == "---":
        out.pop()
    return "\n".join(out).rstrip()


@_tool()
def whoami() -> dict:
    """查看当前 cookie 对应的 linux.do 登录用户与信任等级。"""
    return _whoami()


@_tool()
def search(query: str, page: int = 1, pages: int = 1) -> dict:
    """全量搜索 linux.do。query 支持 Discourse 高级语法（order:latest、#分类、@用户、
    tags:标签、after:2025-01-01、in:title 等）。pages 为连续抓取的页数（每页约 50 条），
    按「本页是否带来新话题」判断是否到底；后续页被限流时已抓到的结果照常返回并带
    truncated 字段。展示约定：Markdown 表格或列表，标题完整勿截断，纯文字勿用 emoji（易乱码）。"""
    return _search(query, page, pages)


@_tool()
def get_topic(topic_id: int | str, posts: int = 20, start: int = 1) -> dict:
    """读取指定话题的详情与楼层正文。topic_id 可传数字 id，也可直接传 linux.do 话题
    URL（如 https://linux.do/t/xxx/2885565/1，会自动取出 id）。posts=返回楼层数，
    start=起始楼层(1-based，用于翻页，如 start=21 取第 21 楼起)。返回含 total_posts(总楼数)。"""
    return _topic(topic_id, posts, start)


@_tool()
def format_search(query: str, page: int = 1, pages: int = 1) -> str:
    """同 search，但直接返回拼好的 Markdown（标题+URL+摘要列表），客户端可原样展示。"""
    return _format_search(query, page, pages)


@_tool()
def format_topic(topic_id: int | str, posts: int = 20, start: int = 1) -> str:
    """同 get_topic，但直接返回拼好的 Markdown（出处头 + 逐楼表格），客户端可原样展示。
    topic_id 可传数字 id 或 linux.do 话题 URL（自动解析）。posts=楼层数，
    start=起始楼层(1-based，翻页用，如 start=21)。"""
    return _format_topic(topic_id, posts, start)


@_tool()
def list_categories() -> dict:
    """列出所有板块/类别，含每个类别的话题数(topic_count)与帖子数(post_count)。"""
    cats = _categories()
    return {"count": len(cats), "categories": cats}


@_tool()
def category_topics(category_id: int, page: int = 1) -> dict:
    """列出指定类别下的话题（每页约 30 条）。返回含该类别总话题数 topic_count、
    本页话题列表与是否有下一页。category_id 用 list_categories 查询。每条话题已含
    category、min_trust_level。展示约定同 latest_topics（Markdown 表格、完整标题、
    纯文字表头禁用 emoji）。"""
    return _category_topics(category_id, page)


@_tool()
def list_tags() -> dict:
    """列出所有标签及各自的话题数(count)。"""
    tags = _tags()
    return {"count": len(tags), "tags": tags}


@_tool()
def tag_topics(tag: str, page: int = 1) -> dict:
    """列出指定标签下的话题（每页约 30 条）。tag 用标签名（如「人工智能」）。每条话题
    已含 category、min_trust_level。展示约定同 latest_topics（Markdown 表格、完整
    标题、纯文字表头禁用 emoji）。"""
    return _tag_topics(tag, page)


@_tool()
def user_info(username: str) -> dict:
    """查询用户资料：信任等级、注册/最后在线时间、发帖数、获赞数等。"""
    return _user_info(username)


@_tool()
def latest_topics(page: int = 1) -> dict:
    """获取首页「最新」话题列表（每页约 30 条）。每条已含 category(分类名)、
    min_trust_level(最低等级要求，null=无限制)，无需再逐条 get_topic 查分类。

    展示约定：用 Markdown 表格，列依次为 标题(完整勿截断) | 分类 | 等级 | 回复 |
    点赞 | 链接；表头与单元格一律纯文字，禁用 emoji（多字节 emoji 在生成时可能
    碎成「����」乱码）。等级按 min_trust_level 显示「Lv0/1/2/3」，null 显示「—」。"""
    return _topics_page(f"/latest.json?page={page}", {"page": page})


@_tool()
def top_topics(period: str = "weekly", page: int = 1) -> dict:
    """获取「热门」话题列表。period 取 daily/weekly/monthly/quarterly/yearly/all。
    每条已含 category、min_trust_level。展示约定同 latest_topics（Markdown 表格、
    完整标题、纯文字表头禁用 emoji）。"""
    return _top(period, page)


@_tool()
def user_actions(username: str, limit: int = 20) -> dict:
    """获取某用户的发帖/回复活动（含摘要与跳转链接）。"""
    return _user_actions(username, limit)


def main():
    transport = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    if transport == "stdio":
        mcp.run()
        return
    if transport != "streamable-http":
        raise SystemExit("MCP_TRANSPORT must be either stdio or streamable-http")

    import uvicorn
    from mcp.server.auth.settings import AuthSettings

    from .oauth import (
        OAuthStore,
        SingleUserOAuthProvider,
        StoreTokenVerifier,
        build_remote_app,
    )
    from .oauth_config import load_oauth_config

    oauth_config = load_oauth_config()
    oauth_store = OAuthStore(oauth_config.database_path)
    oauth_provider = SingleUserOAuthProvider(oauth_config, oauth_store)
    token_verifier = StoreTokenVerifier(oauth_provider)
    auth = AuthSettings(
        issuer_url=oauth_config.issuer_url,
        resource_server_url=oauth_config.public_url,
        required_scopes=list(oauth_config.scopes),
        # audience（resource）校验由 StoreTokenVerifier / provider 自己做，
        # 这里显式关掉 MCP SDK 的重复校验，避免 3.0 默认开启后行为变化。
        validate_token_resource=False,
    )
    remote_mcp = create_remote_server(auth, token_verifier)
    app = build_remote_app(oauth_config, remote_mcp, oauth_provider, auth)
    uvicorn.run(
        app,
        host=oauth_config.bind_host,
        port=oauth_config.bind_port,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


if __name__ == "__main__":
    main()
