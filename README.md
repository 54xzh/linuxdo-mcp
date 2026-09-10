
# linuxdo-mcp

#### 本帖使用社区公益推广，符合推广要求。我申明并遵循社区要求的以下内容：
* **我的项目是免费使用的，无收费（变相收费、赞助）部分：** 是 
* **我的帖子已经打上 #公益推广 标签：** 是 
* **我的项目属于个人项目，与公司或商业机构无关：** 是 
* **我的项目不存在QQ、TG等群组引流：** 是 
* **我的项目不存在非运营必要的网站引流：** 是 
* **我的项目不存在为他人推广、AFF：** 是 
* **我的项目无关联的商业项目：** 是 
* **我的站点存在登录，并已接入 LINUX DO Connect：** 否
* **我帖子内的项目介绍，AI生成、润色内容部分已截图发出：** 是 
* **以上选择我承诺是永久有效的，接受社区和佬友监督：** 是 

  
搜索 / 阅读 [linux.do](https://linux.do)(Discourse 论坛)的 MCP 服务器。
用 [curl_cffi](https://github.com/lexiforest/curl_cffi) 模拟 Chrome TLS 指纹绕过 Cloudflare,
凭登录 cookie 访问受信任等级限制的内容。

## 工具

| 工具 | 返回 | 说明 |
|------|------|------|
| `whoami()` | JSON | 当前 cookie 对应的登录用户与信任等级 |
| `search(query, page=1, pages=1)` | JSON | 全量搜索,`query` 支持 Discourse 高级语法 |
| `get_topic(topic_id, posts=5)` | JSON | 话题详情 + 前 N 楼正文 |
| `list_categories()` | JSON | 所有板块,含各自话题数 `topic_count`、帖子数 `post_count` |
| `category_topics(category_id, page=1)` | JSON | 指定类别下的话题列表(每页约 30),含该类别总话题数 |
| `list_tags()` | JSON | 所有标签及各自话题数 `count` |
| `tag_topics(tag, page=1)` | JSON | 指定标签下的话题列表 |
| `user_info(username)` | JSON | 用户资料:信任等级、头衔、发帖数、获赞数、注册/在线时间 |
| `latest_topics(page=1)` | JSON | 首页「最新」话题 |
| `top_topics(period="weekly", page=1)` | JSON | 「热门」话题,period: daily/weekly/monthly/quarterly/yearly/all |
| `user_actions(username, limit=20)` | JSON | 某用户的发帖/回复活动(含摘要与链接) |
| `format_search(query, page=1, pages=1)` | Markdown | 同 search,直接返回成品 Markdown(标题+URL+摘要) |
| `format_topic(topic_id, posts=20)` | Markdown | 同 get_topic,直接返回成品 Markdown(出处头+逐楼表格) |

- `format_*` 工具返回拼好的 Markdown 字符串,客户端可原样展示;其余返回结构化 JSON。
- `get_topic` / `format_topic` 的 `topic_id` 可直接传话题 URL（如 `https://linux.do/t/xxx/2885565`），自动解析出 id。
- 搜索高级语法:`order:latest`、`#分类`、`@用户`、`tags:标签`、`after:2025-01-01`、`in:title` 等。

## 前置

- 安装 [uv](https://docs.astral.sh/uv/)(提供 `uvx`)。
- 准备一个 linux.do 的登录 cookie(`_t`),给法见下方「登录配置」。只需 `_t`,**不需要** `cf_clearance`。

## 配置(复制到你的 MCP 客户端)

`uvx` 会自动拉取并运行,无需下载代码。基础配置:

```json
{
  "mcpServers": {
    "linuxdo": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mrsxs/linuxdo-mcp", "linuxdo-mcp"]
    }
  }
}
```

再按下面「登录配置」二选一填 `env`。

- **Claude Code**:`claude mcp add-json linuxdo '<上面的内容>'`,或写进 `.mcp.json` / 设置。
- **Cursor / Claude Desktop / Cline**:粘进各自的 MCP 配置文件即可。

## 登录配置(两种方式,二选一)

> 为什么不直接读你平时用的浏览器?因为工具和主浏览器**共用同一个 `_t`** 时,
> Discourse 的 token 轮换会判定异常、把会话作废,导致**主浏览器被顶下线**。
> 所以默认 `LINUXDO_READ_BROWSER=0`(不读浏览器),请用下面任一「独立身份」。

### 方式一:独立 token(任何平台通用,最省心)

在**隐身窗口**或另一个浏览器登录 linux.do,F12 → Application → Cookies → `https://linux.do`
→ 复制 `_t` 的值,填进 `env`:

```json
"env": { "LINUXDO_COOKIE": "_t=你复制的值" }
```

只需填一次:工具之后自动接收 Discourse 轮换、写回缓存**自续期**,长期免维护,且与主浏览器互不影响。

### 方式二:专用 Chrome profile 自动读(macOS/Linux,免手工复制)

在 Chrome 右上角头像 →「添加」新建一个 profile(例:显示名 `linuxdo`),在其中登录 linux.do,然后:

```json
"env": {
  "LINUXDO_READ_BROWSER": "1",
  "LINUXDO_CHROME_PROFILE": "linuxdo"
}
```

`LINUXDO_CHROME_PROFILE` 可填**显示名**(Chrome 菜单里看到的,如 `linuxdo`)或**目录名**(如 `Profile 1`);
填错会列出所有可用 profile 供对照。工具首次自动读该 profile 做 bootstrap,之后同样走缓存自续期。
你日常用的主 profile(`Default`)完全不受影响——只要不在这个专用 profile 里刷 linux.do 就永不冲突。

## cookie 获取顺序与续期

1. 缓存文件 `~/.cache/linuxdo-mcp/cookie.json`(权限 600,工具自维护、含轮换续期,最新);
2. 环境变量 `LINUXDO_COOKIE`(方式一,首次 bootstrap 后写入缓存);
3. 浏览器 cookie 库(方式二,仅当 `LINUXDO_READ_BROWSER=1`)。

`_t` 是 Discourse 的滚动 token,工具每次请求都会接收服务器轮换回来的新值写回缓存,
所以配一次通常长期有效;遇 401/403 会清缓存并提示更新。

方式二各平台授权差异:

| 平台 | Chrome/Chromium/Brave | Firefox |
|---|---|---|
| macOS | 首次弹一次钥匙串授权框,选「始终允许」;uv 缓存重建致解释器路径变化时会再弹一次 | 免授权 |
| Linux | 一般免授权(cookie 若在已上锁的 gnome-keyring/kwallet 则需解锁) | 免授权 |
| Windows | **不支持**(pycookiecheat 只支持 macOS/Linux),请用方式一或 `LINUXDO_BROWSER=firefox` | 免授权 |

## 环境变量一览

| 变量 | 说明 |
|---|---|
| `LINUXDO_COOKIE` | 方式一:手工指定 cookie,形如 `_t=xxx`(裸 token 也可) |
| `LINUXDO_READ_BROWSER` | 方式二:置 `1` 才允许读浏览器(默认 `0`,防止与主浏览器互顶) |
| `LINUXDO_CHROME_PROFILE` | 方式二:Chrome 系 profile 的显示名或目录名(如 `linuxdo` / `Profile 1`) |
| `LINUXDO_BROWSER` | `chrome`(默认)/`chromium`/`brave`/`slack`/`firefox` |
| `LINUXDO_COOKIE_TTL` | 缓存有效期秒数,默认 `2592000`(30 天,配合自续期) |
| `LINUXDO_CACHE_DIR` | 缓存目录,默认 `~/.cache/linuxdo-mcp` |
| `LINUXDO_IMPERSONATE` | TLS 指纹,默认 `chrome` |

> ⚠️ `_t` 等于你的 linux.do 登录凭证,只填进自己的本地配置,**切勿分享给他人**。


## 本地运行(开发)

```bash
uvx --from . linuxdo-mcp        # 或 uv run src/linuxdo_mcp/server.py
```

## 备注

- cookie 过期返回 401/403 时会清缓存并提示更新;按你选的方式重配一次即可(方式二一般不会到期,浏览器保持登录时会自动续期)。
- 读取浏览器 cookie 依赖 [pycookiecheat](https://github.com/n8henrie/pycookiecheat),只读取 linux.do 一个域名下的 cookie。
- 偶发被 Cloudflare 拦截时会自动重试 3 次;仍失败可设 `LINUXDO_IMPERSONATE=chrome131`(或 `chrome124`)换指纹。
- 所有请求为只读 GET,不做任何写操作。

## 远程模式：Streamable HTTP + OAuth(供 ChatGPT 连接)

本机 stdio 模式完全不变。远程模式额外提供一个带 OAuth 2.1 鉴权的 Streamable HTTP
入口,实现写法与 [`54xzh/miot-mcp`](https://github.com/54xzh/miot-mcp) 的远程模式一致:
单用户、ChatGPT CIMD(client_id 元数据文档)+ PKCE `S256`,密码在同意页手工输入。

### 1. 生成管理员密码摘要

```bash
uv run python -m linuxdo_mcp.oauth.cli     # 安装后也可用 linuxdo-mcp-oauth-password
```

只输出 `scrypt$...` 摘要,不保存明文。密码至少 12 位。

### 2. 配置并启动

```bash
export MCP_TRANSPORT="streamable-http"
export MCP_PUBLIC_URL="https://<你的域名>/mcp"
export MCP_OAUTH_PASSWORD_HASH='scrypt$...'
export MCP_HTTP_HOST="127.0.0.1"
export MCP_HTTP_PORT="8011"

uv run python -m linuxdo_mcp.server
```

- `MCP_PUBLIC_URL` 必须是 HTTPS 绝对地址且带 `/mcp` 路径(回环测试允许 `http://127.0.0.1:端口/mcp`)。
- `MCP_HTTP_HOST` 只接受回环地址,公网入口交给 Cloudflare Tunnel。
- 登录 cookie 仍需 `LINUXDO_COOKIE`(或缓存),远程模式只是把它包在 OAuth 后面。

### 3. Cloudflare Tunnel

只把域名转发到回环端口,**不要**给这个域名启用 Cloudflare Access,否则会挡住
ChatGPT 的 OAuth 自动发现。

```yaml
ingress:
  - hostname: <你的域名>
    service: http://127.0.0.1:8011
  - service: http_status:404
```

### 4. ChatGPT 接入

新建连接 → 服务器 URL 填 `https://<你的域名>/mcp` → 身份验证选 OAuth →
在跳出的同意页输入用户名 `admin` 和第 1 步设置的密码。

### 远程模式的安全边界

- 工具集与本机完全一致(13 个只读工具),没有登录管理类入口。
- `/token` 必须带与 `MCP_PUBLIC_URL` 完全一致的 `resource` 参数,否则 `invalid_target`。
- 授权页带 CSRF 令牌,同一来源 15 分钟内 10 次失败即拒绝。
- 刷新令牌轮换,重放旧的 refresh token 会作废整条 token family。
- `/revoke` 支持公共客户端(token + client_id,不需要 client_secret)。
- 授权/令牌/撤销端点按 Cloudflare 来源 IP 限流(60 秒 12 次),请求体上限 64 KiB。
- OAuth 数据默认落在 `~/.linuxdo-mcp/oauth.db`,只保存客户端信息与各类令牌摘要。

### 新增环境变量

| 变量 | 说明 |
|---|---|
| `MCP_TRANSPORT` | `stdio`(默认)/ `streamable-http` |
| `MCP_PUBLIC_URL` | 远程模式必填,形如 `https://域名/mcp` |
| `MCP_OAUTH_PASSWORD_HASH` | 远程模式必填,`linuxdo-mcp-oauth-password` 生成的摘要 |
| `MCP_OAUTH_ISSUER_URL` | 可选,默认取 `MCP_PUBLIC_URL` 的 origin |
| `MCP_HTTP_HOST` / `MCP_HTTP_PORT` | 默认 `127.0.0.1` / `8000`,仅接受回环地址 |
| `MCP_CONFIG_DIR` | 默认 `~/.linuxdo-mcp` |
| `MCP_OAUTH_DATABASE` | 默认 `<MCP_CONFIG_DIR>/oauth.db` |
| `MCP_OAUTH_ADMIN_USERNAME` | 同意页用户名,默认 `admin` |
| `LINUXDO_PROXY` | 可选,备用出口(如 `socks5h://127.0.0.1:25344`),见下节 |

## 出口与 Cloudflare 限流

linux.do 在 Cloudflare 后面,短时间密集请求就会吃到 `429 / Just a moment...`。实测要点:

- 限流与挑战是**按来源 IP 分桶**的。换出口能立刻拿到一个新额度。
- 挑战页需要执行 JS 才能通过,curl_cffi 做不到——被挑战时只能等该 IP 的惩罚窗口衰减,
  期间继续重试会把窗口续上,所以"停手几分钟"才会恢复。
- 设了 `LINUXDO_PROXY` 后:`_fetch` 先走直连,一旦遇到 429 或挑战页就自动切到备用出口,
  并在 `PROXY_COOLDOWN`(180s)内都走它;冷却结束自动回切直连尝试。
- 备用出口自己也被拦时直接报错,不会在两条出口之间来回横跳。

备用出口实测对比(同一台机器):

| 出口 | 表现 |
|---|---|
| 直连(云主机专用 IP) | 连续 4~7 个请求后开始 429,几分钟后恢复 |
| WARP 共享出口 | 一上来就频繁被挑战,额度极小 |

所以 WARP 只适合当**应急容量**,不能当主出口;真正管用的是把请求间隔留够
(`PAGE_DELAY`,连续翻页之间 1.5s)。

### 用 WARP 做备用出口(用户态,不动系统路由)

不需要 root,不建 tun,不影响机器上其它服务:

```bash
mkdir -p ~/warp && cd ~/warp
curl -sL -o wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.32/wgcf_2.2.32_linux_arm64
curl -sL -o wireproxy.tar.gz https://github.com/windtf/wireproxy/releases/download/v1.1.3/wireproxy_linux_arm64.tar.gz
tar xzf wireproxy.tar.gz && chmod +x wgcf wireproxy
./wgcf register --accept-tos     # 数据中心 IP 可能瞬时 429,重试即可
./wgcf generate                  # 生成 wgcf-profile.conf
```

把 `wgcf-profile.conf` 里的 PrivateKey / Address(v4) / PublicKey / Endpoint 填进
`wireproxy.conf`:

```ini
[Interface]
PrivateKey = ...
Address = 172.16.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = ...
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0

[Socks5]
BindAddress = 127.0.0.1:25344
```

起服务(`~/.config/systemd/user/wireproxy.service`,`systemctl --user enable --now wireproxy`),
再把 `LINUXDO_PROXY=socks5h://127.0.0.1:25344` 写进 MCP 服务的环境文件。
注意:同一个 `_t` 在两条出口之间切换不会导致会话失效(已实测 whoami 交替可用),
但仍应把备用出口当低频应急通道,不要用它跑批量抓取。

### 发现端点与测试

```bash
curl -s https://<你的域名>/.well-known/oauth-authorization-server
curl -s https://<你的域名>/.well-known/oauth-protected-resource/mcp
```

```bash
uv run pytest tests -q     # 22 项:发现文档、授权码+PKCE、刷新轮换、CIMD、限流等
```

