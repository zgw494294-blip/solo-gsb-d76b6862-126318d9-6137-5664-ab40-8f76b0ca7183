"""站内页面可达性（POST /v1/site-reachability）核心。

给定 Base64 WARC、首页 HTTP(S) URL 与 RFC3339 时点，离线计算从首页出发
沿页面链接能到达哪些站内 HTML 页面：

- WARC 解码、2 MiB 上限与 WARC/revisit 结构校验与 /v1/navigate 完全一致；
  每个 URL 取 ``WARC-Date`` 不晚于时点的最新抓取，同一时刻取归档中靠后者，
  重定向跟随（相对 Location、成环、8 跳上限等）同样沿用 /v1/navigate；
- 页面节点的判定：跟随重定向后的**终点 URL** 与首页终点**同源**，且终点
  记录自己的 HTTP 状态为 2xx、HTTP ``Content-Type`` 的媒体类型为
  ``text/html``（参数忽略、大小写不敏感）；正文使用 revisit 还原后的正文；
- 从每个页面解析 ``a[href]``：相对地址按**首个有效** ``<base href>``
  解析（规则与 /v1/page-assets 一致），去片段；跨源与非 HTTP(S) 链接忽略；
- 逐层广度优先遍历：每层先按查询时点解析本层全部出链及其重定向，再按
  同源、2xx、text/html 页面的**终点 URL** 去重并排序，然后按此顺序扩展
  下一层；同层等长路径取此顺序下先展开的父页面为前驱。已到达的终点 URL
  去重防环，每个节点取首次到达（即最短点击次数），重定向不计点击；
- 首页（根）无抓取 → 404；根重定向错误（缺 Location、目标非法、成环、超
  跳数）→ 422；根终点非 2xx → 422 ``status_not_2xx``，非 HTML → 422
  ``not_html``；子链接的任何失败（无抓取、重定向异常、非 2xx、非 HTML、
  跨源）一律跳过，不影响其余页面；
- 归档中该时点下其余可独立还原的同源 2xx HTML 页面（未被遍历到达）列入
  ``unreachable``，只给记录 ID。
"""

from __future__ import annotations

from datetime import datetime
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlsplit

from .navigate import (
    _build_index,
    _follow_redirects,
    _http_url,
    _parse_rfc3339,
)
from .page_assets import _resolve_http_url
from .replay import ReplayError, load_records

# Content-Type 参数分隔符；媒体类型取分号前一段
_MEDIA_TYPE_HTML = "text/html"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> Optional[tuple[str, str, int]]:
    """返回 URL 的规范化同源三元组 (scheme, host, port)；非 HTTP(S) 为 None。"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    port = parts.port if parts.port is not None else _DEFAULT_PORTS[scheme]
    return scheme, parts.hostname.lower(), port


def _media_type(content_type: Optional[str]) -> Optional[str]:
    """从 HTTP Content-Type 原值取媒体类型（去参数、小写）；无头为 None。"""
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def _is_html_2xx(rec) -> bool:
    """终点记录自己 2xx 且 Content-Type 媒体类型为 text/html。"""
    status = rec.http_status
    if status is None or not 200 <= status < 300:
        return False
    return _media_type(rec.http_content_type) == _MEDIA_TYPE_HTML


class _LinkHTMLParser(HTMLParser):
    """收集 ``<base href>`` 候选与 ``a[href]`` 原始字面值（暂不解析）。

    与 /v1/page-assets 的解析器同样：标签/属性名由 HTMLParser 统一小写，
    同一属性重复出现取首次值；``<base>`` 按文档顺序全保留，由调用方选首个
    有效者；自闭合标签经默认 ``handle_startendtag`` 无需单独处理。
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_hrefs: list[str] = []
        self.anchors: list[str] = []

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, Optional[str]]]) -> None:
        values: dict[str, Optional[str]] = {}
        for name, value in attrs:
            if name not in values:
                values[name] = value

        if tag == "base":
            href = values.get("href")
            if href:
                self.base_hrefs.append(href)
        elif tag == "a":
            href = values.get("href")
            if href and href.strip():
                self.anchors.append(href)


def _page_links(body: bytes, page_url: str,
                site_origin: tuple[str, str, int]) -> list[str]:
    """解析页面正文里的站内链接：去片段、只留与站点同源的 HTTP(S) 绝对 URL。

    相对地址按首个有效 ``<base href>``（相对本页 URL 解析）计算，无有效
    base 时用本页 URL；跨源、非 HTTP(S)（``mailto:``、``javascript:``、
    ``data:`` 等）忽略；结果按 URL 排序去重。
    """
    html = body.decode("utf-8", errors="replace")
    parser = _LinkHTMLParser()
    parser.feed(html)
    parser.close()

    base_url = page_url
    for raw_base in parser.base_hrefs:
        resolved_base = _resolve_http_url(raw_base, page_url)
        if resolved_base is not None:
            base_url = resolved_base
            break

    links: set[str] = set()
    for raw_href in parser.anchors:
        resolved = _resolve_http_url(raw_href, base_url)
        if resolved is None:
            continue
        if _origin(resolved) != site_origin:
            continue
        links.add(resolved)
    return sorted(links)


def _terminal(index, url: str, point_in_time: datetime, at: str
              ) -> Optional[tuple[list[dict], str, object]]:
    """跟随一个链接，返回 (重定向路径, 终点 URL, 终点记录)；失败返回 None。

    覆盖无抓取（404）与全部重定向异常（422）；调用方对失败链接直接跳过。
    """
    try:
        path, final_url, rec = _follow_redirects(index, url, point_in_time, at)
    except ReplayError:
        return None
    return path, final_url, rec


def site_reachability(warc_b64: str, start_url: str, at: str) -> dict:
    """site-reachability 入口：返回可达/不可达的站内 HTML 页面。"""
    url = _http_url(start_url)
    point_in_time = _parse_rfc3339(at)

    records = load_records(warc_b64, allow_missing_target_uri=True)
    index = _build_index(records)

    # 每个链接 URL 的跟随结果只算一次：缓存 _terminal 的完整结果
    # （含重定向路径），失败（无抓取/重定向异常）缓存为 None。
    resolutions: dict[
        str, Optional[tuple[list[dict], str, object]]
    ] = {}

    def resolve(link_url: str):
        if link_url not in resolutions:
            resolutions[link_url] = _terminal(
                index, link_url, point_in_time, at
            )
        return resolutions[link_url]

    # 根页面：选取与重定向跟随与 /v1/navigate 完全一致；capture_not_found
    # （404）与重定向异常（422）原样向上抛。
    root_path, root_final, root_rec = _follow_redirects(
        index, url, point_in_time, at
    )
    resolutions[url] = (root_path, root_final, root_rec)

    # 根终点必须 2xx 且 Content-Type 为 text/html，否则请求失败（422）。
    status = root_rec.http_status
    if status is None or not 200 <= status < 300:
        raise ReplayError(
            "status_not_2xx",
            f"首页终点 URL {root_final} 的终点记录 "
            f"{root_rec.record_id_raw} HTTP 状态为 {status}，不是 2xx",
            url=root_final,
            record_id=root_rec.record_id_raw,
            http_status=status,
        )
    if _media_type(root_rec.http_content_type) != _MEDIA_TYPE_HTML:
        raise ReplayError(
            "not_html",
            f"首页终点 URL {root_final} 的终点记录 "
            f"{root_rec.record_id_raw} Content-Type 为 "
            f"{root_rec.http_content_type!r}，媒体类型不是 text/html",
            url=root_final,
            record_id=root_rec.record_id_raw,
            content_type=root_rec.http_content_type,
        )

    site_origin = _origin(root_final)

    # 终点 URL -> 可达条目；根为 0 跳、无前驱。
    reached: dict[str, dict] = {
        root_final: {
            "record_id": root_rec.record_id_raw,
            "min_clicks": 0,
            "previous_url": None,
        }
    }

    # 逐层 BFS：每层先解析本层全部页面的出链（含重定向跟随），再按终点
    # URL 去重、排序后统一扩展；点击数即层号（重定向不另计点击）。
    # 层内元素：(页面终点 URL, 终点记录)，按终点 URL 升序。
    current_layer = [(root_final, root_rec)]
    clicks = 0
    while current_layer:
        # 候选：终点 URL -> (前驱页面终点 URL, 终点记录)。按本层扩展顺序
        # 收集，同一终点被同层多个父页面链接时，先展开的父页面胜出。
        candidates: dict[str, tuple[str, object]] = {}
        for parent_url, parent_rec in current_layer:
            for link in _page_links(parent_rec.body, parent_url, site_origin):
                outcome = resolve(link)
                if outcome is None:
                    continue  # 子链接无抓取或重定向异常：跳过
                _path, final_url, rec = outcome
                # 终点跨源 / 非 2xx / 非 HTML 都不是页面节点，跳过。
                if _origin(final_url) != site_origin \
                        or not _is_html_2xx(rec):
                    continue
                if final_url in reached or final_url in candidates:
                    continue
                candidates[final_url] = (parent_url, rec)
        clicks += 1
        next_layer: list[tuple[str, object]] = []
        for final_url in sorted(candidates):
            parent_url, rec = candidates[final_url]
            reached[final_url] = {
                "record_id": rec.record_id_raw,
                "min_clicks": clicks,
                "previous_url": parent_url,
            }
            next_layer.append((final_url, rec))
        current_layer = next_layer

    # 枚举该时点下归档中其余可独立还原的同源 2xx HTML 页面：未在遍历中
    # 到达者即不可达。任何跟随失败、非同源或非 HTML 的 URL 均不计入。
    unreachable_ids: set[str] = set()
    for raw_url in index:
        outcome = resolve(raw_url)
        if outcome is None:
            continue
        _path, final_url, rec = outcome
        if final_url in reached:
            continue
        if _origin(final_url) != site_origin or not _is_html_2xx(rec):
            continue
        unreachable_ids.add(rec.record_id_raw)

    return {
        "reachable": list(reached.values()),
        "unreachable": [
            {"record_id": record_id}
            for record_id in sorted(unreachable_ids)
        ],
    }
