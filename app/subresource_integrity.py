"""页面子资源完整性核验（POST /v1/subresource-integrity）核心。

给定 Base64 WARC、起始 HTTP(S) URL 与 RFC3339 时点，先以与 /v1/navigate
完全相同的时点选取与重定向跟随还原最终页面，再逐项核对页面 HTML 中
``script[src]`` 与样式表 ``link[href]`` 标签的 ``integrity`` 属性
（Subresource Integrity）：

- 只处理**带 integrity 属性**的 ``script[src]`` 与 ``rel=stylesheet``
  的 ``link[href]``（标签与属性名大小写不敏感；``rel`` 按空白分词后
  包含 ``stylesheet`` 即算，规则与 /v1/page-assets 一致）；不带
  integrity 的标签不参与核验；
- 相对地址按**首个有效** ``<base href>`` 解析（规则与 /v1/page-assets
  一致；没有有效 base 时用最终页 URL）；解析结果去片段后必须是
  HTTP(S) 绝对地址，否则该标签跳过（``data:``、``javascript:`` 等
  不计入结果）；
- 带 integrity 的标签**按 DOM 顺序逐项处理，不按 URL 去重**——同一
  URL 出现多次即产生多个条目，各自独立核验；
- 每个资源独立按同一时点选取抓取并跟随重定向（与 navigate 同一套规则，
  含 8 跳上限与成环检测）；无抓取、重定向异常、终点非 2xx 都只在对应
  条目上标明原因（``result`` 字段），不中断其余条目；
- 到达 2xx 终点后核验 integrity：属性值按空白拆分为若干 token，仅
  ``sha256``/``sha384``/``sha512``（算法名大小写不敏感）加标准 Base64
  摘要（允许缺省填充，解码长度须等于算法摘要长度）算**合法摘要**，
  其余 token（未知算法、Base64 非法、长度不符）一律忽略；没有任何
  合法摘要记 ``invalid_integrity``；
- 有合法摘要时**只比较其中最强的算法**（sha512 > sha384 > sha256）：
  对终点记录的还原正文（revisit 已还原为链终点 response 的正文）计算
  该算法摘要，任一合法摘要与之相同即 ``match``，全部不同即
  ``mismatch``；
- 抓取类失败原因优先于摘要核验：资源无法还原到 2xx 终点时不再读取
  integrity 内容；根页面的选取/重定向失败与归档错误则与 /v1/navigate
  一样使整个请求失败（404/422 原样透传）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime
from html.parser import HTMLParser
from typing import Optional

from .navigate import (
    _build_index,
    _follow_redirects,
    _http_url,
    _parse_rfc3339,
)
from .page_assets import _resolve_http_url
from .replay import ReplayError, load_records

# 算法强度：只比较合法摘要中最强的一档（sha512 > sha384 > sha256）
_ALGO_STRENGTH = {"sha256": 0, "sha384": 1, "sha512": 2}
# 各算法摘要的字节长度：合法摘要解码后必须恰好这么长
_ALGO_DIGEST_SIZE = {"sha256": 32, "sha384": 48, "sha512": 64}
# integrity token 形如 "<算法>-<Base64>"；算法名大小写不敏感
_TOKEN_RE = re.compile(r"^(sha256|sha384|sha512)-(.+)$", re.IGNORECASE)
# 标准 Base64 字母表，填充符只允许出现在末尾（0～2 个）
_B64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _decode_digest(algo: str, value: str) -> Optional[bytes]:
    """把 token 的摘要部分解码为字节；不是合法 Base64 或长度不符返回 None。

    允许缺省填充（解码前补齐）；余数为 1 的长度不可能来自合法 Base64，
    直接判非法。
    """
    if not _B64_RE.fullmatch(value):
        return None
    body = value.rstrip("=")
    if len(body) % 4 == 1:
        return None
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != _ALGO_DIGEST_SIZE[algo]:
        return None
    return raw


def _parse_integrity(integrity: Optional[str]) -> list[tuple[str, bytes]]:
    """把 integrity 属性值解析为合法摘要列表 ``[(算法, 摘要字节)]``。

    按空白拆分；未知算法、Base64 非法或长度不符的 token 一律忽略。
    """
    digests: list[tuple[str, bytes]] = []
    for token in (integrity or "").split():
        match = _TOKEN_RE.match(token)
        if match is None:
            continue
        algo = match.group(1).lower()
        digest = _decode_digest(algo, match.group(2))
        if digest is not None:
            digests.append((algo, digest))
    return digests


def _verify(integrity: Optional[str], body: bytes) -> str:
    """对还原正文核验 integrity，返回 match / mismatch / invalid_integrity。

    只比较合法摘要中最强的算法：任一该算法合法摘要与正文摘要相同即通过。
    """
    digests = _parse_integrity(integrity)
    if not digests:
        return "invalid_integrity"
    algo = max(digests, key=lambda item: _ALGO_STRENGTH[item[0]])[0]
    actual = hashlib.new(algo, body).digest()
    if any(item_algo == algo and digest == actual
           for item_algo, digest in digests):
        return "match"
    return "mismatch"


class _IntegrityHTMLParser(HTMLParser):
    """收集 ``<base href>`` 候选与带 integrity 的资源标签（DOM 序）。

    与 /v1/page-assets 的解析器同样：标签/属性名由 HTMLParser 统一小写，
    同一属性重复出现取首次值；``<base>`` 按文档顺序全保留，由调用方选
    首个有效者；自闭合标签经默认 ``handle_startendtag`` 无需单独处理。
    只收录**带 integrity 属性**（哪怕值为空）且 src/href 非空的
    ``script`` 与 ``rel=stylesheet`` 的 ``link``。
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_hrefs: list[str] = []
        # (来源标签, 原始 URL 字面值, integrity 原始值)；按 DOM 顺序，不去重
        self.items: list[tuple[str, str, Optional[str]]] = []

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
        elif tag == "script":
            self._add(values, "script", "src")
        elif tag == "link":
            rel_tokens = (values.get("rel") or "").lower().split()
            if "stylesheet" in rel_tokens:
                self._add(values, "link", "href")

    def _add(self, values: dict[str, Optional[str]], tag: str,
             url_attr: str) -> None:
        if "integrity" not in values:
            return  # 不带 integrity 属性的标签不参与核验
        raw = values.get(url_attr)
        if raw and raw.strip():
            self.items.append((tag, raw, values.get("integrity")))


def _check_item(index, tag: str, url: str, integrity: Optional[str],
                point_in_time: datetime, at: str) -> dict:
    """核验单个标签：先还原资源到 2xx 终点，再比较 integrity 摘要。

    无抓取与重定向异常（navigate 的全部 404/422 错误码）只转化为条目
    上的原因标记；终点记录自己的 HTTP 状态非 2xx 记 ``status_not_2xx``
    （终点是 revisit 且自身无 HTTP 头时状态为 None，同样不算 2xx）。
    到达 2xx 终点后才解析 integrity 并比对还原正文。
    """
    try:
        _path, _final_url, rec = _follow_redirects(index, url, point_in_time,
                                                   at)
    except ReplayError as exc:
        return {"tag": tag, "url": url, "record_id": None,
                "result": exc.code}
    status = rec.http_status
    if status is None or not 200 <= status < 300:
        return {"tag": tag, "url": url, "record_id": rec.record_id_raw,
                "result": "status_not_2xx"}
    return {"tag": tag, "url": url, "record_id": rec.record_id_raw,
            "result": _verify(integrity, rec.body)}


def subresource_integrity(warc_b64: str, start_url: str, at: str) -> dict:
    """subresource-integrity 入口：返回带 integrity 标签的逐项核验结果。"""
    url = _http_url(start_url)
    point_in_time = _parse_rfc3339(at)

    records = load_records(warc_b64, allow_missing_target_uri=True)
    index = _build_index(records)

    # 根页面：与 /v1/navigate 完全相同的选取与重定向跟随；这里的
    # ReplayError（含 404 capture_not_found 与重定向异常）原样向上抛，
    # 响应与原接口一致。
    _path, final_url, page_rec = _follow_redirects(index, url, point_in_time,
                                                   at)

    # 正文按 UTF-8 容错解码；HTML 解析本身对畸形输入宽容，找不到标签即空
    html = page_rec.body.decode("utf-8", errors="replace")
    parser = _IntegrityHTMLParser()
    parser.feed(html)
    parser.close()

    # 首个有效 <base href>；没有有效 base 时用最终页 URL
    base_url = final_url
    for raw_base in parser.base_hrefs:
        resolved_base = _resolve_http_url(raw_base, final_url)
        if resolved_base is not None:
            base_url = resolved_base
            break

    # 按 DOM 序逐项核验，不按 URL 去重；非 HTTP(S) 地址的标签跳过
    items: list[dict] = []
    matched = 0
    for tag, raw_url, integrity in parser.items:
        asset_url = _resolve_http_url(raw_url, base_url)
        if asset_url is None:
            continue
        item = _check_item(index, tag, asset_url, integrity, point_in_time,
                           at)
        if item["result"] == "match":
            matched += 1
        items.append(item)

    return {
        "final_url": final_url,
        "total": len(items),
        "matched": matched,
        "items": items,
    }
