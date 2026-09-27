"""页面子资源完整性核验（POST /v1/subresource-integrity）核心。

给定 Base64 WARC、起始 HTTP(S) URL 与 RFC3339 时点，先以与 /v1/navigate
完全相同的时点选取与重定向跟随还原最终页面，再对其 HTML 中**带
integrity 属性**的 ``script[src]`` 与 ``rel=stylesheet`` 的
``link[href]`` 按 DOM 序逐项核验 Subresource Integrity：

- 标签与属性名大小写不敏感；``rel`` 按空白分词后包含 ``stylesheet``
  即算；只有带 ``integrity`` 属性的标签才参与核验（无 integrity 的
  script/link 不计入结果）；
- 相对地址按**首个有效** ``<base href>`` 解析（规则与 /v1/page-assets
  相同）；解析后去片段，只保留 HTTP(S) 绝对地址（``data:``、
  ``javascript:`` 等直接忽略）；**不按 URL 去重**——同一 URL 被多个
  标签引用时每个标签各算一项，结果按 DOM 序返回；
- ``integrity`` 按空白拆分为若干 token，仅 ``sha256``/``sha384``/
  ``sha512`` 且摘要部分为合法 Base64（解码长度恰为该算法摘要长度）的
  token 才算**合法摘要**，其余 token 一律忽略；没有任何合法摘要 →
  该项记 ``invalid_integrity``（不再抓取资源）；
- 只比较合法摘要中**最强的算法**（sha512 > sha384 > sha256）：任一该
  算法摘要与资源终点记录的**还原正文**（revisit 已沿引用链还原到终点
  response 的正文）逐字节相同即通过；无一匹配记 ``integrity_mismatch``；
- 每个资源独立按同一时点选取抓取并跟随重定向（与 navigate 同一套规则，
  含 8 跳上限与成环检测）；无抓取、重定向异常、终点非 2xx 都只在对应
  条目上标明原因，**不使整页失败**；根页面的选取/重定向失败与归档错误
  则与 /v1/navigate 一样使整个请求失败（404/422 原样透传）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
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

# 算法强度排序：只比较合法摘要中最强的一档（sha512 > sha384 > sha256）
_ALGO_STRENGTH = {"sha256": 1, "sha384": 2, "sha512": 3}
# 各算法摘要的字节长度：Base64 解码后长度不符的 token 不算合法摘要
_DIGEST_BYTES = {"sha256": 32, "sha384": 48, "sha512": 64}


def _parse_integrity(value: Optional[str]) -> dict[str, list[bytes]]:
    """把 integrity 属性值解析为 ``{算法: [摘要字节, ...]}``（仅合法摘要）。

    按空白拆分；token 形如 ``<alg>-<base64>``，算法名须为
    sha256/sha384/sha512 的原样小写形式，摘要部分须为合法 Base64 且解码
    长度等于该算法的摘要长度；其余 token（未知算法、非法 Base64、长度
    不符、带选项后缀等）一律忽略。
    """
    digests: dict[str, list[bytes]] = {}
    for token in (value or "").split():
        algorithm, sep, payload = token.partition("-")
        if not sep or algorithm not in _ALGO_STRENGTH or not payload:
            continue
        try:
            digest = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(digest) != _DIGEST_BYTES[algorithm]:
            continue
        digests.setdefault(algorithm, []).append(digest)
    return digests


class _IntegrityHTMLParser(HTMLParser):
    """收集 ``<base href>`` 候选与带 integrity 的资源引用（DOM 序，不去重）。

    HTMLParser 会把标签名与属性名统一成小写；同一属性重复出现时只取
    首次值（与浏览器一致）。``<base>`` 的 href 按文档顺序全部保留，由
    调用方选出首个有效者。只有带 ``integrity`` 属性且带非空资源地址
    （script 的 src / 样式表 link 的 href）的标签才进入 ``references``。
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_hrefs: list[str] = []
        # (来源标签, 原始 URL 字面值, integrity 属性原始值)
        self.references: list[tuple[str, str, Optional[str]]] = []

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
            return
        if "integrity" not in values:
            return
        if tag == "script":
            self._add("script", values.get("src"), values.get("integrity"))
        elif tag == "link":
            rel_tokens = (values.get("rel") or "").lower().split()
            if "stylesheet" in rel_tokens:
                self._add("link", values.get("href"), values.get("integrity"))

    def _add(self, source: str, raw_url: Optional[str],
             integrity: Optional[str]) -> None:
        if raw_url and raw_url.strip():
            self.references.append((source, raw_url, integrity))


def _check_resource(index, url: str, point_in_time, at: str,
                    digests: dict[str, list[bytes]]) -> dict:
    """核验单个资源：按时点抓取并跟随重定向，终点 2xx 后比对最强算法摘要。

    无抓取与重定向异常（navigate 的全部 404/422 错误码）只转化为条目上
    的原因标记；终点记录自己的 HTTP 状态非 2xx（含 revisit 自身无 HTTP
    头、状态为 None）记 ``status_not_2xx``；终点 2xx 时以其还原正文计算
    最强算法摘要，与全部合法该算法摘要逐一比较，任一相同即通过，无一
    匹配记 ``integrity_mismatch``。
    """
    try:
        _path, _final_url, rec = _follow_redirects(index, url, point_in_time,
                                                   at)
    except ReplayError as exc:
        return {
            "record_id": None,
            "http_status": None,
            "ok": False,
            "error": exc.code,
        }
    status = rec.http_status
    if status is None or not 200 <= status < 300:
        return {
            "record_id": rec.record_id_raw,
            "http_status": status,
            "ok": False,
            "error": "status_not_2xx",
        }
    algorithm = max(digests, key=lambda name: _ALGO_STRENGTH[name])
    actual = hashlib.new(algorithm, rec.body).digest()
    matched = any(candidate == actual for candidate in digests[algorithm])
    return {
        "record_id": rec.record_id_raw,
        "http_status": status,
        "ok": matched,
        "error": None if matched else "integrity_mismatch",
    }


def subresource_integrity(warc_b64: str, start_url: str, at: str) -> dict:
    """subresource-integrity 入口：返回最终页面各 integrity 标签的核验结果。"""
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

    # 按 DOM 序逐项核验：不按 URL 去重，非 HTTP(S) 地址直接忽略
    checks: list[dict] = []
    valid = 0
    for source, raw_url, integrity in parser.references:
        resource_url = _resolve_http_url(raw_url, base_url)
        if resource_url is None:
            continue
        digests = _parse_integrity(integrity)
        if not digests:
            # 没有任何合法摘要：不抓取资源，直接记 invalid_integrity
            result = {
                "record_id": None,
                "http_status": None,
                "ok": False,
                "error": "invalid_integrity",
            }
        else:
            result = _check_resource(index, resource_url, point_in_time, at,
                                     digests)
        if result["ok"]:
            valid += 1
        checks.append({"tag": source, "url": resource_url, **result})

    return {
        "final_url": final_url,
        "total": len(checks),
        "valid": valid,
        "checks": checks,
    }
