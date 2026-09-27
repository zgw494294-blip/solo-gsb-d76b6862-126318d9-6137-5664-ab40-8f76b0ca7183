"""/v1/subresource-integrity 端到端测试：integrity 解析、最强算法选取、
DOM 序逐项核验、revisit 还原正文比对与错误场景。"""

from __future__ import annotations

import base64
import hashlib
import io

from fastapi.testclient import TestClient
from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import BufferWARCWriter

from app.main import app

client = TestClient(app)


# ---------- WARC 构造辅助 ----------


def _make_response(w, rec_id, uri, date, status_code=200, reason="OK",
                   body=b"", location=None, with_http=True,
                   rec_type="response", refers_to=None):
    headers = []
    if with_http:
        if location is not None:
            headers.append(("Location", location))
        headers.append(("Content-Length", str(len(body))))
        http = StatusAndHeaders(f"{status_code} {reason}", headers,
                                protocol="HTTP/1.1")
    else:
        http = None
    wh = {"WARC-Date": date, "WARC-Record-ID": rec_id}
    if refers_to is not None:
        wh["WARC-Refers-To"] = refers_to
    return w.create_warc_record(
        uri, rec_type, http_headers=http, payload=io.BytesIO(body),
        warc_headers_dict=wh,
    )


def build_warc(fn, gzip_=False):
    w = BufferWARCWriter(gzip=gzip_)
    fn(w)
    return w.get_contents()


def raw_record(rec_id="<urn:uuid:r>", rec_type="response", block=b"",
               extra_headers=b"", date="2020-01-01T00:00:00Z",
               uri="http://example.com/"):
    uri_line = f"WARC-Target-URI: {uri}\r\n".encode() if uri is not None else b""
    return (
        f"WARC/1.1\r\nWARC-Type: {rec_type}\r\n"
        f"WARC-Record-ID: {rec_id}\r\nWARC-Date: {date}\r\n".encode()
        + uri_line
        + f"Content-Length: {len(block)}\r\n".encode()
        + extra_headers + b"\r\n" + block + b"\r\n\r\n"
    )


def http_block(status_line="HTTP/1.1 200 OK", headers=None, body=b""):
    h = status_line.encode() + b"\r\n"
    for k, v in (headers or []):
        h += f"{k}: {v}\r\n".encode()
    return h + b"\r\n" + body


def sri(algorithm, body):
    """构造合法 SRI token：<alg>-<body 摘要的 Base64>。"""
    digest = hashlib.new(algorithm, body).digest()
    return f"{algorithm}-" + base64.b64encode(digest).decode("ascii")


def page_warc(page_html, fills, page_url="http://a/",
              page_date="2021-01-01T00:00:00Z", page_id="<urn:uuid:page>"):
    """页面记录 + 各资源记录的完整 WARC；fills 为 (rec_id, url, kw) 列表。"""
    def fill(w):
        w.write_record(_make_response(w, page_id, page_url, page_date,
                                      body=page_html))
        for rec_id, url, kw in fills:
            w.write_record(_make_response(w, rec_id, url, **kw))
    return build_warc(fill)


def sri_post(warc_bytes, url, at, **kw):
    return client.post(
        "/v1/subresource-integrity",
        json={"warc": base64.b64encode(warc_bytes).decode(), "url": url,
              "at": at},
        **kw,
    )


def sri_post_b64(warc_b64, url, at, **kw):
    return client.post("/v1/subresource-integrity",
                       json={"warc": warc_b64, "url": url, "at": at}, **kw)


AT = "2021-06-01T00:00:00Z"
D = "2021-01-01T00:00:00Z"


# ---------- 正常路径：摘要匹配与算法选取 ----------


def test_script_and_link_digests_match():
    js, css = b"console.log(1)", b"body{color:red}"
    html = (f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'
            f'<link rel="stylesheet" href="c.css" '
            f'integrity="{sri("sha256", css)}">').encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
        ("<urn:uuid:c>", "http://a/c.css", {"date": D, "body": css}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["final_url"] == "http://a/"
    assert d["total"] == 2
    assert d["valid"] == 2
    # DOM 序：script 在前、link 在后（不是 URL 字典序）
    assert [(c["tag"], c["url"]) for c in d["checks"]] == [
        ("script", "http://a/s.js"), ("link", "http://a/c.css")]
    for c in d["checks"]:
        assert c["ok"] is True
        assert c["error"] is None
        assert c["http_status"] == 200
    assert d["checks"][0]["record_id"] == "<urn:uuid:s>"
    assert d["checks"][1]["record_id"] == "<urn:uuid:c>"


def test_all_three_algorithms_supported():
    body = b"body-bytes"
    html = (f'<script src="a.js" integrity="{sri("sha256", body)}"></script>'
            f'<script src="b.js" integrity="{sri("sha384", body)}"></script>'
            f'<script src="c.js" integrity="{sri("sha512", body)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:a>", "http://a/a.js", {"date": D, "body": body}),
        ("<urn:uuid:b>", "http://a/b.js", {"date": D, "body": body}),
        ("<urn:uuid:c>", "http://a/c.js", {"date": D, "body": body}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["valid"] == 3
    assert all(c["ok"] for c in d["checks"])


def test_only_strongest_algorithm_compared():
    js = b"js-body"
    # sha256 正确但 sha512 错误：只比较最强的 sha512 → 不匹配
    # sha256 错误但 sha384 正确：只比较最强的 sha384 → 通过
    html = (
        f'<script src="x.js" '
        f'integrity="{sri("sha256", js)} {sri("sha512", b"other")}"></script>'
        f'<script src="y.js" '
        f'integrity="{sri("sha256", b"other")} {sri("sha384", js)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:x>", "http://a/x.js", {"date": D, "body": js}),
        ("<urn:uuid:y>", "http://a/y.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["valid"] == 1
    x, y = d["checks"]
    assert x["url"] == "http://a/x.js"
    assert x["ok"] is False
    assert x["error"] == "integrity_mismatch"
    assert x["record_id"] == "<urn:uuid:x>"
    assert x["http_status"] == 200
    assert y["url"] == "http://a/y.js"
    assert y["ok"] is True
    assert y["error"] is None


def test_multiple_tokens_of_strongest_algorithm_any_match():
    js = b"js-body"
    html = (f'<script src="s.js" '
            f'integrity="{sri("sha512", b"no")} {sri("sha512", js)} '
            f'{sri("sha256", b"also-no")}"></script>').encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["checks"][0]["ok"] is True


def test_integrity_tokens_split_on_any_whitespace():
    js = b"js-body"
    html = (b'<script src="s.js" integrity="  ' + sri("sha256", js).encode()
            + b'\t\n ' + sri("sha384", js).encode() + b'  "></script>')
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["checks"][0]["ok"] is True


def test_invalid_tokens_ignored_strongest_valid_wins():
    js = b"js-body"
    # 更强的 sha512 token 非法（含非 Base64 字符、长度不符），
    # 不参与算法选取；最强的合法算法 sha256 正确 → 通过
    bad_b64 = "sha512-" + "!" * 68
    wrong_len = "sha384-" + base64.b64encode(b"\x00" * 32).decode()
    html = (f'<script src="s.js" integrity="{bad_b64} {wrong_len} '
            f'{sri("sha256", js)}"></script>').encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["checks"][0]["ok"] is True


# ---------- integrity 属性本身不合法：invalid_integrity ----------


def test_no_valid_digest_is_invalid_integrity():
    js = b"js-body"
    cases = [
        'integrity=""',                                  # 空值
        "integrity",                                     # 无值属性
        'integrity="   "',                               # 纯空白
        'integrity="md5-1B2M2Y8AsgTpgAmY7PhCfg=="',      # 未知算法
        'integrity="SHA256-' + "A" * 43 + '="',          # 算法名大写不认
        'integrity="sha256-!!!not-base64!!!"',           # 非法 Base64
        'integrity="sha256-AAAA"',                       # 解码长度不符
        'integrity="sha512-' + "A" * 43 + '="',          # sha256 长度冒充 sha512
        'integrity="sha256-"',                           # 空摘要
    ]
    for i, attr in enumerate(cases):
        html = f'<script src="s{i}.js" {attr}></script>'.encode()
        warc = page_warc(html, [
            (f"<urn:uuid:s{i}>", f"http://a/s{i}.js",
             {"date": D, "body": js}),
        ])
        r = sri_post(warc, "http://a/", AT)
        assert r.status_code == 200, (attr, r.text)
        d = r.json()
        assert d["total"] == 1, attr
        item = d["checks"][0]
        assert item["ok"] is False, attr
        assert item["error"] == "invalid_integrity", attr
        # 无合法摘要时不抓取资源：无终点记录
        assert item["record_id"] is None, attr
        assert item["http_status"] is None, attr
        assert d["valid"] == 0


def test_invalid_integrity_does_not_fetch_even_when_capture_missing():
    # 资源在归档中不存在：无合法摘要仍记 invalid_integrity（而非抓取错误）
    html = b'<script src="ghost.js" integrity="md5-AAAA"></script>'
    warc = page_warc(html, [])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["checks"][0]
    assert item["error"] == "invalid_integrity"
    assert item["record_id"] is None


# ---------- 标签筛选与 DOM 序 ----------


def test_tags_without_integrity_not_checked():
    html = (b'<script src="a.js"></script>'
            b'<link rel="stylesheet" href="b.css">'
            b'<script src="c.js" integrity=""></script>')
    warc = page_warc(html, [])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    # 只有带 integrity 的 c.js 参与（空 integrity → invalid_integrity）
    assert [c["url"] for c in d["checks"]] == ["http://a/c.js"]
    assert d["checks"][0]["error"] == "invalid_integrity"


def test_script_without_src_and_link_without_href_skipped():
    html = (b'<script integrity="sha256-AAAA"></script>'
            b'<script src="" integrity="sha256-AAAA"></script>'
            b'<link rel="stylesheet" integrity="sha256-AAAA">'
            b'<link rel="stylesheet" href="" integrity="sha256-AAAA">')
    warc = page_warc(html, [])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["checks"] == []


def test_no_integrity_tags_returns_empty():
    warc = page_warc(b"<html><body>plain</body></html>", [])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 0
    assert d["valid"] == 0
    assert d["checks"] == []


def test_dom_order_kept_and_no_url_dedup():
    js = b"js-body"
    # 同一 URL 出现两次（一次摘要错误、一次正确），与 link 交错：
    # 结果按 DOM 序，各自独立判定，不去重
    html = (f'<script src="b.js" integrity="{sri("sha256", b"no")}"></script>'
            f'<link rel="stylesheet" href="a.css" '
            f'integrity="{sri("sha256", js)}">'
            f'<script src="b.js" integrity="{sri("sha256", js)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:b>", "http://a/b.js", {"date": D, "body": js}),
        ("<urn:uuid:a>", "http://a/a.css", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 3
    assert d["valid"] == 2
    assert [(c["tag"], c["url"], c["ok"]) for c in d["checks"]] == [
        ("script", "http://a/b.js", False),
        ("link", "http://a/a.css", True),
        ("script", "http://a/b.js", True),
    ]
    assert d["checks"][0]["error"] == "integrity_mismatch"
    assert d["checks"][0]["record_id"] == "<urn:uuid:b>"


def test_case_insensitive_tags_attrs_and_rel():
    js = b"js-body"
    html = (f'<SCRIPT SRC="s.js" INTEGRITY="{sri("sha256", js)}"></SCRIPT>'
            f'<Link REL="StyleSheet" HREF="c.css" '
            f'Integrity="{sri("sha384", js)}">').encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
        ("<urn:uuid:c>", "http://a/c.css", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["valid"] == 2
    assert [c["tag"] for c in d["checks"]] == ["script", "link"]


def test_rel_token_list_and_non_stylesheet_link():
    js = b"js-body"
    html = (f'<link rel="alternate stylesheet" href="alt.css" '
            f'integrity="{sri("sha256", js)}">'
            f'<link rel="icon" href="favicon.ico" '
            f'integrity="{sri("sha256", js)}">').encode()
    warc = page_warc(html, [
        ("<urn:uuid:alt>", "http://a/alt.css", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    # rel 为词表：含 stylesheet 才核验；icon 即使带 integrity 也不参与
    assert [c["url"] for c in d["checks"]] == ["http://a/alt.css"]
    assert d["checks"][0]["ok"] is True


def test_fragment_stripped_and_non_http_ignored():
    js = b"js-body"
    html = (f'<script src="s.js#frag" integrity="{sri("sha256", js)}">'
            f'</script>'
            f'<script src="data:text/javascript,alert(1)" '
            f'integrity="{sri("sha256", js)}"></script>'
            f'<script src="javascript:void(0)" '
            f'integrity="{sri("sha256", js)}"></script>'
            f'<link rel="stylesheet" href="mailto:a@b" '
            f'integrity="{sri("sha256", js)}">').encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    # 片段去除；data:/javascript:/mailto: 直接忽略
    assert [c["url"] for c in d["checks"]] == ["http://a/s.js"]
    assert d["checks"][0]["ok"] is True


# ---------- base href 与根页面重定向 ----------


def test_first_valid_base_href_used():
    js = b"js-body"
    html = ('<base href="ftp://cdn/x/"><base href="">'
            '<base href="http://cdn.example.com/s/">'
            f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://cdn.example.com/s/s.js",
         {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [c["url"] for c in d["checks"]] == [
        "http://cdn.example.com/s/s.js"]
    assert d["checks"][0]["ok"] is True


def test_no_valid_base_falls_back_to_final_page_url():
    js = b"js-body"
    html = ('<base href="mailto:a@b">'
            f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:s>", "http://a/dir/s.js", {"date": D, "body": js}),
    ], page_url="http://a/dir/page")
    r = sri_post(warc, "http://a/dir/page", AT)
    assert r.status_code == 200, r.text
    assert [c["url"] for c in r.json()["checks"]] == ["http://a/dir/s.js"]


def test_relative_urls_resolve_against_final_url_after_root_redirect():
    js = b"js-body"
    html = f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'
    html_b = html.encode()

    def fill(w):
        w.write_record(_make_response(
            w, "<urn:uuid:redir>", "http://a/start", D,
            status_code=301, reason="Moved", location="/home"))
        w.write_record(_make_response(
            w, "<urn:uuid:page>", "http://a/home", D, body=html_b))
        w.write_record(_make_response(
            w, "<urn:uuid:s>", "http://a/s.js", D, body=js))
    r = sri_post(build_warc(fill), "http://a/start", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["final_url"] == "http://a/home"
    assert [c["url"] for c in d["checks"]] == ["http://a/s.js"]
    assert d["checks"][0]["ok"] is True


# ---------- 逐项判定：抓取与重定向失败不中断其他项 ----------


def test_capture_not_found_marked_per_item():
    js = b"js-body"
    html = (f'<script src="have.js" integrity="{sri("sha256", js)}"></script>'
            f'<script src="gone.js" integrity="{sri("sha256", js)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:have>", "http://a/have.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 2
    assert d["valid"] == 1
    have, gone = d["checks"]
    assert have["ok"] is True
    assert gone["ok"] is False
    assert gone["error"] == "capture_not_found"
    assert gone["record_id"] is None
    assert gone["http_status"] is None


def test_non_2xx_terminal_marked_per_item():
    js = b"js-body"
    html = (f'<script src="nf.js" integrity="{sri("sha256", js)}"></script>'
            f'<script src="ok.js" integrity="{sri("sha256", js)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:nf>", "http://a/nf.js",
         {"date": D, "status_code": 404, "reason": "Not Found",
          "body": b"oops"}),
        ("<urn:uuid:ok>", "http://a/ok.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["valid"] == 1
    nf, ok = d["checks"]
    # 终点非 2xx：不比对摘要，直接记 status_not_2xx
    assert nf["ok"] is False
    assert nf["error"] == "status_not_2xx"
    assert nf["record_id"] == "<urn:uuid:nf>"
    assert nf["http_status"] == 404
    assert ok["ok"] is True


def test_resource_redirect_errors_marked_per_item():
    js = b"js-body"
    html = (f'<script src="noloc.js" integrity="{sri("sha256", js)}"></script>'
            f'<script src="loop.js" integrity="{sri("sha256", js)}"></script>'
            f'<script src="bad.js" integrity="{sri("sha256", js)}"></script>'
            f'<script src="ok.js" integrity="{sri("sha256", js)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:noloc>", "http://a/noloc.js",
         {"date": D, "status_code": 302, "reason": "Found"}),
        ("<urn:uuid:loop>", "http://a/loop.js",
         {"date": D, "status_code": 301, "location": "/loop.js"}),
        ("<urn:uuid:bad>", "http://a/bad.js",
         {"date": D, "status_code": 301, "location": "mailto:a@b"}),
        ("<urn:uuid:ok>", "http://a/ok.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 4
    assert d["valid"] == 1
    errors = {c["url"]: c for c in d["checks"]}
    assert errors["http://a/noloc.js"]["error"] == "missing_location"
    assert errors["http://a/loop.js"]["error"] == "redirect_cycle"
    assert errors["http://a/bad.js"]["error"] == "invalid_redirect_target"
    for url in ("noloc.js", "loop.js", "bad.js"):
        item = errors[f"http://a/{url}"]
        assert item["ok"] is False
        assert item["record_id"] is None
        assert item["http_status"] is None
    assert errors["http://a/ok.js"]["ok"] is True


def test_resource_redirect_followed_digest_checked_on_endpoint_body():
    js = b"endpoint-body"
    html = f'<script src="old.js" integrity="{sri("sha256", js)}"></script>'
    warc = page_warc(html.encode(), [
        ("<urn:uuid:r1>", "http://a/old.js",
         {"date": D, "status_code": 301, "reason": "Moved",
          "location": "/new.js"}),
        ("<urn:uuid:r2>", "http://a/new.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["checks"][0]
    assert item["url"] == "http://a/old.js"
    assert item["ok"] is True
    assert item["record_id"] == "<urn:uuid:r2>"  # 终点记录 ID
    assert item["http_status"] == 200


def test_selection_respects_point_in_time():
    # 同一 URL 两次抓取：时点选中旧版，按旧版正文比对
    v1, v2 = b"body-v1", b"body-v2"
    html = (f'<script src="t.js" integrity="{sri("sha256", v1)}"></script>'
            f'<script src="u.js" integrity="{sri("sha256", v2)}"></script>'
            ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:old>", "http://a/t.js",
         {"date": "2020-01-01T00:00:00Z", "body": v1}),
        ("<urn:uuid:new>", "http://a/t.js",
         {"date": "2021-03-01T00:00:00Z", "body": v2}),
        ("<urn:uuid:u>", "http://a/u.js",
         {"date": "2021-03-01T00:00:00Z", "body": v2}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    t, u = d["checks"]
    # t.js 的 integrity 按 v1 构造，但时点选中 v2 → 不匹配
    assert t["record_id"] == "<urn:uuid:new>"
    assert t["ok"] is False
    assert t["error"] == "integrity_mismatch"
    assert u["ok"] is True


# ---------- revisit 还原正文 ----------


def test_revisit_endpoint_body_from_chain_terminal():
    # 终点 revisit 自带 200 HTTP 头：按其引用链终点 response 的正文比对
    orig_body = b"original-js"
    html = f'<script src="rev.js" integrity="{sri("sha256", orig_body)}">'
    html = (html + "</script>").encode()

    def fill(w):
        w.write_record(_make_response(w, "<urn:uuid:page>", "http://a/", D,
                                      body=html))
        w.write_record(_make_response(w, "<urn:uuid:orig>",
                                      "http://a/orig.js",
                                      "2020-01-01T00:00:00Z",
                                      body=orig_body))
        w.write_record(_make_response(w, "<urn:uuid:rev>", "http://a/rev.js",
                                      D, rec_type="revisit",
                                      refers_to="<urn:uuid:orig>"))
    r = sri_post(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["checks"][0]
    assert item["ok"] is True
    assert item["record_id"] == "<urn:uuid:rev>"
    assert item["http_status"] == 200


def test_revisit_endpoint_without_http_headers_is_status_not_2xx():
    orig_body = b"original-js"
    html = f'<script src="rev.js" integrity="{sri("sha256", orig_body)}">'
    html = (html + "</script>").encode()

    def fill(w):
        w.write_record(_make_response(w, "<urn:uuid:page>", "http://a/", D,
                                      body=html))
        w.write_record(_make_response(w, "<urn:uuid:orig>",
                                      "http://a/orig.js",
                                      "2020-01-01T00:00:00Z",
                                      body=orig_body))
        w.write_record(_make_response(w, "<urn:uuid:rev>", "http://a/rev.js",
                                      D, rec_type="revisit", with_http=False,
                                      refers_to="<urn:uuid:orig>"))
    r = sri_post(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["checks"][0]
    assert item["ok"] is False
    assert item["error"] == "status_not_2xx"
    assert item["record_id"] == "<urn:uuid:rev>"
    assert item["http_status"] is None


def test_page_body_from_revisit_endpoint_is_parsed():
    # 根页面自身是无 HTTP 头的 revisit：HTML 取自链终点 response 的正文
    js = b"js-body"
    html = f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'

    def fill(w):
        w.write_record(_make_response(w, "<urn:uuid:orig-page>",
                                      "http://a/orig-page",
                                      "2020-01-01T00:00:00Z",
                                      body=html.encode()))
        w.write_record(_make_response(w, "<urn:uuid:rev-page>", "http://a/",
                                      D, rec_type="revisit", with_http=False,
                                      refers_to="<urn:uuid:orig-page>"))
        w.write_record(_make_response(w, "<urn:uuid:s>", "http://a/s.js",
                                      D, body=js))
    r = sri_post(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 1
    assert d["valid"] == 1
    assert d["checks"][0]["url"] == "http://a/s.js"


def test_empty_body_digest_matches():
    empty = b""
    html = f'<script src="e.js" integrity="{sri("sha384", empty)}"></script>'
    warc = page_warc(html.encode(), [
        ("<urn:uuid:e>", "http://a/e.js", {"date": D, "body": empty}),
    ])
    r = sri_post(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["checks"][0]["ok"] is True


def test_gzip_warc_supported():
    import gzip
    js = b"js-body"
    html = f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'
    warc = page_warc(html.encode(), [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
    ])
    r = sri_post(gzip.compress(warc), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["valid"] == 1


# ---------- 根页面 / 归档错误：沿用原接口响应 ----------


def test_root_page_no_capture_is_404():
    js = b"js-body"
    html = f'<script src="s.js" integrity="{sri("sha256", js)}"></script>'
    warc = page_warc(html.encode(), [
        ("<urn:uuid:s>", "http://a/s.js", {"date": D, "body": js}),
    ])
    r = sri_post(warc, "http://other/", AT)
    assert r.status_code == 404
    d = r.json()
    assert d["error"] == "capture_not_found"
    assert d["url"] == "http://other/"
    assert d["path"] == []


def test_root_page_redirect_error_is_422():
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:uuid:1>", "http://a/", D,
            status_code=301, reason="Moved", location="/x"))
        w.write_record(_make_response(
            w, "<urn:uuid:2>", "http://a/x", D,
            status_code=302, reason="Found", location="/"))
    r = sri_post(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "redirect_cycle"


def test_root_page_missing_location_is_422():
    rec = raw_record("<urn:uuid:1>", uri="http://a/",
                     block=http_block("HTTP/1.1 302 Found", body=b""))
    r = sri_post(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "missing_location"


def test_invalid_start_url_422():
    warc_b64 = base64.b64encode(b"").decode()
    for bad in ("ftp://a/", "not a url", "http://", ""):
        r = sri_post_b64(warc_b64, bad, AT)
        assert r.status_code == 422, bad
        assert r.json()["error"] == "invalid_start_url"


def test_invalid_at_422():
    r = sri_post_b64(base64.b64encode(b"").decode(), "http://a/", "not-a-time")
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_at"


def test_malformed_warc_422():
    r = sri_post_b64(base64.b64encode(b"garbage").decode(), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "malformed_warc"


def test_invalid_base64_422():
    r = sri_post_b64("!!!not-base64!!!", "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_base64"


def test_invalid_capture_date_in_warc_422():
    rec = raw_record("<urn:uuid:1>", uri="http://a/", date="not-a-date",
                     block=http_block(body=b"<script src='s.js' "
                                      b"integrity='x'></script>"))
    r = sri_post(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_capture_date"


def test_broken_revisit_chain_still_422():
    rev = raw_record(
        "<urn:uuid:rev>", rec_type="revisit", uri="http://a/",
        block=b"", extra_headers=b"WARC-Refers-To: <urn:uuid:ghost>\r\n")
    r = sri_post(rev, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "target_not_found"


def test_missing_json_fields_422():
    r = client.post("/v1/subresource-integrity", json={"warc": ""})
    assert r.status_code == 422


def test_empty_warc_root_is_404():
    r = sri_post(b"", "http://a/", AT)
    assert r.status_code == 404
    assert r.json()["error"] == "capture_not_found"
