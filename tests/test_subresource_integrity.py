"""/v1/subresource-integrity 端到端测试：integrity 解析、最强算法比较、
DOM 序逐项判定（不去重）与错误场景。"""

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


def page_warc(page_html, fills, page_url="http://a/",
              page_date="2021-01-01T00:00:00Z", page_id="<urn:uuid:page>"):
    """页面记录 + 各资源记录的完整 WARC；fills 为 (rec_id, url, kw) 列表。"""
    def fill(w):
        w.write_record(_make_response(w, page_id, page_url, page_date,
                                      body=page_html))
        for rec_id, url, kw in fills:
            w.write_record(_make_response(w, rec_id, url, **kw))
    return build_warc(fill)


def sri(algo, body):
    """计算 integrity 属性值中的合法摘要 token。"""
    digest = hashlib.new(algo, body).digest()
    return f"{algo}-{base64.b64encode(digest).decode()}"


def si(warc_bytes, url, at, **kw):
    return client.post(
        "/v1/subresource-integrity",
        json={"warc": base64.b64encode(warc_bytes).decode(), "url": url,
              "at": at},
        **kw,
    )


def si_b64(warc_b64, url, at, **kw):
    return client.post("/v1/subresource-integrity",
                       json={"warc": warc_b64, "url": url, "at": at}, **kw)


AT = "2021-06-01T00:00:00Z"
D = "2021-01-01T00:00:00Z"

CSS = b"body { color: black; }"
JS = b"alert(1)"


# ---------- 正常路径：提取与核验 ----------


def test_script_and_link_match_in_dom_order():
    html = (
        f'<html><head><link rel="stylesheet" href="/c.css" '
        f'integrity="{sri("sha384", CSS)}"></head>'
        f'<body><script src="/s.js" integrity="{sri("sha256", JS)}">'
        f"</script></body></html>"
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:css>", "http://a/c.css", {"date": D, "body": CSS}),
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["final_url"] == "http://a/"
    assert d["total"] == 2
    assert d["matched"] == 2
    # 按 DOM 序（head 的 link 在前），不按 URL 排序
    assert [i["tag"] for i in d["items"]] == ["link", "script"]
    assert [i["url"] for i in d["items"]] == [
        "http://a/c.css", "http://a/s.js"]
    assert [i["record_id"] for i in d["items"]] == [
        "<urn:uuid:css>", "<urn:uuid:js>"]
    assert [i["result"] for i in d["items"]] == ["match", "match"]


def test_sha512_match_and_mismatch():
    html = (
        f'<script src="/ok.js" integrity="{sri("sha512", JS)}"></script>'
        f'<script src="/bad.js" integrity="{sri("sha512", b"other")}">'
        f"</script>"
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:ok>", "http://a/ok.js", {"date": D, "body": JS}),
        ("<urn:uuid:bad>", "http://a/bad.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["matched"] == 1
    assert [i["result"] for i in d["items"]] == ["match", "mismatch"]
    assert d["items"][1]["record_id"] == "<urn:uuid:bad>"


def test_no_integrity_tags_returns_empty():
    html = (b'<script src="/s.js"></script>'
            b'<link rel="stylesheet" href="/c.css">'
            b'<img src="/p.png" integrity="ignored">')
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
        ("<urn:uuid:css>", "http://a/c.css", {"date": D, "body": CSS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 0
    assert d["matched"] == 0
    assert d["items"] == []


def test_case_insensitive_tags_attrs_and_rel():
    html = (
        f'<SCRIPT SRC="/s.js" INTEGRITY="{sri("sha256", JS)}"></SCRIPT>'
        f'<Link REL="Alternate StyleSheet" HREF="/c.css" '
        f'Integrity="{sri("sha384", CSS)}">'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
        ("<urn:uuid:css>", "http://a/c.css", {"date": D, "body": CSS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["matched"] == 2
    assert [i["tag"] for i in d["items"]] == ["script", "link"]


def test_non_stylesheet_link_and_missing_src_skipped():
    html = (
        f'<link rel="icon" href="/f.ico" integrity="{sri("sha256", JS)}">'
        f'<script integrity="{sri("sha256", JS)}"></script>'
        f'<script src="" integrity="{sri("sha256", JS)}"></script>'
        f'<link rel="stylesheet" integrity="{sri("sha256", JS)}">'
    ).encode()
    warc = page_warc(html, [])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["items"] == []


def test_non_http_url_skipped():
    html = (
        f'<script src="data:text/javascript,alert(1)" '
        f'integrity="{sri("sha256", JS)}"></script>'
        f'<script src="javascript:void(0)" integrity="{sri("sha256", JS)}">'
        f"</script>"
        f'<link rel="stylesheet" href="ftp://a/c.css" '
        f'integrity="{sri("sha256", CSS)}">'
    ).encode()
    warc = page_warc(html, [])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["items"] == []


def test_dom_order_kept_and_urls_not_deduped():
    # 同一 URL 出现两次：两个条目各自核验（一次匹配、一次不匹配）
    html = (
        f'<script src="/s.js" integrity="{sri("sha256", b"wrong")}"></script>'
        f'<link rel="stylesheet" href="/c.css" '
        f'integrity="{sri("sha384", CSS)}">'
        f'<script src="/s.js" integrity="{sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
        ("<urn:uuid:css>", "http://a/c.css", {"date": D, "body": CSS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 3
    assert d["matched"] == 2
    assert [(i["tag"], i["url"], i["result"]) for i in d["items"]] == [
        ("script", "http://a/s.js", "mismatch"),
        ("link", "http://a/c.css", "match"),
        ("script", "http://a/s.js", "match"),
    ]


# ---------- integrity 解析：合法摘要与最强算法 ----------


def test_strongest_algorithm_only_is_compared():
    # sha256 匹配但 sha512 不匹配：只比较最强的 sha512 → mismatch
    html = (
        f'<script src="/a.js" '
        f'integrity="{sri("sha256", JS)} {sri("sha512", b"wrong")}">'
        f"</script>"
        # sha256 不匹配但 sha384 匹配：只比较 sha384 → match
        f'<script src="/b.js" '
        f'integrity="{sri("sha256", b"wrong")} {sri("sha384", JS)}">'
        f"</script>"
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:a>", "http://a/a.js", {"date": D, "body": JS}),
        ("<urn:uuid:b>", "http://a/b.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [i["result"] for i in r.json()["items"]] == ["mismatch", "match"]


def test_multiple_digests_same_algo_any_match():
    good = sri("sha256", JS)
    other = sri("sha256", b"other")
    html = (
        f'<script src="/s.js" integrity="{other}  {good}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["items"][0]["result"] == "match"


def test_whitespace_separation_and_unknown_tokens_ignored():
    # 未知算法与损坏 token 忽略；余下的合法 sha256 参与比较
    html = (
        '<script src="/s.js" integrity="md5-AAAA\n\t'
        f'sha1-AAA {sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["items"][0]["result"] == "match"


def test_invalid_integrity_values():
    cases = [
        'integrity="md5-AAAA"',                       # 算法不受支持
        'integrity="sha256-!!!not-base64!!!"',        # Base64 非法
        f'integrity="sha256-{base64.b64encode(b"hi").decode()}"',  # 长度不符
        'integrity="sha512-"',                        # 空摘要
        'integrity=""',                               # 空属性值
        "integrity",                                  # 裸属性（无值）
        'integrity="sha256-AAAA"',                    # 解码长度不符
    ]
    html = "".join(f'<script src="/s{idx}.js" {attr}></script>'
                   for idx, attr in enumerate(cases)).encode()
    warc = page_warc(html, [
        (f"<urn:uuid:j{idx}>", f"http://a/s{idx}.js",
         {"date": D, "body": JS})
        for idx in range(len(cases))
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == len(cases)
    assert d["matched"] == 0
    assert [i["result"] for i in d["items"]] == ["invalid_integrity"] * 7
    # 到达 2xx 终点后才发现无合法摘要：终点记录 ID 照常给出
    assert d["items"][0]["record_id"] == "<urn:uuid:j0>"


def test_algorithm_name_case_insensitive_and_unpadded_base64():
    unpadded = sri("sha384", CSS).rstrip("=")
    html = (
        f'<script src="/s.js" integrity="SHA384-{unpadded.split("-", 1)[1]}">'
        f"</script>"
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": CSS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["items"][0]["result"] == "match"


# ---------- base href 与根页面重定向 ----------


def test_base_href_used_for_relative_urls():
    html = (
        f'<base href="http://cdn.example.com/static/">'
        f'<script src="s.js" integrity="{sri("sha256", JS)}"></script>'
        f'<link rel="stylesheet" href="/root.css" '
        f'integrity="{sri("sha384", CSS)}">'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://cdn.example.com/static/s.js",
         {"date": D, "body": JS}),
        ("<urn:uuid:css>", "http://cdn.example.com/root.css",
         {"date": D, "body": CSS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [i["url"] for i in d["items"]] == [
        "http://cdn.example.com/static/s.js",
        "http://cdn.example.com/root.css",
    ]
    assert d["matched"] == 2


def test_first_valid_base_wins():
    html = (
        f'<base href="ftp://cdn/x/"><base href="">'
        f'<base href="http://cdn.example.com/s/">'
        f'<script src="s.js" integrity="{sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://cdn.example.com/s/s.js",
         {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [i["url"] for i in r.json()["items"]] == [
        "http://cdn.example.com/s/s.js"]


def test_relative_urls_resolve_against_final_url_after_root_redirect():
    html = f'<script src="s.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:uuid:redir>", "http://a/start", D,
            status_code=301, reason="Moved", location="/home"))
        w.write_record(_make_response(
            w, "<urn:uuid:page>", "http://a/home", D, body=html))
        w.write_record(_make_response(
            w, "<urn:uuid:js>", "http://a/s.js", D, body=JS))
    r = si(build_warc(fill), "http://a/start", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["final_url"] == "http://a/home"
    assert d["items"][0]["url"] == "http://a/s.js"
    assert d["items"][0]["result"] == "match"


# ---------- 逐项判定：不中断其他项 ----------


def test_missing_capture_marked_per_item():
    html = (
        f'<script src="/have.js" integrity="{sri("sha256", JS)}"></script>'
        f'<script src="/gone.js" integrity="{sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:have>", "http://a/have.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 2
    assert d["matched"] == 1
    have, gone = d["items"]
    assert have["result"] == "match"
    assert gone["result"] == "capture_not_found"
    assert gone["record_id"] is None


def test_non_2xx_terminal_marked_per_item():
    html = (
        f'<script src="/nf.js" integrity="{sri("sha256", JS)}"></script>'
        f'<script src="/ok.js" integrity="{sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:nf>", "http://a/nf.js",
         {"date": D, "status_code": 404, "reason": "Not Found"}),
        ("<urn:uuid:ok>", "http://a/ok.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    nf, ok = d["items"]
    assert nf["result"] == "status_not_2xx"
    assert nf["record_id"] == "<urn:uuid:nf>"
    assert ok["result"] == "match"


def test_fetch_failure_takes_precedence_over_invalid_integrity():
    # 资源无法还原到 2xx 终点时报抓取原因，不看 integrity 是否合法
    html = b'<script src="/gone.js" integrity="md5-AAAA"></script>'
    warc = page_warc(html, [])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    assert item["result"] == "capture_not_found"
    assert item["record_id"] is None


def test_asset_redirect_followed_and_body_checked_at_terminal():
    html = f'<script src="/old.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    warc = page_warc(html, [
        ("<urn:uuid:r1>", "http://a/old.js",
         {"date": D, "status_code": 301, "reason": "Moved",
          "location": "/new.js"}),
        ("<urn:uuid:r2>", "http://a/new.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    assert item["url"] == "http://a/old.js"
    assert item["result"] == "match"
    assert item["record_id"] == "<urn:uuid:r2>"  # 终点记录 ID


def test_asset_redirect_errors_marked_per_item():
    html = (
        f'<script src="/noloc.js" integrity="{sri("sha256", JS)}"></script>'
        f'<script src="/loop.js" integrity="{sri("sha256", JS)}"></script>'
        f'<script src="/bad.js" integrity="{sri("sha256", JS)}"></script>'
        f'<script src="/ok.js" integrity="{sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:noloc>", "http://a/noloc.js",
         {"date": D, "status_code": 302, "reason": "Found"}),
        ("<urn:uuid:loop>", "http://a/loop.js",
         {"date": D, "status_code": 301, "location": "/loop.js"}),
        ("<urn:uuid:bad>", "http://a/bad.js",
         {"date": D, "status_code": 301, "location": "mailto:a@b"}),
        ("<urn:uuid:ok>", "http://a/ok.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [i["result"] for i in d["items"]] == [
        "missing_location", "redirect_cycle", "invalid_redirect_target",
        "match"]
    for item in d["items"][:3]:
        assert item["record_id"] is None


def test_selection_respects_point_in_time():
    html = (
        f'<script src="/t.js" integrity="{sri("sha256", b"v2")}"></script>'
        f'<script src="/u.js" integrity="{sri("sha256", JS)}"></script>'
    ).encode()
    warc = page_warc(html, [
        ("<urn:uuid:old>", "http://a/t.js",
         {"date": "2020-01-01T00:00:00Z", "body": b"v1"}),
        ("<urn:uuid:new>", "http://a/t.js",
         {"date": "2021-03-01T00:00:00Z", "body": b"v2"}),
        ("<urn:uuid:future>", "http://a/u.js",
         {"date": "2022-01-01T00:00:00Z", "body": JS}),
    ])
    r = si(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    t, u = r.json()["items"]
    assert t["result"] == "match"
    assert t["record_id"] == "<urn:uuid:new>"  # 时点前最新一条
    assert u["result"] == "capture_not_found"  # 时点之后才有抓取


def test_revisit_terminal_body_restored_for_check():
    # 终点 revisit 自己带 200：摘要对比的是链终点 response 的正文
    html = f'<script src="/rev.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    def fill(w):
        w.write_record(_make_response(w, "<urn:uuid:page>", "http://a/", D,
                                      body=html))
        w.write_record(_make_response(w, "<urn:uuid:orig>",
                                      "http://a/orig.js",
                                      "2020-01-01T00:00:00Z", body=JS))
        w.write_record(_make_response(w, "<urn:uuid:rev>", "http://a/rev.js",
                                      D, rec_type="revisit",
                                      refers_to="<urn:uuid:orig>"))
    r = si(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    assert item["result"] == "match"
    assert item["record_id"] == "<urn:uuid:rev>"


def test_revisit_terminal_without_http_status_is_not_2xx():
    html = f'<script src="/rev.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    def fill(w):
        w.write_record(_make_response(w, "<urn:uuid:page>", "http://a/", D,
                                      body=html))
        w.write_record(_make_response(w, "<urn:uuid:orig>",
                                      "http://a/orig.js",
                                      "2020-01-01T00:00:00Z", body=JS))
        w.write_record(_make_response(w, "<urn:uuid:rev>", "http://a/rev.js",
                                      D, rec_type="revisit", with_http=False,
                                      refers_to="<urn:uuid:orig>"))
    r = si(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]
    assert item["result"] == "status_not_2xx"
    assert item["record_id"] == "<urn:uuid:rev>"


def test_page_body_from_revisit_endpoint_is_parsed():
    html = f'<script src="/s.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    def fill(w):
        w.write_record(_make_response(w, "<urn:uuid:orig-page>",
                                      "http://a/orig-page",
                                      "2020-01-01T00:00:00Z", body=html))
        w.write_record(_make_response(w, "<urn:uuid:rev-page>", "http://a/",
                                      D, rec_type="revisit", with_http=False,
                                      refers_to="<urn:uuid:orig-page>"))
        w.write_record(_make_response(w, "<urn:uuid:js>", "http://a/s.js",
                                      D, body=JS))
    r = si(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 1
    assert d["items"][0]["result"] == "match"


def test_gzip_warc_supported():
    import gzip
    html = f'<script src="/s.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
    ])
    r = si(gzip.compress(warc), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert r.json()["matched"] == 1


# ---------- 根页面 / 归档错误：沿用原接口响应 ----------


def test_root_page_no_capture_is_404():
    html = f'<script src="/s.js" integrity="{sri("sha256", JS)}"></script>'.encode()
    warc = page_warc(html, [
        ("<urn:uuid:js>", "http://a/s.js", {"date": D, "body": JS}),
    ])
    r = si(warc, "http://other/", AT)
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
    r = si(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "redirect_cycle"


def test_root_page_missing_location_is_422():
    rec = raw_record("<urn:uuid:1>", uri="http://a/",
                     block=http_block("HTTP/1.1 302 Found", body=b""))
    r = si(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "missing_location"


def test_invalid_start_url_422():
    warc_b64 = base64.b64encode(b"").decode()
    for bad in ("ftp://a/", "not a url", "http://", ""):
        r = si_b64(warc_b64, bad, AT)
        assert r.status_code == 422, bad
        assert r.json()["error"] == "invalid_start_url"


def test_invalid_at_422():
    r = si_b64(base64.b64encode(b"").decode(), "http://a/", "not-a-time")
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_at"


def test_malformed_warc_422():
    r = si_b64(base64.b64encode(b"garbage").decode(), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "malformed_warc"


def test_invalid_base64_422():
    r = si_b64("!!!not-base64!!!", "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_base64"


def test_invalid_capture_date_in_warc_422():
    rec = raw_record("<urn:uuid:1>", uri="http://a/", date="not-a-date",
                     block=http_block(
                         body=b"<script src='/s.js' "
                              b"integrity='sha256-x'></script>"))
    r = si(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_capture_date"


def test_broken_revisit_chain_still_422():
    rev = raw_record(
        "<urn:uuid:rev>", rec_type="revisit", uri="http://a/",
        block=b"", extra_headers=b"WARC-Refers-To: <urn:uuid:ghost>\r\n")
    r = si(rev, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "target_not_found"


def test_missing_json_fields_422():
    r = client.post("/v1/subresource-integrity", json={"warc": ""})
    assert r.status_code == 422


def test_empty_warc_root_is_404():
    r = si(b"", "http://a/", AT)
    assert r.status_code == 404
    assert r.json()["error"] == "capture_not_found"
