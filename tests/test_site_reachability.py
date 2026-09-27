"""/v1/site-reachability 端到端测试：BFS 遍历、链接解析、节点判定与错误场景。"""

from __future__ import annotations

import base64
import io

from fastapi.testclient import TestClient
from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import BufferWARCWriter

from app.main import app

client = TestClient(app)

AT = "2021-06-01T00:00:00Z"
D = "2021-01-01T00:00:00Z"


# ---------- WARC 构造辅助 ----------


def _make_response(w, rec_id, uri, date=D, status_code=200, reason="OK",
                   body=b"", location=None, with_http=True, rec_type="response",
                   refers_to=None, content_type="text/html; charset=utf-8"):
    headers = []
    if with_http:
        if location is not None:
            headers.append(("Location", location))
        if content_type is not None:
            headers.append(("Content-Type", content_type))
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


def sr(warc_bytes, url, at, **kw):
    return client.post(
        "/v1/site-reachability",
        json={"warc": base64.b64encode(warc_bytes).decode(), "url": url,
              "at": at},
        **kw,
    )


def sr_b64(warc_b64, url, at, **kw):
    return client.post("/v1/site-reachability",
                       json={"warc": warc_b64, "url": url, "at": at}, **kw)


def site_warc(pages, root_html=None, root_url="http://a/", root_id="<urn:root>"):
    """根页面 + 若干 (rec_id, url, html/kw) 页面的完整 WARC。

    pages 元素为 (rec_id, url, html) 三元组（默认 200 text/html）或
    (rec_id, url, html, kw) 四元组。
    """
    def fill(w):
        w.write_record(_make_response(
            w, root_id, root_url, D,
            body=root_html if root_html is not None else b""))
        for item in pages:
            rec_id, url, html = item[0], item[1], item[2]
            kw = item[3] if len(item) > 3 else {}
            kw.setdefault("date", D)
            w.write_record(_make_response(w, rec_id, url, body=html, **kw))
    return build_warc(fill)


def reached_map(resp_json):
    return {p["record_id"]: p for p in resp_json["reachable"]}


def unreachable_ids(resp_json):
    return [p["record_id"] for p in resp_json["unreachable"]]


# ---------- 正常路径：BFS 遍历与最短点击 ----------


def test_root_alone():
    warc = site_warc([], root_html=b"<html>home</html>")
    r = sr(warc, "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["reachable"] == [{
        "record_id": "<urn:root>", "min_clicks": 0, "previous_url": None}]
    assert d["unreachable"] == []


def test_bfs_chain_and_shortest_clicks_with_predecessors():
    # root -> a1 -> a2 -> a3；root 直接指向 a3（同层也验证最短路径取首次到达）
    root = (b'<a href="/s1">s1</a><a href="/s3">deep</a>')
    pages = [
        ("<urn:s1>", "http://a/s1", b'<a href="s2">s2</a>'),
        ("<urn:s2>", "http://a/s2", b'<a href="/s3">s3</a>'),
        ("<urn:s3>", "http://a/s3", b"end"),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:s1>", "<urn:s3>", "<urn:s2>"]
    by = reached_map(d)
    assert by["<urn:root>"]["min_clicks"] == 0
    assert by["<urn:root>"]["previous_url"] is None
    assert by["<urn:s1>"]["min_clicks"] == 1
    assert by["<urn:s1>"]["previous_url"] == "http://a/"
    # s3 同时可从 root（1 跳）与 s2（2 跳）到达，取最短：前驱为 root
    assert by["<urn:s3>"]["min_clicks"] == 1
    assert by["<urn:s3>"]["previous_url"] == "http://a/"
    assert by["<urn:s2>"]["min_clicks"] == 2
    assert by["<urn:s2>"]["previous_url"] == "http://a/s1"


def test_same_level_links_expanded_in_url_sorted_order():
    # root 链向 z 与 a；同层按 URL 字典序处理，记录顺序与点击数一致
    root = b'<a href="/z">z</a><a href="/a">a</a>'
    pages = [
        ("<urn:a>", "http://a/a", b'<a href="az">x</a>'),
        ("<urn:z>", "http://a/z", b'<a href="zy">x</a>'),
        ("<urn:az>", "http://a/az", b""),
        ("<urn:zy>", "http://a/zy", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:a>", "<urn:z>", "<urn:az>", "<urn:zy>"]


def test_cycles_and_duplicate_links_dedup():
    # root<->a 互链、b 自链、root 重复指向 a：只遍历一次，点击数取首次
    root = (b'<a href="a">a1</a><a href="a#x">a2</a>'
            b'<a href="/a?">a3</a>')
    pages = [
        ("<urn:a>", "http://a/a",
         b'<a href="/">back</a><a href="b">b</a>'),
        ("<urn:b>", "http://a/b",
         b'<a href="b#self">self</a><a href="./b">self2</a>'),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:a>", "<urn:b>"]
    by = reached_map(d)
    assert by["<urn:a>"]["min_clicks"] == 1
    assert by["<urn:b>"]["min_clicks"] == 2
    assert by["<urn:b>"]["previous_url"] == "http://a/a"


def test_relative_and_fragment_anchors():
    root = (b'<base href="http://a/dir/"><a href="page2.html">p</a>'
            b'<a href="page2.html#section">same</a>'
            b'<a href="/rooted">r</a>')
    pages = [
        ("<urn:p2>", "http://a/dir/page2.html", b""),
        ("<urn:rooted>", "http://a/rooted", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    # 同一层按绝对 URL 字典序：/dir/page2.html 在 /rooted 之前
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:p2>", "<urn:rooted>"]


def test_first_valid_base_href_wins():
    # 第一个 base 非法、第二个有效（相对根）、第三个应被忽略
    root = (b'<base href="mailto:x@y"><base href="/sub/">'
            b'<base href="http://other/ignored/">'
            b'<a href="p">p</a>')
    pages = [("<urn:p>", "http://a/sub/p", b"")]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:p>"]


def test_no_valid_base_falls_back_to_page_url():
    pages = [("<urn:p>", "http://a/dir/p", b"")]
    r = sr(site_warc(pages, root_url="http://a/dir/home",
                     root_html=b'<base href="ftp://x/"><a href="p">p</a>'),
          "http://a/dir/home", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:p>"]


def test_cross_origin_and_non_http_links_ignored():
    root = (b'<a href="http://other.com/x">o</a>'
            b'<a href="https://a/secure">scheme</a>'
            b'<a href="mailto:a@b">m</a>'
            b'<a href="javascript:void(0)">j</a>'
            b'<a href="#frag">frag</a>'
            b'<a href="">empty</a>')
    pages = [
        ("<urn:other>", "http://other.com/x", b""),
        ("<urn:secure>", "https://a/secure", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == ["<urn:root>"]
    # 跨源页面即便同包也不属于本站，不列入不可达
    assert d["unreachable"] == []


def test_host_port_part_of_origin():
    root = (b'<a href="http://a:8080/x">other-port</a>'
            b'<a href="http://a:80/x">default-port</a>')
    pages = [
        ("<urn:p>", "http://a:8080/x", b""),
        ("<urn:default>", "http://a:80/x", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    # 默认端口 80 显式写出仍与 root 同源；8080 是跨源，忽略且不计不可达
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:default>"]
    assert unreachable_ids(d) == []
    assert unreachable_ids(d) == []


# ---------- 节点判定：状态码、Content-Type、重定向 ----------


def test_non_2xx_and_non_html_children_skipped():
    root = (b'<a href="nf">nf</a><a href="img">img</a>'
            b'<a href="ok">ok</a>')
    pages = [
        ("<urn:nf>", "http://a/nf", b"nf",
         {"date": D, "status_code": 404, "reason": "Not Found"}),
        ("<urn:img>", "http://a/img", b"\x89PNG",
         {"date": D, "content_type": "image/png"}),
        ("<urn:ok>", "http://a/ok", b"ok"),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:ok>"]
    # 非 2xx / 非 HTML 终点不是页面节点，也不列入不可达
    assert d["unreachable"] == []


def test_content_type_params_and_case_ignored():
    root = (b'<a href="u1">1</a><a href="u2">2</a><a href="u3">3</a>'
            b'<a href="u4">4</a>')
    pages = [
        ("<urn:u1>", "http://a/u1", b"",
         {"date": D, "content_type": "TEXT/HTML"}),
        ("<urn:u2>", "http://a/u2", b"",
         {"date": D, "content_type": "text/html;charset=iso-8859-1"}),
        ("<urn:u3>", "http://a/u3", b"",
         {"date": D, "content_type": " application/xhtml+xml "}),
        ("<urn:u4>", "http://a/u4", b"", {"date": D, "content_type": None}),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:u1>", "<urn:u2>"]


def test_child_redirect_followed_using_navigate_rules():
    root = b'<a href="old">old</a>'
    pages = [
        ("<urn:old>", "http://a/old", b"",
         {"date": D, "status_code": 301, "reason": "Moved",
          "content_type": None, "location": "/new"}),
        ("<urn:new>", "http://a/new",
         b'<a href="/deeper">d</a>'),
        ("<urn:deeper>", "http://a/deeper", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    by = reached_map(d)
    # 页面节点是重定向终点；点击数按起点链接计（重定向不另算点击）
    assert by["<urn:new>"]["min_clicks"] == 1
    assert by["<urn:new>"]["previous_url"] == "http://a/"
    assert by["<urn:deeper>"]["min_clicks"] == 2
    assert by["<urn:deeper>"]["previous_url"] == "http://a/new"


def test_redirect_to_cross_origin_child_skipped():
    root = b'<a href="/out">out</a><a href="/in">in</a>'
    pages = [
        ("<urn:out>", "http://a/out", b"",
         {"date": D, "status_code": 302, "reason": "Found",
          "content_type": None, "location": "http://other/x"}),
        ("<urn:other>", "http://other/x", b""),
        ("<urn:in>", "http://a/in", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:in>"]
    assert d["unreachable"] == []


def test_child_redirect_error_skipped_not_fatal():
    root = b'<a href="loop">l</a><a href="noloc">n</a><a href="ok">o</a>'
    pages = [
        ("<urn:loop>", "http://a/loop", b"",
         {"date": D, "status_code": 301, "reason": "Moved",
          "content_type": None, "location": "/loop"}),
        ("<urn:noloc>", "http://a/noloc", b"",
         {"date": D, "status_code": 302, "reason": "Found",
          "content_type": None}),
        ("<urn:ok>", "http://a/ok", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:ok>"]


def test_child_missing_capture_skipped():
    root = b'<a href="gone">gone</a><a href="here">here</a>'
    pages = [("<urn:here>", "http://a/here", b"")]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:here>"]


def test_non_html_does_not_expand_links():
    # 2xx 但非 HTML 的页面不被当作节点，其 a[href] 不参与遍历
    root = b'<a href="json">j</a>'
    pages = [
        ("<urn:json>", "http://a/json", b'<a href="/hidden">h</a>',
         {"date": D, "content_type": "application/json"}),
        ("<urn:hidden>", "http://a/hidden", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == ["<urn:root>"]
    assert unreachable_ids(r.json()) == ["<urn:hidden>"]


# ---------- 时点选取与 revisit ----------


def test_selection_respects_point_in_time():
    root = b'<a href="p">p</a>'
    pages = [
        ("<urn:old>", "http://a/p", b"OLD",
         {"date": "2020-01-01T00:00:00Z"}),
        ("<urn:new>", "http://a/p",
         b'<a href="future">f</a>',
         {"date": "2021-03-01T00:00:00Z"}),
        ("<urn:future>", "http://a/future", b"",
         {"date": "2020-01-01T00:00:00Z"}),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    by = reached_map(r.json())
    # 选中 2021-03 的新版，其链接继续展开
    assert "<urn:new>" in by
    assert "<urn:future>" in by
    assert "<urn:old>" not in by


def test_same_timestamp_later_archive_record_wins():
    root = b'<a href="p">p</a>'

    def fill(w):
        w.write_record(_make_response(w, "<urn:root>", "http://a/", D, body=root))
        w.write_record(_make_response(w, "<urn:first>", "http://a/p", D,
                                      body=b"first"))
        w.write_record(_make_response(w, "<urn:second>", "http://a/p", D,
                                      body=b"second"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert "<urn:second>" in reached_map(r.json())


def test_capture_after_point_makes_child_unreachable():
    root = b'<a href="p">p</a><a href="q">q</a>'
    pages = [
        ("<urn:p>", "http://a/p", b"", {"date": "2022-01-01T00:00:00Z"}),
        ("<urn:q>", "http://a/q", b"", {"date": D}),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [x["record_id"] for x in d["reachable"]] == [
        "<urn:root>", "<urn:q>"]
    assert d["unreachable"] == []


def test_root_redirect_followed_before_crawling():
    # 根 301 到 /home：站点以终点同源，相对链接按终点 URL 解析
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:redir>", "http://a/start", D,
            status_code=301, reason="Moved", content_type=None,
            location="/home"))
        w.write_record(_make_response(
            w, "<urn:home>", "http://a/home", D,
            body=b'<a href="p">p</a>'))
        w.write_record(_make_response(
            w, "<urn:p>", "http://a/p", D, body=b""))
    r = sr(build_warc(fill), "http://a/start", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    by = reached_map(d)
    assert "<urn:home>" in by
    assert by["<urn:home>"]["min_clicks"] == 0
    assert by["<urn:home>"]["previous_url"] is None
    assert by["<urn:p>"]["previous_url"] == "http://a/home"


def test_revisit_page_body_is_restored_for_link_parsing():
    # 根是自带 200 HTTP 头的 revisit：正文取链终点 response（含 a[href]）；
    # 第二跳页面同样是 revisit，正文还原后继续展开其链接。
    def fill(w):
        w.write_record(_make_response(w, "<urn:orig-root>", "http://a/orig",
                                      "2020-01-01T00:00:00Z",
                                      body=b'<a href="/p">p</a>'))
        w.write_record(_make_response(w, "<urn:root>", "http://a/", D,
                                      rec_type="revisit",
                                      refers_to="<urn:orig-root>"))
        w.write_record(_make_response(w, "<urn:orig-p>", "http://a/orig-p",
                                      "2020-01-01T00:00:00Z",
                                      body=b'<a href="/q">q</a>'))
        w.write_record(_make_response(w, "<urn:p>", "http://a/p", D,
                                      rec_type="revisit",
                                      refers_to="<urn:orig-p>"))
        w.write_record(_make_response(w, "<urn:q>", "http://a/q", D, body=b""))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:p>", "<urn:q>"]
    by = reached_map(d)
    assert by["<urn:root>"]["record_id"] == "<urn:root>"
    assert by["<urn:p>"]["previous_url"] == "http://a/"
    assert by["<urn:q>"]["previous_url"] == "http://a/p"


def test_revisit_page_without_own_http_headers_is_skipped_as_child():
    # 子链接终点是无 HTTP 头的 revisit：状态/Content-Type 均为 null，
    # 不是 2xx HTML 节点，跳过但不报错。
    def fill(w):
        w.write_record(_make_response(w, "<urn:root>", "http://a/", D,
                                      body=b'<a href="/rev">r</a>'))
        # 链终点 response 位于跨源 URL：revisit 正文虽还原自它，但不参与
        # 本站页面枚举。
        w.write_record(_make_response(w, "<urn:orig>",
                                      "http://other/orig",
                                      "2020-01-01T00:00:00Z",
                                      body=b'<a href="/x">x</a>'))
        w.write_record(_make_response(w, "<urn:rev>", "http://a/rev", D,
                                      rec_type="revisit", with_http=False,
                                      content_type=None,
                                      refers_to="<urn:orig>"))
        w.write_record(_make_response(w, "<urn:x>", "http://a/x", D, body=b""))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == ["<urn:root>"]
    # revisit 无自身 HTTP 头，其正文里的链接不会被展开：x 不可达
    assert unreachable_ids(r.json()) == ["<urn:x>"]


def test_gzip_warc_supported():
    import gzip
    pages = [("<urn:p>", "http://a/p", b"")]
    r = sr(gzip.compress(site_warc(pages, root_html=b'<a href="/p">p</a>')),
           "http://a/", AT)
    assert r.status_code == 200, r.text
    assert [p["record_id"] for p in r.json()["reachable"]] == [
        "<urn:root>", "<urn:p>"]


# ---------- 不可达页面枚举 ----------


def test_unreachable_orphans_listed_sorted_by_record_id():
    pages = [
        ("<urn:linked>", "http://a/linked", b""),
        ("<urn:orphan-z>", "http://a/z", b""),
        ("<urn:orphan-a>", "http://a/a2", b""),
    ]
    r = sr(site_warc(pages, root_html=b'<a href="/linked">l</a>'),
           "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:linked>"]
    assert unreachable_ids(d) == ["<urn:orphan-a>", "<urn:orphan-z>"]
    assert all(set(p) == {"record_id"} for p in d["unreachable"])


def test_unreachable_excludes_non_html_non_2xx_and_cross_origin():
    pages = [
        ("<urn:html404>", "http://a/e404", b"",
         {"date": D, "status_code": 404, "reason": "Not Found"}),
        ("<urn:img>", "http://a/i.png", b"\x89PNG",
         {"date": D, "content_type": "image/png"}),
        ("<urn:other>", "http://other.site/x", b""),
        ("<urn:orphan>", "http://a/orphan", b""),
    ]
    r = sr(site_warc(pages, root_html=b"no links"), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert unreachable_ids(r.json()) == ["<urn:orphan>"]


def test_unreachable_page_behind_redirect_still_enumerated():
    # /alias 301 到 /target；root 不链向它们：target 是不可达 HTML 节点
    pages = [
        ("<urn:alias>", "http://a/alias", b"",
         {"date": D, "status_code": 301, "reason": "Moved",
          "content_type": None, "location": "/target"}),
        ("<urn:target>", "http://a/target", b""),
    ]
    r = sr(site_warc(pages, root_html=b""), "http://a/", AT)
    assert r.status_code == 200, r.text
    assert unreachable_ids(r.json()) == ["<urn:target>"]


def test_aliased_and_direct_link_to_redirect_target_shortest_wins():
    # root 同时链向 /alias（301 到 /target）与 /target：/target 首次到达为
    # 1 跳直链，前驱是 root；/alias 的重定向结果不产生重复节点。
    root = b'<a href="/alias">a</a><a href="/target">t</a>'
    pages = [
        ("<urn:alias>", "http://a/alias", b"",
         {"date": D, "status_code": 301, "reason": "Moved",
          "content_type": None, "location": "/target"}),
        ("<urn:target>", "http://a/target", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:target>"]
    t = reached_map(d)["<urn:target>"]
    assert t["min_clicks"] == 1
    assert t["previous_url"] == "http://a/"
    assert d["unreachable"] == []


def test_diamond_predecessor_takes_shortest_path():
    # root -> x -> z，root -> y -> z（两条 2 跳路径）；URL 序 x<y，
    # z 的前驱为 x（同层按 URL 排序时先展开 x）。
    root = b'<a href="x">x</a><a href="y">y</a>'
    pages = [
        ("<urn:x>", "http://a/x", b'<a href="z">z</a>'),
        ("<urn:y>", "http://a/y", b'<a href="z">z</a>'),
        ("<urn:z>", "http://a/z", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    by = reached_map(r.json())
    assert by["<urn:z>"]["min_clicks"] == 2
    assert by["<urn:z>"]["previous_url"] == "http://a/x"


def test_layer_sorted_by_terminal_url_not_entry_url():
    # 首页同时链接 /a 与 /b；/a 301 到 /z，/b 与 /z 都链接 /target。
    # 同层先解析重定向再按终点 URL 排序：/b 排在 /z 前展开，
    # 因此 /target 的前驱是 /b 而不是 /z（重定向不计点击）。
    root = b'<a href="/a">a</a><a href="/b">b</a>'
    pages = [
        ("<urn:a>", "http://a/a", b"",
         {"date": D, "status_code": 301, "reason": "Moved",
          "content_type": None, "location": "/z"}),
        ("<urn:z>", "http://a/z", b'<a href="/target">t</a>'),
        ("<urn:b>", "http://a/b", b'<a href="/target">t</a>'),
        ("<urn:target>", "http://a/target", b""),
    ]
    r = sr(site_warc(pages, root_html=root), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert [p["record_id"] for p in d["reachable"]] == [
        "<urn:root>", "<urn:b>", "<urn:z>", "<urn:target>"]
    by = reached_map(d)
    assert by["<urn:b>"]["min_clicks"] == 1
    assert by["<urn:b>"]["previous_url"] == "http://a/"
    assert by["<urn:z>"]["min_clicks"] == 1
    assert by["<urn:z>"]["previous_url"] == "http://a/"
    assert by["<urn:target>"]["min_clicks"] == 2
    assert by["<urn:target>"]["previous_url"] == "http://a/b"
    assert d["unreachable"] == []


# ---------- 根页面 / 归档错误 ----------


def test_root_no_capture_is_404():
    warc = site_warc([], root_html=b"")
    r = sr(warc, "http://missing/", AT)
    assert r.status_code == 404
    d = r.json()
    assert d["error"] == "capture_not_found"
    assert d["url"] == "http://missing/"


def test_root_redirect_cycle_is_422():
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:1>", "http://a/", D,
            status_code=301, reason="Moved", content_type=None,
            location="/x"))
        w.write_record(_make_response(
            w, "<urn:2>", "http://a/x", D,
            status_code=302, reason="Found", content_type=None,
            location="/"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "redirect_cycle"


def test_root_redirect_missing_location_is_422():
    rec = raw_record(
        "<urn:1>", uri="http://a/",
        block=http_block("HTTP/1.1 302 Found",
                         headers=[("Content-Length", "0")], body=b""))
    r = sr(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "missing_location"


def test_root_non_2xx_is_422():
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:nf>", "http://a/", D,
            status_code=404, reason="Not Found", body=b"nf"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    d = r.json()
    assert d["error"] == "status_not_2xx"
    assert d["record_id"] == "<urn:nf>"
    assert d["http_status"] == 404
    assert d["url"] == "http://a/"


def test_root_revisit_without_http_headers_is_422():
    def fill(w):
        w.write_record(_make_response(w, "<urn:orig>", "http://a/orig",
                                      "2020-01-01T00:00:00Z", body=b"html"))
        w.write_record(_make_response(w, "<urn:rev>", "http://a/", D,
                                      rec_type="revisit", with_http=False,
                                      content_type=None,
                                      refers_to="<urn:orig>"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "status_not_2xx"


def test_root_non_html_content_type_is_422():
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:img>", "http://a/", D, body=b"\x89PNG",
            content_type="image/png"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    d = r.json()
    assert d["error"] == "not_html"
    assert d["record_id"] == "<urn:img>"
    assert d["content_type"] == "image/png"


def test_root_missing_content_type_is_422():
    rec = raw_record(
        "<urn:1>", uri="http://a/",
        block=http_block("HTTP/1.1 200 OK",
                         headers=[("Content-Length", "4")], body=b"html"))
    r = sr(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "not_html"


def test_root_redirect_to_non_html_is_422():
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:redir>", "http://a/", D,
            status_code=302, reason="Found", content_type=None,
            location="/img"))
        w.write_record(_make_response(
            w, "<urn:img>", "http://a/img", body=b"\x89PNG",
            content_type="image/png"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "not_html"


def test_root_cross_origin_terminal_is_not_422():
    # 跨源根终点不触发 422：站点即终点同源，根页面正常（无同源子链接）
    def fill(w):
        w.write_record(_make_response(
            w, "<urn:redir>", "http://a/", D,
            status_code=301, reason="Moved", content_type=None,
            location="http://other.site/home"))
        w.write_record(_make_response(
            w, "<urn:home>", "http://other.site/home", body=b"home"))
    r = sr(build_warc(fill), "http://a/", AT)
    assert r.status_code == 200, r.text
    d = r.json()
    assert len(d["reachable"]) == 1
    assert d["reachable"][0]["record_id"] == "<urn:home>"
    assert d["unreachable"] == []


def test_invalid_start_url_422():
    warc_b64 = base64.b64encode(b"").decode()
    for bad in ("ftp://a/", "not a url", "http://", ""):
        r = sr_b64(warc_b64, bad, AT)
        assert r.status_code == 422, bad
        assert r.json()["error"] == "invalid_start_url"


def test_invalid_at_422():
    r = sr_b64(base64.b64encode(b"").decode(), "http://a/", "not-a-time")
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_at"


def test_malformed_warc_422():
    r = sr_b64(base64.b64encode(b"garbage").decode(), "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "malformed_warc"


def test_invalid_base64_422():
    r = sr_b64("!!!not-base64!!!", "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_base64"


def test_invalid_capture_date_in_warc_422():
    rec = raw_record("<urn:1>", uri="http://a/", date="not-a-date",
                     block=http_block(body=b"<a href='x'>"))
    r = sr(rec, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "invalid_capture_date"


def test_broken_revisit_chain_still_422():
    rev = raw_record(
        "<urn:rev>", rec_type="revisit", uri="http://a/",
        block=b"", extra_headers=b"WARC-Refers-To: <urn:uuid:ghost>\r\n")
    r = sr(rev, "http://a/", AT)
    assert r.status_code == 422
    assert r.json()["error"] == "target_not_found"


def test_missing_json_fields_422():
    r = client.post("/v1/site-reachability", json={"warc": ""})
    assert r.status_code == 422
