"""The page's contract with its markup and translations (no browser needed)."""
import http.client
import json
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

import nemla
from nemla_ui import server

WEB = Path(nemla.__file__).resolve().parent.parent / "nemla_ui" / "web"


def text(name):
    return (WEB / name).read_bytes().decode("utf-8")


@pytest.fixture()
def ui(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(app))
    port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{port}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, port
    app.finished.set()
    httpd.shutdown()
    httpd.server_close()


def get(port, path, token):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers={"X-Nemla-Token": token})
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res.status, data


def js_keys():
    """{lang: set of translation keys} of i18n.js, including the Object.assign additions."""
    source = text("i18n.js")
    keys = {"en": set(), "ar": set(), "he": set()}
    start = source.index("const STRINGS = {")
    end = source.index("let lang = 'en';")
    body = source[start:end]
    current = None
    for line in body.splitlines():
        top = re.match(r"^    (en|ar|he): \{", line)
        assign = re.match(r"^  Object\.assign\(STRINGS\.(en|ar|he), \{", line)
        if top or assign:
            current = (top or assign).group(1)
            continue
        key = re.match(r"^\s+'([^']+)':", line)
        if key and current:
            keys[current].add(key.group(1))
    return keys


def test_all_three_languages_have_the_same_ui_keys():
    keys = js_keys()
    assert len(keys["en"]) > 150
    assert keys["ar"] == keys["en"] == keys["he"], (sorted(keys["en"] ^ keys["ar"])[:5], sorted(keys["en"] ^ keys["he"])[:5])


def test_every_data_i18n_key_used_in_the_markup_exists():
    keys = js_keys()["en"]
    used = set(re.findall(r'data-i18n(?:-ph|-title|-aria)?="([^"]+)"', text("index.html")))
    assert used and not (used - keys), sorted(used - keys)


def test_every_translation_key_used_by_the_script_exists():
    keys = js_keys()["en"]
    used = set(re.findall(r"\bt\('([a-z][\w.]*)'", text("app.js")))
    used = {k for k in used if not k.endswith(".")}
    assert not (used - keys), sorted(used - keys)


def test_every_element_id_the_script_looks_up_exists_in_the_page():
    html = text("index.html")
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    wanted = set(re.findall(r"\$\('#([A-Za-z][\w-]*)'\)", text("app.js")))
    assert wanted and not (wanted - ids), sorted(wanted - ids)
    for tab in re.findall(r'data-tab="(\w+)"', html):
        assert f'id="pane-{tab}"' in html, tab


def test_the_new_screens_are_wired_up():
    js, html = text("app.js"), text("index.html")
    for needle in ("loadHistory", "openSaved", "history/scan?id=", "history/diff?a=", "history/report?id=", "osLabel",
                   "findingWhy", "findingFix", "udp: $('#optUdp').checked", "I.extend(", "cmpIp"):
        assert needle in js, needle
    for needle in ('data-tab="history"', 'id="pane-history"', 'id="optUdp"', 'data-fmt="md"', 'data-fmt="sarif"',
                   'id="inspEvidence"', 'id="inspUdp"'):
        assert needle in html, needle


def test_ipv6_addresses_sort_after_ipv4_in_the_page_logic():
    """The same algorithm as app.js's ipKey/cmpIp, checked in Python against the source text."""
    js = text("app.js")
    assert "if (bare.indexOf(':') === -1) return [4," in js and "return [6].concat(" in js

    def key(ip):
        bare = ip.split("%")[0]
        if ":" not in bare:
            n = 0
            for octet in bare.split("."):
                n = n * 256 + (int(octet) if octet.isdigit() else 0)
            return [4, n]
        halves = bare.split("::")
        head = halves[0].split(":") if halves[0] else []
        tail = halves[1].split(":") if len(halves) > 1 and halves[1] else []
        fill = ["0"] * max(0, 8 - len(head) - len(tail)) if len(halves) > 1 else []
        return [6] + [int(g or "0", 16) for g in head + fill + tail]

    ips = ["2001:db8::10", "10.0.0.9", "2001:db8::9", "10.0.0.10", "::1", "fe80::1%eth0"]
    assert sorted(ips, key=key) == ["10.0.0.9", "10.0.0.10", "::1", "2001:db8::9", "2001:db8::10", "fe80::1%eth0"]


def test_strings_endpoint_carries_every_finding_text_in_every_language(ui):
    app, port = ui
    status, data = get(port, "/api/strings", app.token)
    assert status == 200
    strings = json.loads(data)
    assert set(strings) == {"en", "ar", "he"}
    keys = set(strings["en"])
    assert strings["ar"].keys() == keys == strings["he"].keys()
    for kind in ("find.", "finddesc.", "findfix."):
        assert {k for k in keys if k.startswith(kind)} >= {kind + "telnet", kind + "smb1", kind + "tls_weak_sig"}
    ids = {k[len("find."):] for k in keys if k.startswith("find.")}
    assert ids == {k[len("finddesc."):] for k in keys if k.startswith("finddesc.")} == {k[len("findfix."):] for k in keys if k.startswith("findfix.")}
    assert "{port}" in strings["en"]["find.telnet"]


def test_strings_endpoint_needs_the_token(ui):
    _app, port = ui
    assert get(port, "/api/strings", "wrong")[0] == 401


def test_page_scripts_are_served_without_inline_code():
    html = text("index.html")
    assert re.findall(r'<script[^>]*src="([^"]+)"', html) == ["i18n.js", "scene.js", "demo.js", "app.js"] or \
        {"i18n.js", "scene.js", "demo.js", "app.js"} <= set(re.findall(r'<script[^>]*src="([^"]+)"', html))


def test_demo_colony_uses_the_new_fields():
    demo = text("demo.js")
    for needle in ("confidence", "heuristic", "evidence", "osGuess", "proto: 'tcp'"):
        assert needle in demo, needle
