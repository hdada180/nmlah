"""The Fleet page: what the operator listener serves, and the rules its files must keep."""
import re

import pytest

from nemla_ui import fleet_server
from nemla_ui.server import CSP, MIME, WEB_DIR

from test_fleet_controller import op, req

BANNED_IN_JS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout('", 'setTimeout("')


@pytest.fixture()
def running(tmp_path):
    rc = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0)
    yield rc
    rc.stop()


def page(rc, path, **kwargs):
    return req(rc.operator_port, "GET", path, **kwargs)


# --------------------------------------------------------------------------
# what is served
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path, name", [("/", "fleet.html"), ("/fleet.js", "fleet.js"), ("/fleet.css", "fleet.css"),
                                        ("/brand/nemla-logo.svg", "brand/nemla-logo.svg"), ("/brand/nemla-icon.svg", "brand/nemla-icon.svg")])
def test_the_page_and_its_assets_are_served_as_they_are_on_disk(running, path, name):
    status, body, res = page(running, path)
    assert status == 200 and body == (WEB_DIR / name).read_bytes()
    assert res.getheader("Content-Type") == MIME[("." + name.rsplit(".", 1)[1])]
    assert "no-cache" in res.getheader("Cache-Control") and res.getheader("X-Content-Type-Options") == "nosniff"


def test_the_html_carries_the_same_security_headers_as_the_main_interface(running):
    _, _, res = page(running, "/")
    assert res.getheader("Content-Security-Policy") == CSP
    assert res.getheader("X-Frame-Options") == "DENY" and res.getheader("Cross-Origin-Opener-Policy") == "same-origin"
    directives = dict(part.strip().split(" ", 1) for part in CSP.split(";") if part.strip())
    assert directives["script-src"] == "'self'" and "unsafe-eval" not in CSP     # scripts: our own files only, nothing inline
    assert directives["connect-src"] == "'self'" and directives["frame-ancestors"] == "'none'" and directives["object-src"] == "'none'"


def test_the_page_needs_no_token_but_the_data_behind_it_does(running):
    assert page(running, "/")[0] == 200
    for name in ("agents", "jobs", "audit", "info"):
        assert req(running.operator_port, "GET", f"/api/fleet/{name}")[0] == 401


@pytest.mark.parametrize("path", ["/fleet.html", "/index.html", "/app.js", "/style.css", "/i18n.js", "/scene.js", "/demo.js",
                                  "/brand/nemla-mark.svg", "/brand/", "/brand", "/../pyproject.toml", "/%2e%2e/pyproject.toml",
                                  "/brand/../style.css", "/brand/%2e%2e/style.css", "/fleet.js/", "/fleet.js%00.css",
                                  "/agent/v1/poll", "/api/fleet", "/api/fleet/nothing", "/favicon.ico"])
def test_nothing_but_the_fleet_page_and_its_own_assets_is_served(running, path):
    status, _, _ = req(running.operator_port, "GET", path, headers={"X-Nemla-Token": running.token})
    assert status in (400, 404)


def test_a_page_request_for_another_host_name_is_refused(running):
    """The same DNS-rebinding guard as the API: a page served under a name we did not bind is never handed out."""
    for host in ("evil.example", f"evil.example:{running.operator_port}", "127.0.0.1", ""):
        status, _, _ = page(running, "/", headers={"Host": host})
        assert status == 403, host
    assert page(running, "/", headers={"Host": f"localhost:{running.operator_port}"})[0] == 200


def test_the_page_cannot_be_written_to(running):
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        assert req(running.operator_port, method, "/", body={})[0] in (404, 405, 501)
        assert req(running.operator_port, method, "/fleet.js", body={})[0] in (404, 405, 501)


def test_a_dispatch_from_the_page_is_recorded_as_the_web_page_and_never_as_someone_else(running):
    token = op(running, "POST", "enroll-token", {"name": "acme-hq"})[1]["token"]
    enrolled, _, _ = req(running.agent_port, "POST", "/agent/v1/enroll",
                         {"token": token, "scope": "127.0.0.0/24", "version": "2", "hostname": "h"})
    assert enrolled == 200
    status, _, _ = op(running, "POST", "dispatch", {"agent": "acme-hq", "job": {"target": "127.0.0.1", "ports": "22"}},
                      headers={"X-Nemla-Operator": "web page"})
    assert status == 200
    events = op(running, "GET", "audit")[1]["events"]
    assert [e["operator"] for e in events if e["event"] == "dispatch"] == ["web page"]
    op(running, "POST", "dispatch", {"agent": "acme-hq", "job": {"target": "127.0.0.1", "ports": "22"}},
       headers={"X-Nemla-Operator": "<script>alert(1)</script>"})
    labels = [e["operator"] for e in op(running, "GET", "audit")[1]["events"] if e["event"] == "dispatch"]
    assert all(re.fullmatch(r"[A-Za-z0-9._@ -]+", label) for label in labels)


# --------------------------------------------------------------------------
# the rules the files themselves keep
# --------------------------------------------------------------------------

def read(name):
    return (WEB_DIR / name).read_text(encoding="utf-8")


def test_the_page_has_no_inline_code_and_loads_nothing_from_elsewhere():
    html = read("fleet.html")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), "inline scripts are blocked by the CSP anyway"
    assert not re.search(r"\son\w+\s*=", html) and "javascript:" not in html.lower()
    assert not re.search(r"""(?:src|href|action)\s*=\s*["'](?:https?:)?//""", html), "no third-party resources"
    assert not re.search(r"https?://", read("fleet.css")) and "@import" not in read("fleet.css")
    for reference in re.findall(r"""(?:src|href)="([^"#]+)"|url\(([^)]+)\)""", html + read("fleet.css")):
        target = next(part for part in reference if part).strip("'\" ")
        if target not in ("./",):
            assert (WEB_DIR / target).is_file() or target.startswith("data:"), f"{target} is not shipped"


def test_the_scripts_never_build_html_from_strings():
    text = read("fleet.js")
    for banned in BANNED_IN_JS:
        assert banned not in text, f"fleet.js uses {banned}"
    assert "'use strict'" in text


def test_the_token_is_kept_out_of_urls_and_sent_only_as_a_header():
    text = read("fleet.js")
    assert "X-Nemla-Token" in text
    assert not re.search(r"[?&]k=", text.replace("[#&]k=", "")), "the key must not travel in a query string"
    assert "history.replaceState" in text, "the #k= fragment is removed from the address bar once read"
    assert "localStorage.setItem('nemla.fk'" not in text, "the operator key lives in sessionStorage, not localStorage"
    for call in re.findall(r"fetch\(([^,)]*)", text):
        assert call.strip().startswith("'/api/fleet/'"), call


def text_blocks():
    js = read("fleet.js")
    blocks = {}
    for lang in ("en", "ar"):
        found = re.search(rf"\n    {lang}: \{{(.*?)\n    \}}", js, re.S)
        assert found, f"the {lang} texts were not found"
        entries = re.findall(r"""(?:^|[\s,{])(?:'([\w.]+)'|([A-Za-z_]\w*)):\s*(['"])(.*?)\3\s*(?:,|$)""", found.group(1), re.M | re.S)
        blocks[lang] = {quoted or plain: value for quoted, plain, _quote, value in entries}
    return js, blocks


def test_english_and_arabic_have_the_same_texts_with_the_same_placeholders():
    _, blocks = text_blocks()
    assert len(blocks["en"]) > 80
    assert blocks["en"].keys() == blocks["ar"].keys(), sorted(blocks["en"].keys() ^ blocks["ar"].keys())
    for key, english in blocks["en"].items():
        assert sorted(re.findall(r"\{(\w+)\}", english)) == sorted(re.findall(r"\{(\w+)\}", blocks["ar"][key])), key
        assert blocks["ar"][key].strip(), key


def test_every_text_the_page_asks_for_exists_and_none_is_left_over():
    js, blocks = text_blocks()
    html = read("fleet.html")
    code = re.sub(r"const TEXT = \{.*?\n  \};", "", js, flags=re.S)                  # the page's logic, without its dictionary
    dynamic = {f"{family}.{member}" for family, members in {
        "status": ("online", "offline", "revoked"), "state": ("queued", "sent", "running", "done", "failed", "cancelled", "expired"),
        "lost.session": ("title", "body"), "lost.gone": ("title", "body")}.items() for member in members}
    asked = set(re.findall(r'data-i18n="([\w.]+)"', html)) | set(re.findall(r"\bt\('([\w.]+)'\s*[,)]", code))
    asked |= set(re.findall(r"'((?:col|stat|act|live|add|pin)\.\w+)'", code)) | dynamic          # keys held in lists and ternaries
    missing = sorted(key for key in asked if key not in blocks["en"])
    assert not missing, missing
    mentioned = set(re.findall(r"'([\w.]+)'", code)) | set(re.findall(r'data-i18n="([\w.]+)"', html)) | dynamic
    unused = sorted(key for key in blocks["en"] if key not in mentioned)
    assert not unused, f"texts nobody asks for: {unused}"
