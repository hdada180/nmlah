"""The 3D interface in a real browser: the Stop button must be visible and clickable at every screen size.

Regression test for a layout bug: at 1440px wide the colour legend (lower right) covered the right part of the
Stop button, at 1280px all of it, and on phones the button was pushed off the screen. The test drives a real
headless Chrome/Chromium/Edge (standard-library DevTools client in browser_cdp.py) and measures the page.
It is skipped when no such browser is installed (set NEMLA_CHROME to choose one).
"""
import threading
import time

import pytest

import nemla
from browser_cdp import Browser, find_browser
from nemla_ui import server

pytestmark = pytest.mark.browser

# what the page must satisfy with the Stop button showing (the button is shown during a scan)
MEASURE = r"""
(() => {
  const box = (e) => { const b = e.getBoundingClientRect(); return {l: b.left, t: b.top, r: b.right, b: b.bottom, w: b.width, h: b.height}; };
  const shown = (id) => { const e = document.getElementById(id); return e && !e.hidden && getComputedStyle(e).display !== 'none' ? e : null; };
  const area = (a, b) => Math.max(0, Math.min(a.r, b.r) - Math.max(a.l, b.l)) * Math.max(0, Math.min(a.b, b.b) - Math.max(a.t, b.t));
  const stop = document.getElementById('btnStop');
  stop.hidden = false;
  const s = box(stop), hud = box(document.getElementById('hud'));
  const problems = [];
  const eps = 0.5;
  if (s.l < -eps || s.t < -eps || s.r > innerWidth + eps || s.b > innerHeight + eps) problems.push('the Stop button leaves the screen');
  if (s.l < hud.l - eps || s.r > hud.r + eps || s.t < hud.t - eps || s.b > hud.b + eps) problems.push('the Stop button sticks out of the HUD');
  for (const id of ['legend', 'dock', 'inspector']) {
    const e = shown(id); if (!e) continue;
    const b = box(e);
    if (area(s, b) > 0) problems.push('the ' + id + ' covers the Stop button');
    if (area(hud, b) > 1) problems.push('the ' + id + ' overlaps the HUD');
  }
  let hits = 0;
  for (const fx of [0.08, 0.5, 0.92]) for (const fy of [0.15, 0.5, 0.85]) {
    const el = document.elementFromPoint(s.l + s.w * fx, s.t + s.h * fy);
    if (el && (el === stop || stop.contains(el))) hits++;
  }
  if (hits !== 9) problems.push('only ' + hits + ' of 9 points of the Stop button receive clicks');
  const lg = shown('legend');
  if (lg) { const b = box(lg); if (b.l < 0 || b.r > innerWidth || b.t < 0 || b.b > innerHeight) problems.push('the legend leaves the screen'); }
  else problems.push('the legend is hidden');
  if (document.documentElement.scrollWidth > innerWidth) problems.push('the page scrolls sideways');
  const bar = document.querySelector('.topbar');
  for (const e of bar.querySelectorAll('.brand, .top-actions')) { if (e.getBoundingClientRect().right > innerWidth + eps) problems.push('the top bar overflows'); }
  return {problems, stop: s, hud, viewport: [innerWidth, innerHeight], lost: !document.getElementById('lost').hidden};
})()
"""

# a snapshot that only changes when the layout does, to wait until the page has settled
SNAPSHOT = r"""
(() => JSON.stringify(['hud', 'legend', 'dock', 'btnStop'].map((id) => { const e = document.getElementById(id); const b = e.getBoundingClientRect(); return [id, Math.round(b.left), Math.round(b.top), Math.round(b.width), Math.round(b.height)]; })))()
"""

SIZES = [
    (1920, 1080, "en"), (1440, 900, "en"), (1366, 768, "en"), (1280, 720, "en"), (1024, 768, "en"),
    (768, 1024, "en"), (390, 844, "en"), (360, 640, "en"), (320, 568, "en"),
    (1440, 900, "ar"), (1280, 720, "ar"), (1366, 768, "he"), (1024, 768, "he"), (390, 844, "ar"),
]


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    if find_browser() is None:
        pytest.skip("no Chrome, Chromium or Edge found (set NEMLA_CHROME)")
    app = server.App(nemla, data_dir=tmp_path_factory.mktemp("ui"))
    httpd = server.BoundedServer(("127.0.0.1", 0), server.make_handler(app))
    port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with Browser() as browser:
            yield browser, f"http://127.0.0.1:{port}/?demo=1#k={app.token}"
    finally:
        app.finished.set()
        httpd.shutdown()
        httpd.server_close()
        nemla._LANG = "en"
        nemla._LOG_SINK = None


def settle(browser, tries=80):
    """Wait until the welcome splash is gone and two snapshots 200 ms apart agree: the layout is final."""
    previous = None
    for _ in range(tries):
        try:
            current = browser.run(SNAPSHOT) if browser.run("!document.getElementById('splash')") else None
        except RuntimeError:                       # the page is still loading
            current = None
        if current is not None and current == previous:
            return
        previous = current
        time.sleep(0.2)
    raise AssertionError("the page never settled")


def open_at(browser, url, width, height, lang):
    browser.viewport(width, height)
    browser.open(url)
    settle(browser)
    if lang != "en":
        browser.run(f"document.querySelector('#langPop a[data-lang=\"{lang}\"]').click()")
        settle(browser)


@pytest.mark.parametrize(("width", "height", "lang"), SIZES)
def test_stop_button_is_visible_and_clickable(page, width, height, lang):
    browser, url = page
    open_at(browser, url, width, height, lang)
    result = browser.run(MEASURE)
    assert not result["lost"], "the page lost its connection to the server"
    assert result["problems"] == [], f"{width}x{height} {lang}: {result['problems']} (stop={result['stop']}, hud={result['hud']})"


def test_layout_follows_a_window_that_is_resized_after_loading(page):
    """The page is loaded wide and then narrowed and widened again, as when a window is dragged."""
    browser, url = page
    open_at(browser, url, 1920, 1080, "en")
    for width, height in ((1280, 720), (1440, 900), (390, 844), (1366, 768)):
        browser.viewport(width, height)
        settle(browser)
        result = browser.run(MEASURE)
        assert result["problems"] == [], f"after resizing to {width}x{height}: {result['problems']}"
