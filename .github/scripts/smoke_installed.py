"""Smoke-test an *installed* Nemla: run it with the Python of a clean virtual environment, from outside the checkout.

    <venv>/bin/python .github/scripts/smoke_installed.py            # after `pip install dist/*.whl`
    python .github/scripts/smoke_installed.py --source-checkout     # the same checks against the source tree

It proves what a user gets after `pip install`: the package comes from site-packages (not from the checkout), one
version everywhere (package metadata, `import nemla`, `nemla --version`, `python -m nemla`, the web API and the
reports), every module imports on its own, the console script works, a real scan of a loopback port produces every
report format, the web page and its assets are served with the security headers and refuse bad requests, and Fleet
mode works: its page and API, and an enrolled agent running a real scan and reporting it.
Standard library only.
"""
import http.client
import importlib.metadata
import json
import os
import pkgutil
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
failures = []
SOURCE_ENV = {}


def check(condition, what):
    print(("ok:   " if condition else "FAIL: ") + what)
    if not condition:
        failures.append(what)
    return condition


def run(*args, timeout=120):
    env = dict(os.environ, **SOURCE_ENV)
    # the arguments are built by this script from its own Python and the installed command: nothing untrusted
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, cwd=tempfile.gettempdir(),  # noqa: S603
                          env=env, check=False)


def source_version():
    text = (ROOT / "nemla" / "config.py").read_text(encoding="utf-8")
    return re.search(r'^__version__ = "([^"]+)"', text, re.M).group(1)


def console_script():
    found = shutil.which("nemla", path=str(Path(sys.executable).parent))
    return found or shutil.which("nemla")


def main(argv):
    from_source = "--source-checkout" in argv
    if from_source:
        sys.path.insert(0, str(ROOT))
        SOURCE_ENV["PYTHONPATH"] = str(ROOT)          # the subprocesses below start in another folder
    import nemla
    import nemla_ui

    here = Path(nemla.__file__).resolve()
    if from_source:
        check(ROOT in here.parents, f"running from the source checkout ({here})")
    else:
        check(ROOT not in here.parents and "site-packages" in here.parts, f"nemla is the installed copy ({here})")
        check(ROOT not in Path(nemla_ui.__file__).resolve().parents, "nemla_ui is the installed copy")

    # -- one version everywhere ------------------------------------------------------------------------------
    expected = source_version()
    check(nemla.__version__ == expected, f"import nemla: {nemla.__version__} == nemla/config.py {expected}")
    if not from_source:
        installed = importlib.metadata.version("nemla")
        check(installed == expected, f"package metadata: {installed} == {expected}")
    module_cli = run(sys.executable, "-m", "nemla", "--version")
    check(module_cli.returncode == 0 and module_cli.stdout.strip() == f"nemla {expected}",
          f"python -m nemla --version -> {module_cli.stdout.strip()!r}")
    script = console_script()
    if not from_source:
        check(script is not None, f"the `nemla` console script is installed ({script})")
    if script:
        script_cli = run(script, "--version")
        check(script_cli.returncode == 0 and script_cli.stdout.strip() == f"nemla {expected}",
              f"nemla --version -> {script_cli.stdout.strip()!r}")
        helped = run(script, "--help")
        check(helped.returncode == 0 and "usage" in helped.stdout.lower(), "nemla --help works")

    # -- every module imports on its own (a circular import only shows in a fresh interpreter) --------------------
    modules = []
    for package in (nemla, nemla_ui):
        modules.append(package.__name__)
        for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            modules.append(info.name)
    broken = []
    for name in modules:
        result = run(sys.executable, "-c", f"import {name}")
        if result.returncode != 0:
            broken.append(f"{name}: {result.stderr.strip().splitlines()[-1:]}")
    detail = f" (broken: {broken[:5]})" if broken else ""
    check(not broken, f"all {len(modules)} modules import in a fresh interpreter{detail}")

    # -- a real scan of a loopback port, in every report format ----------------------------------------------
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
            except OSError:
                pass
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    out = Path(tempfile.mkdtemp())
    files = {"html": out / "r.html", "json": out / "r.json", "csv": out / "r.csv", "md": out / "r.md", "sarif": out / "r.sarif"}
    command = script or None
    scan_args = ["127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "-o", str(files["html"]), "--json", str(files["json"]),
                 "--csv", str(files["csv"]), "--md", str(files["md"]), "--sarif", str(files["sarif"])]
    scan = run(command, *scan_args) if command else run(sys.executable, "-m", "nemla", *scan_args)
    listener.close()
    detail = "" if scan.returncode == 0 else f" ({scan.stdout[-300:]}{scan.stderr[-300:]})"
    check(scan.returncode == 0, f"scan of 127.0.0.1:{port} exits 0{detail}")
    check(all(path.is_file() and path.stat().st_size > 0 for path in files.values()), "every report format was written")
    if files["json"].is_file():
        data = json.loads(files["json"].read_text(encoding="utf-8"))
        ports = [p["port"] for host in data["hosts"] for p in host["open_ports"]]
        check(ports == [port], f"the JSON report lists the open port ({ports})")
        check(data.get("tool") == "nemla" and data.get("version") == expected,
              f"the JSON report says nemla {data.get('version')}")
    if files["sarif"].is_file():
        sarif = json.loads(files["sarif"].read_text(encoding="utf-8"))
        driver = sarif["runs"][0]["tool"]["driver"]
        check(sarif["version"] == "2.1.0" and driver["version"] == expected, "the SARIF report is 2.1.0 and carries the version")
    if files["html"].is_file():
        check("OpenSSH" in files["html"].read_text(encoding="utf-8"), "the HTML report names the service it found")

    # -- the web page and its assets, from the installed package -----------------------------------------------
    from nemla_ui import server
    app = server.App(nemla, data_dir=tempfile.mkdtemp())
    httpd = server.BoundedServer(("127.0.0.1", 0), server.make_handler(app))
    web_port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{web_port}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def get(path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=10)
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response.status, response, body

    status, response, body = get("/")
    has_csp = bool(response.getheader("Content-Security-Policy"))
    check(status == 200 and b"<html" in body.lower() and has_csp, "the web page is served with its CSP")
    check(get("/app.js")[0] == 200 and get("/brand/nemla-logo.svg")[0] == 200, "the page's script and brand assets are shipped")
    check(get("/api/info")[0] == 401, "the API refuses a request without the token")
    status, _, body = get("/api/info", {"X-Nemla-Token": app.token})
    check(status == 200 and json.loads(body)["version"] == expected, "the API reports the same version (with the token)")
    check(get("/api/info", {"X-Nemla-Token": app.token, "Host": "evil.example"})[0] == 403, "a wrong Host header is refused")
    check(get("/..%2f..%2fpyproject.toml")[0] == 404 and get("/%2e%2e/%2e%2e/config.py")[0] == 404, "path traversal is refused")
    httpd.shutdown()
    httpd.server_close()

    # -- Fleet mode from the installed package: the page, the API's key, and a real scan through a real agent ----------
    from nemla.fleet import agent as fleet_agent
    from nemla.fleet.controller import FleetError
    from nemla_ui import fleet_server
    fleet_root = Path(tempfile.mkdtemp())
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    target.listen(8)
    target_port = target.getsockname()[1]

    def answer():
        while True:
            try:
                conn, _ = target.accept()
            except OSError:
                return
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
            except OSError:
                pass
            conn.close()

    threading.Thread(target=answer, daemon=True).start()
    running = fleet_server.start_controller(fleet_root / "fleet", "127.0.0.1", 0, 0)
    stop = threading.Event()
    try:
        def fleet_get(path, headers=None):
            conn = http.client.HTTPConnection("127.0.0.1", running.operator_port, timeout=10)
            conn.request("GET", path, headers=headers or {})
            response = conn.getresponse()
            body = response.read()
            conn.close()
            return response.status, response, body

        status, response, body = fleet_get("/")
        check(status == 200 and b"Nemla Fleet" in body and bool(response.getheader("Content-Security-Policy")),
              "the Fleet page is served with its CSP")
        check(all(fleet_get(path)[0] == 200 for path in ("/fleet.js", "/fleet.css", "/brand/nemla-logo.svg")),
              "the Fleet page's script, style and logo are shipped")
        check(fleet_get("/app.js")[0] == 404 and fleet_get("/..%2f..%2fpyproject.toml")[0] in (400, 404),
              "the Fleet listener serves only its own files")
        check(fleet_get("/api/fleet/agents")[0] == 401, "the Fleet API refuses a request without the key")
        check(fleet_get("/api/fleet/agents", {"X-Nemla-Token": running.token})[0] == 200, "the Fleet API answers with the key")
        check(fleet_get("/", {"Host": "evil.example"})[0] == 403, "the Fleet page refuses a wrong Host header")

        token = running.controller.issue_token("smoke", "smoke test")["token"]
        fleet_agent.enroll(fleet_root / "agent", f"http://127.0.0.1:{running.agent_port}", token, "127.0.0.0/24", "")
        runner = fleet_agent.Runner(fleet_root / "agent", stop, say=lambda line: None, poll_seconds=2)
        worker = threading.Thread(target=runner.run, daemon=True)
        worker.start()
        try:
            running.controller.dispatch("smoke", {"target": "10.9.9.9", "ports": "22"}, "smoke test")
            refused = False
        except FleetError as err:
            refused = err.status == 403
        check(refused, "a job outside the agent's scope is refused by the controller")
        job = running.controller.dispatch("smoke", {"target": "127.0.0.1", "ports": str(target_port),
                                                    "options": {"no_os": True, "no_ping": True, "timeout": 1}}, "smoke test")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and running.controller.job(job["id"])["state"] not in ("done", "failed"):
            time.sleep(0.25)
        final = running.controller.job(job["id"])
        detail = "" if final["state"] == "done" else f" ({final.get('error')})"
        check(final["state"] == "done" and (final["summary"] or {}).get("open_ports") == 1,
              f"an enrolled agent ran a real scan and reported its open port ({final['state']}){detail}")
        outside = run(command, "agent", "status", "--data-dir", str(fleet_root / "nobody")) if command else \
            run(sys.executable, "-m", "nemla", "agent", "status", "--data-dir", str(fleet_root / "nobody"))
        check(outside.returncode == 1 and "not enrolled" in outside.stderr,
              "`nemla agent status` runs from the installed command")
    finally:
        stop.set()
        running.stop()
        target.close()

    print()
    print(f"{len(failures)} check(s) failed" if failures else "all smoke checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
