"""Speed, limits and failure isolation, measured on controlled loopback targets (benchmarks/targets.py).

The benchmarks in benchmarks/ produce the numbers; these tests keep the properties they showed:
* one broken host (reset, stalled, crashing, silent) never stops or spoils the scan, and is still reported,
* 10, 50 and 100 hosts are scanned side by side (the time does not grow with the host count),
* the scheduler never runs more than its limits and counts what it did,
* a port that never answers costs a bounded number of probes,
* a service is never mistaken for PostgreSQL just because its reply starts with S or N,
* cancelling stops a scan within a fraction of a second, even while connections hang.
"""
import time

import pytest

import nemla
from benchmarks import bench_network, bench_scan
from benchmarks.targets import LocalTarget
from nemla import engine
from nemla.fingerprint import SILENT_PROBES_BEFORE_GIVING_UP, detect_service

# ----------------------------------------------------------------------------------------------- scheduler counters


def test_the_scheduler_counts_what_it_did_and_respects_its_limits():
    with LocalTarget() as target:
        open_ports = [target.listen("127.0.0.1", 0, "close") for _ in range(4)]
        ports = bench_scan.port_list(300, open_ports)
        hosts, meta = nemla.run_scan("stats", ["127.0.0.1"], ports, no_ping=True, no_os=True, no_banner=True, threads=20, per_host=10,
                                     timeout=0.5)
    stats = meta["scheduler"]
    assert stats["workers"] == 20 and stats["failed"] == 0 and stats["cancelled"] == 0
    assert stats["submitted"] == stats["completed"] == 300 + 1                 # every port, plus the host's own final step
    assert 1 <= stats["peak_inflight"] <= 10                                    # per_host caps a single host
    assert stats["peak_queued"] <= 20 * 4                                       # the waiting line is bounded by the window
    assert len(hosts[0]["open_ports"]) >= 4


def test_cancelled_jobs_are_counted_and_the_moment_of_the_cancel_is_recorded():
    import threading
    cancel = threading.Event()
    with LocalTarget() as target:
        ports = [target.listen("127.0.0.1", 0, "silent") for _ in range(30)]
        threading.Timer(0.3, cancel.set).start()
        started = time.monotonic()
        _, meta = nemla.run_scan("stats", ["127.0.0.1"], ports, no_ping=True, no_os=True, threads=30, timeout=10.0, cancel=cancel)
        took = time.monotonic() - started
    assert meta["cancelled"] is True and took < 3.0                             # a 10 s timeout did not hold it back
    assert meta["scheduler"]["cancel_seen_after"] is not None and meta["scheduler"]["cancel_seen_after"] >= 0.25


# ----------------------------------------------------------------------------------------------- many hosts, some broken

@pytest.mark.parametrize("hosts", [10, 50, 100])
def test_many_hosts_are_scanned_side_by_side_and_broken_ones_do_not_matter(hosts):
    result = bench_network.scan_network(hosts, threads=400, timeout=0.3)
    plan = result["plan"]
    assert result["hosts_returned"] == hosts                                    # nobody vanished, broken or not
    assert result["healthy_complete"] == result["healthy_expected"] == hosts - 4
    assert result["broken_accounted_for"] and sum(len(v) for v in plan.values()) == 4
    assert result["crash_host_partial"]                                        # the host that crashed at the end kept its ports
    assert "host_incomplete" in result["warnings"] and result["failed_jobs"] == 1
    assert result["peak_active_connections"] <= 400
    assert result["seconds"] < 30 + hosts * 0.1                                # side by side: 100 hosts is not 10x the time of 10


def test_a_host_that_fails_at_the_last_step_keeps_its_open_ports(monkeypatch, tcp_server):
    port = tcp_server(lambda c: c.close())
    real = engine.assess_host

    def flaky(host):
        if host["ip"] == "127.0.0.2":
            raise RuntimeError("boom")
        return real(host)

    monkeypatch.setattr(engine, "assess_host", flaky)
    hosts, _ = nemla.run_scan("t", ["127.0.0.1", "127.0.0.2"], [port], no_ping=True, no_os=True, no_banner=True)
    by_ip = {h["ip"]: h for h in hosts}
    assert set(by_ip) == {"127.0.0.1"} or set(by_ip) == {"127.0.0.1", "127.0.0.2"}
    if "127.0.0.2" in by_ip:                                                    # only 127.0.0.1 has the listener
        assert by_ip["127.0.0.2"]["findings"] == [] and by_ip["127.0.0.2"]["os"]["family"] == "unknown"
    assert "127.0.0.1" in by_ip and by_ip["127.0.0.1"]["open_ports"]


def test_the_partial_record_of_a_failed_host_is_a_valid_report_row(monkeypatch, tcp_server):
    port = tcp_server(lambda c: c.close())
    monkeypatch.setattr(engine, "assess_host", lambda host: (_ for _ in ()).throw(RuntimeError("boom")))
    hosts, meta = nemla.run_scan("t", ["127.0.0.1"], [port], no_ping=True, no_os=True, no_banner=True)
    assert len(hosts) == 1 and hosts[0]["open_ports"] and hosts[0]["findings"] == []
    assert "host_incomplete" in [w["code"] for w in meta["warnings"]]
    for render in (nemla.render_html, nemla.markdown_text, nemla.json_text, nemla.sarif_text):
        assert render(meta, hosts)                                              # every report format copes with it
    assert nemla.csv_text(hosts)


# ----------------------------------------------------------------------------------------------- silent ports and lookalikes

def connections_used(intensity, timeout=0.15):
    with LocalTarget() as target:
        port = target.listen("127.0.0.1", 0, "silent")
        started = time.monotonic()
        info = detect_service("127.0.0.1", port, b"", "", timeout, None, None, intensity, None)
        return target.accepted, time.monotonic() - started, info


def test_a_port_that_never_answers_costs_a_bounded_number_of_probes():
    """Twelve probes of a full timeout each used to be tried on a silent port (6 s at 0.5 s): now a handful."""
    normal, normal_time, info = connections_used(intensity=5)
    everything, everything_time, _ = connections_used(intensity=9)
    assert info == {}                                                          # nothing to learn from a silent port
    assert normal <= SILENT_PROBES_BEFORE_GIVING_UP + 3                        # the silent probes, the TLS attempt, the port's own
    assert everything > normal and everything_time > normal_time               # intensity 7+ still tries every detector


def test_giving_up_never_skips_the_detectors_that_belong_to_the_port(monkeypatch):
    from nemla import fingerprint
    from nemla.fingerprint.base import Detector, Probe

    tried = []

    class Slow(Detector):                       # a general detector that always sits out the full timeout
        def __init__(self, name):
            self.name, self.rarity, self.ports = name, 1, ()

        def probe(self, probe):
            tried.append(self.name)
            time.sleep(probe.timeout)

    class Own(Detector):
        name, rarity, ports = "own", 9, (4242,)

        def probe(self, probe):
            tried.append(self.name)

    monkeypatch.setattr(fingerprint, "REGISTRY", [Slow(f"g{i}") for i in range(10)] + [Own()])
    fingerprint._active(Probe("127.0.0.1", 4242, timeout=0.05), intensity=5, diagnostics=None, stage="all")
    assert tried[0] == "own"                                                   # the port's own detector goes first
    assert len(tried) == 1 + SILENT_PROBES_BEFORE_GIVING_UP                    # then the general ones, until it gives up
    tried.clear()
    fingerprint._active(Probe("127.0.0.1", 4243, timeout=0.05), intensity=9, diagnostics=None, stage="all")
    assert [n for n in tried if n != "own"] == [f"g{i}" for i in range(10)]     # on another port, at intensity 9: all of them


def serve_reply(tcp_server, reply):
    def handler(conn):
        try:
            conn.settimeout(1)
            conn.sendall(reply)
            conn.recv(64)
        except OSError:
            pass
        finally:
            conn.close()

    return tcp_server(handler)


@pytest.mark.parametrize("reply", [b"SSH-2.0-OpenSSH_9.6\r\n", b"SS", b"NOTICE", b"SIP/2.0 200 OK\r\n", b"N?", b"Server ready\r\n"])
def test_a_reply_that_merely_starts_with_s_or_n_is_not_postgresql(tcp_server, reply):
    port = serve_reply(tcp_server, reply)
    info = detect_service("127.0.0.1", port, b"", "", 0.3, None, None, 5, None)
    assert info.get("detected") != "postgresql", info


@pytest.mark.parametrize("answer, ssl", [(b"S", True), (b"N", False)])
def test_a_real_postgresql_answer_is_still_recognised(tcp_server, answer, ssl):
    def handler(conn):
        try:
            conn.settimeout(1)
            conn.recv(8)
            conn.sendall(answer)
        except OSError:
            pass
        finally:
            conn.close()

    info = detect_service("127.0.0.1", tcp_server(handler), b"", "", 0.5, None, None, 5, None)
    assert info.get("detected") == "postgresql" and info["details"]["ssl_support"] is ssl


# ----------------------------------------------------------------------------------------------- the benchmark scripts

def test_the_port_benchmark_measures_what_it_promises():
    result = bench_scan.scan_once(100, 100, 0.3)
    assert result["ports"] == 100 and result["open_found"] >= result["open_expected"] == 20
    assert 1 <= result["peak_active_connections"] <= 100 and result["target_peak_connections"] >= 1
    assert result["peak_memory_mb"] >= 0 and result["seconds"] > 0 and result["probes"] >= 100


@pytest.mark.parametrize("scenario", ["rate_limited", "hung"])
def test_cancelling_stops_a_scan_within_a_fraction_of_a_second(scenario):
    result = bench_scan.cancel_latency(scenario, 100)
    assert result["cancelled"] is True and result["cancel_latency_s"] is not None
    assert result["cancel_latency_s"] < 1.0, result                             # measured: about 0.1 s


def test_port_lists_have_exactly_the_requested_size():
    assert len(bench_scan.port_list(100, [50000, 50001])) == 100
    assert len(bench_scan.port_list(65535, [1, 2, 65000])) == 65535
    assert bench_scan.port_list(10, [3]) == sorted(set(bench_scan.port_list(10, [3])))
