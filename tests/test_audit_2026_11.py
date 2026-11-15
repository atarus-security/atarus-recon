"""Regression tests for the 14 Nov 2026 audit findings.

Standard library plus click's CliRunner. Every network sink is a stand-in
or a server bound to 127.0.0.1 that the test starts and stops itself.
"""
import http.server
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from click.testing import CliRunner
from rich.console import Console

from atarus_recon import cli, runner as runner_module
from atarus_recon.models import ScanResult, Host
from atarus_recon.modules import crtsh, subfinder, waf_detect, cert_analysis, webprobe, whois_asn
from atarus_recon.modules import portscan, nuclei_scan, screenshot, risk_score
from atarus_recon.reports import html as html_report
from atarus_recon.runner import ModuleResult, ReconRunner
from atarus_recon.scope import ActiveScope, ScopeValidator


# Names a third-party source can hand back that end in the target domain but
# are not DNS names. Put in a URL, each one points somewhere else: a port on
# another host, a path or a fragment after a foreign host, userinfo.
HOSTILE_NAMES = [
    "127.0.0.1:18431#.lab.test",
    "out.invalid/x.lab.test",
    "out.invalid?.lab.test",
    "user@out.invalid#.lab.test",
    "out.invalid\\.lab.test",
    "two words.lab.test",
    "-flag.lab.test",
]


class _FakeCrtshResponse:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


class _Probe:
    def __init__(self):
        self.calls = []

    def run(self, result, scope, rate_limit, verbose):
        self.calls.append([h.hostname for h in result.hosts])
        return ModuleResult(success=True, message="probed")


class MalformedDiscoveredNameTests(unittest.TestCase):
    """A name from crt.sh or subfinder is admitted only when it is a well formed
    DNS name. Otherwise a name such as 127.0.0.1:18431#.lab.test matches
    *.lab.test by suffix and an active module turns it into a request to a
    host the user never named."""

    def test_scope_validator_refuses_names_that_are_not_dns_names(self):
        s = ScopeValidator("lab.test")
        for name in HOSTILE_NAMES:
            self.assertFalse(s.is_in_scope(name), name)
        self.assertTrue(s.is_in_scope("app.lab.test"))
        self.assertTrue(s.is_in_scope("APP.Lab.Test."))
        self.assertEqual(s.filter_in_scope(["App.lab.test.", "app.lab.test"]), ["app.lab.test"])

    def test_crtsh_drops_malformed_names(self):
        body = json.dumps([{"name_value": "\n".join(HOSTILE_NAMES + ["app.lab.test", "B.lab.test."])}]).encode()
        result = ScanResult(target="lab.test")
        with mock.patch.object(crtsh.urllib.request, "urlopen", return_value=_FakeCrtshResponse(body)):
            res = crtsh.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertTrue(res.success, res.message)
        self.assertEqual(sorted(h.hostname for h in result.hosts), ["app.lab.test", "b.lab.test"])

    def test_subfinder_drops_malformed_names(self):
        out = "\n".join(HOSTILE_NAMES + ["mail.lab.test"]) + "\n"
        result = ScanResult(target="lab.test")
        with mock.patch.object(subfinder.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=out, stderr="")):
            res = subfinder.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertTrue(res.success, res.message)
        self.assertEqual([h.hostname for h in result.hosts], ["mail.lab.test"])

    def test_active_scope_never_covers_a_malformed_name(self):
        s = ActiveScope(["*.lab.test", "203.0.113.0/24"])
        for name in HOSTILE_NAMES:
            self.assertFalse(s.covers(name, "203.0.113.7"), name)
        self.assertTrue(s.covers("app.lab.test", "203.0.113.7"))
        self.assertTrue(s.covers("", "203.0.113.7"), "an address alone is still matched against networks")

    def test_malformed_host_is_never_handed_to_an_active_module(self):
        def seed(result, scope, rate_limit, verbose):
            for name in HOSTILE_NAMES + ["app.lab.test"]:
                result.add_host(Host(hostname=name, ip="203.0.113.7"))
            return ModuleResult(True, "seeded")

        probe = _Probe()
        r = ReconRunner(target="lab.test", output_dir=".", active=True,
                        active_scope=ActiveScope(["*.lab.test", "203.0.113.0/24"]), assume_yes=True)
        r.register("Seed", "seed", seed, active=False)
        r.register("Probe", "probe", probe.run, active=True)
        with mock.patch.object(runner_module, "console", Console(file=io.StringIO(), width=200)):
            result = r.run()
        self.assertEqual(probe.calls, [["app.lab.test"]])
        self.assertEqual(sorted(h["hostname"] for h in result.out_of_scope), sorted(HOSTILE_NAMES))


class _Recorder(http.server.BaseHTTPRequestHandler):
    """Records every request; answers HEAD with a redirect when told to."""
    redirect_to = None
    hits = None

    def do_HEAD(self):
        type(self).hits.append((self.command, self.path, self.headers.get("Host")))
        if type(self).redirect_to:
            self.send_response(301)
            self.send_header("Location", type(self).redirect_to)
        else:
            self.send_response(200)
            self.send_header("Server", "cloudflare")
        self.end_headers()

    do_GET = do_HEAD

    def log_message(self, *args):
        pass


def _serve(redirect_to=None):
    handler = type("H", (_Recorder,), {"redirect_to": redirect_to, "hits": []})
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler


class _NoNameLookups:
    """Fails any name lookup that is not a literal address, so a probe that
    resolves the host name again (instead of using the checked IP) is caught."""

    def __enter__(self):
        real = socket.getaddrinfo

        def guarded(host, *args, **kwargs):
            try:
                import ipaddress
                ipaddress.ip_address(host)
            except ValueError:
                raise AssertionError(f"host name looked up again: {host}")
            return real(host, *args, **kwargs)

        self._patch = mock.patch.object(socket, "getaddrinfo", side_effect=guarded)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        return False


class InProcessProbeTests(unittest.TestCase):
    """The WAF probe and the certificate grab connect to the address the scope
    check approved, never to a fresh lookup of the name, and never follow a
    redirect to another host."""

    def test_waf_probe_does_not_follow_a_redirect_to_another_host(self):
        other, other_handler = _serve()
        target, target_handler = _serve(redirect_to=f"http://localhost:{other.server_port}/elsewhere")
        try:
            with _NoNameLookups():
                answered, text = waf_detect._fetch_headers("http", "app.lab.test", "127.0.0.1", target.server_port)
        finally:
            target.shutdown()
            other.shutdown()
        self.assertTrue(answered)
        self.assertIn("Location:", text)
        self.assertEqual(target_handler.hits, [("HEAD", "/", f"app.lab.test:{target.server_port}")])
        self.assertEqual(other_handler.hits, [], "the redirect target must not be contacted")

    def test_waf_probe_reads_headers_from_the_checked_address(self):
        server, handler = _serve()
        try:
            with _NoNameLookups():
                answered, text = waf_detect._fetch_headers("http", "app.lab.test", "127.0.0.1", server.server_port)
        finally:
            server.shutdown()
        self.assertTrue(answered)
        self.assertIn("Server: cloudflare", text)
        self.assertEqual(len(handler.hits), 1)

    def test_cert_grab_connects_to_the_checked_address(self):
        seen = []

        def fake_connect(addr, *args, **kwargs):
            seen.append(addr)
            raise ConnectionRefusedError()

        with mock.patch.object(cert_analysis.socket, "create_connection", side_effect=fake_connect):
            self.assertEqual(cert_analysis._get_cert_info("app.lab.test", "203.0.113.7"), {})
        self.assertEqual(seen, [("203.0.113.7", 443)])

    def test_waf_and_cert_that_reach_nothing_are_not_run(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7", status_code=200))
        scope = ScopeValidator("lab.test")
        with mock.patch.object(waf_detect.socket, "create_connection", side_effect=ConnectionRefusedError()):
            waf = waf_detect.run(result, scope, 10, False)
            cert = cert_analysis.run(result, scope, 10, False)
        self.assertFalse(waf.success, waf.message)
        self.assertIn("WAF presence unknown", waf.message)
        self.assertFalse(cert.success, cert.message)
        self.assertIn("no certificate could be read", cert.message)


class HttpxRedirectTests(unittest.TestCase):
    def test_httpx_follows_redirects_only_on_the_same_host(self):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                f.write(json.dumps({"input": "app.lab.test", "status_code": 200}) + "\n")
            return mock.Mock(returncode=0, stdout="", stderr="")

        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7"))
        with mock.patch.object(webprobe, "_find_pd_httpx", return_value="/opt/bin/httpx"), \
             mock.patch.object(webprobe.subprocess, "run", side_effect=fake_run):
            res = webprobe.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertTrue(res.success, res.message)
        self.assertIn("-follow-host-redirects", seen["cmd"])
        self.assertNotIn("-follow-redirects", seen["cmd"], "httpx must not follow redirects to other hosts")


def _invoke(args):
    """Invoke the CLI with the runner replaced; returns (click result, runner kwargs or None)."""
    captured = {}

    class _FakeRunner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def register(self, *a, **k):
            pass

        def run(self):
            r = ScanResult(target="lab.test")
            r.finalize()
            return r

    with tempfile.TemporaryDirectory() as d, mock.patch.object(cli, "ReconRunner", _FakeRunner), \
         mock.patch.object(cli, "tty_available", return_value=False):
        res = CliRunner().invoke(cli.main, ["-o", d, "--format", "json"] + args)
        # -o given twice: click keeps the last, so a test may pass its own.
    return res, (captured or None)


class ModuleSelectionFlagTests(unittest.TestCase):
    """--skip and --only must never silently select a module the user meant to leave out."""

    def test_unknown_module_key_is_a_usage_error(self):
        for args in (["--skip", "portscna"], ["--only", "crtsh,nothing"]):
            res, ran = _invoke(["-t", "lab.test"] + args)
            self.assertEqual(res.exit_code, 2, res.output)
            self.assertIn("unknown module", res.output)
            self.assertIsNone(ran)

    def test_repeated_skip_and_only_are_merged(self):
        res, ran = _invoke(["-t", "lab.test", "--skip", "crtsh", "--skip", "subfinder,whois"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertEqual(ran["skip"], ["crtsh", "subfinder", "whois"])
        res, ran = _invoke(["-t", "lab.test", "--only", "crtsh", "--only", "resolve"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertEqual(ran["only"], ["crtsh", "resolve"])

    def test_skip_and_only_together_is_a_usage_error(self):
        res, ran = _invoke(["-t", "lab.test", "--only", "crtsh", "--skip", "crtsh"])
        self.assertEqual(res.exit_code, 2, res.output)
        self.assertIsNone(ran)

    def test_keys_are_case_insensitive(self):
        res, ran = _invoke(["-t", "lab.test", "--skip", "CRTSH"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertEqual(ran["skip"], ["crtsh"])

    def test_rate_limit_must_be_positive(self):
        for value in ("0", "-3"):
            res, ran = _invoke(["-t", "lab.test", "--rate-limit", value])
            self.assertEqual(res.exit_code, 2, res.output)
            self.assertIsNone(ran)


class ScopeFlagTests(unittest.TestCase):
    def test_repeated_scope_is_the_union(self):
        res, ran = _invoke(["-t", "lab.test", "--scope", "app.lab.test", "--scope", "203.0.113.0/24"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertEqual(ran["active_scope"].entries, ["app.lab.test", "203.0.113.0/24"])

    def test_missing_scope_file_is_not_taken_as_a_host_name(self):
        for spec in ("scop.txt", "./engagements/scope.lst", "missing/scope"):
            res, ran = _invoke(["-t", "lab.test", "--scope", spec])
            self.assertEqual(res.exit_code, 2, res.output)
            self.assertIn("scope file not found", res.output)
            self.assertIsNone(ran)


class TargetAndOutputTests(unittest.TestCase):
    def test_invalid_target_is_a_usage_error_and_writes_no_report(self):
        for target in ("not a domain", "203.0.113.5", "bücher.example", "lab.test;id"):
            with tempfile.TemporaryDirectory() as d, \
                 mock.patch.object(cli.ReconRunner, "run", side_effect=AssertionError("runner must not start")):
                res = CliRunner().invoke(cli.main, ["-t", target, "-o", d, "--format", "json"])
                self.assertEqual(res.exit_code, 2, res.output)
                self.assertIn("not a domain name", res.output)
                self.assertEqual(os.listdir(d), [], "no report for a run that never started")
        res = CliRunner().invoke(cli.main, ["-t", "bücher.example"])
        self.assertIn("Punycode", res.output)

    def test_output_that_is_a_file_is_a_usage_error_before_the_scan(self):
        with tempfile.NamedTemporaryFile() as f, \
             mock.patch.object(cli.ReconRunner, "run", side_effect=AssertionError("runner must not start")):
            res = CliRunner().invoke(cli.main, ["-t", "lab.test", "-o", f.name])
        self.assertEqual(res.exit_code, 2, res.output)
        self.assertIn("--output", res.output)
        self.assertNotIn("Traceback", res.output)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write anywhere")
    def test_unwritable_output_is_a_usage_error_before_the_scan(self):
        with tempfile.TemporaryDirectory() as d:
            ro = os.path.join(d, "ro")
            os.mkdir(ro, 0o555)
            try:
                for out in (ro, os.path.join(ro, "sub")):
                    with mock.patch.object(cli.ReconRunner, "run", side_effect=AssertionError("runner must not start")):
                        res = CliRunner().invoke(cli.main, ["-t", "lab.test", "-o", out])
                    self.assertEqual(res.exit_code, 2, res.output)
                    self.assertIn("--output", res.output)
            finally:
                os.chmod(ro, 0o755)

    def test_output_path_with_markup_is_printed_literally(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "x[/]y[red]z")
            res, ran = _invoke(["-t", "lab.test", "-o", out])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("x[/]y[red]z", res.output.replace("\n", ""))


def _real_run_printing(raw: bytes, returncode: int = 0):
    """A subprocess.run stand-in that runs a real child printing raw bytes,
    passing the module's own keyword arguments through unchanged."""
    real = subprocess.run
    code = f"import sys; sys.stdout.buffer.write({raw!r}); sys.stderr.buffer.write({raw!r}); sys.exit({returncode})"

    def fake(cmd, *args, **kwargs):
        return real([sys.executable, "-c", code], **kwargs)
    return fake


class NonUtf8OutputTests(unittest.TestCase):
    """Registries and tools print Latin-1 and other bytes that are not UTF-8.
    That must not crash the module and turn real data into a not-run."""

    LATIN1 = b"Registrar: Caf\xe9 Registry\nRegistrant Organization: M\xfcller GmbH\nmail.lab.test\n"

    def test_whois_output_in_latin1_is_parsed(self):
        with mock.patch.object(whois_asn.subprocess, "run", side_effect=_real_run_printing(self.LATIN1)):
            data = whois_asn._whois_subprocess("lab.test")
        self.assertEqual(data["registrar"], "Caf\ufffd Registry")
        self.assertEqual(data["org"], "M\ufffdller GmbH")

    def test_subfinder_output_with_stray_bytes_is_read(self):
        result = ScanResult(target="lab.test")
        with mock.patch.object(subfinder.subprocess, "run", side_effect=_real_run_printing(self.LATIN1)):
            res = subfinder.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertTrue(res.success, res.message)
        self.assertEqual([h.hostname for h in result.hosts], ["mail.lab.test"])

    def test_every_external_binary_is_decoded_leniently(self):
        """Sweep: each module that runs a binary asks for UTF-8 with replacement."""
        calls = []

        def record(cmd, *args, **kwargs):
            calls.append((cmd[0] if isinstance(cmd, list) else cmd, kwargs))
            raise FileNotFoundError(cmd[0])

        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.44", status_code=200))
        scope = ScopeValidator("lab.test")
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"ATARUS_OUTPUT_DIR": d}), \
             mock.patch("subprocess.run", side_effect=record), \
             mock.patch.object(webprobe, "_find_pd_httpx", return_value="/opt/bin/httpx"), \
             mock.patch.object(nuclei_scan, "_find_nuclei", return_value="/opt/bin/nuclei"), \
             _TreatAsPublic("203.0.113.0/24"):
            whois_asn._whois_subprocess("lab.test")
            subfinder.run(result, scope, 10, False)
            portscan.run(result, scope, 10, False)
            webprobe.run(result, scope, 10, False)
            nuclei_scan.run(result, scope, 10, False)
            screenshot.run(result, scope, 10, False)
            webprobe._is_pd_httpx("/opt/bin/httpx")
        self.assertEqual(len(calls), 7, calls)
        for binary, kwargs in calls:
            self.assertEqual(kwargs.get("encoding"), "utf-8", binary)
            self.assertEqual(kwargs.get("errors"), "replace", binary)


class ReportEncodingTests(unittest.TestCase):
    def test_reports_are_written_as_utf8_under_a_latin1_locale(self):
        """Report files are UTF-8 whatever the locale; under a Latin-1 locale
        the HTML report used to fail on any non-Latin-1 title."""
        code = (
            "import locale, sys, tempfile\n"
            "if 'iso8859' not in locale.getpreferredencoding(False).lower().replace('-', '').replace('_', ''):\n"
            "    print('SKIP'); sys.exit(0)\n"
            "from atarus_recon.models import ScanResult, Host\n"
            "from atarus_recon.reports import html, json_export\n"
            "r = ScanResult(target='lab.test')\n"
            "r.add_host(Host(hostname='lab.test', ip='203.0.113.5', status_code=200, title='\\u65e5\\u672c \\u2603'))\n"
            "r.finalize()\n"
            "d = tempfile.mkdtemp()\n"
            "p = html.generate(r, d)\n"
            "json_export.generate(r, d)\n"
            "print('TITLE_OK' if '\\u65e5\\u672c' in open(p, encoding='utf-8').read() else 'TITLE_MISSING')\n"
        )
        env = dict(os.environ, LC_ALL="en_US.ISO8859-1", LANG="en_US.ISO8859-1", PYTHONUTF8="0")
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)
        if "SKIP" in proc.stdout:
            self.skipTest("no Latin-1 locale on this system")
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertIn("TITLE_OK", proc.stdout)


class ReportHonestyTests(unittest.TestCase):
    """The report says nothing clean about a check that was not made."""

    def _html(self, result):
        with tempfile.TemporaryDirectory() as d:
            with open(html_report.generate(result, d), encoding="utf-8") as f:
                return f.read()

    def test_unscanned_host_does_not_read_as_no_open_ports(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5"))
        result.modules_not_run.append({"module": "portscan", "name": "Port scan", "reason": "passive mode"})
        result.finalize()
        content = self._html(result)
        self.assertNotIn("No open ports detected", content)
        self.assertIn("Ports not scanned", content)

    def test_scanned_host_with_no_ports_says_so(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.44"))
        xml = '<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.44"/><ports></ports></host></nmaprun>'

        def fake_run(cmd, **kwargs):
            with open(cmd[cmd.index("-oX") + 1], "w") as f:
                f.write(xml)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(portscan.subprocess, "run", side_effect=fake_run), \
             _TreatAsPublic("203.0.113.0/24"):
            res = portscan.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertTrue(res.success, res.message)
        self.assertTrue(result.hosts[0].ports_scanned)
        result.finalize()
        self.assertIn("No open ports detected in top 100", self._html(result))

    def test_unchecked_waf_is_not_none_detected_and_carries_no_penalty(self):
        result = ScanResult(target="lab.test")
        host = Host(hostname="lab.test", ip="203.0.113.5", status_code=200, title="t")
        result.add_host(host)
        risk_score.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertEqual(host.risk_score, 0, "no WAF penalty for a WAF check that was not made")
        result.finalize()
        content = self._html(result)
        self.assertNotIn("None detected", content)
        self.assertIn("Not checked", content)

    def test_stale_screenshot_from_an_earlier_run_is_not_counted(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7", status_code=200))
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "screenshots"))
            stale = os.path.join(d, "screenshots", "https---app.lab.test-443.png")
            open(stale, "wb").close()
            os.utime(stale, (1, 1))
            with mock.patch.dict(os.environ, {"ATARUS_OUTPUT_DIR": d}), \
                 mock.patch.object(screenshot.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")):
                res = screenshot.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertIn("Captured 0 screenshots", res.message)
        self.assertEqual(result.hosts[0].screenshot_path, "")

    def test_fresh_screenshot_is_counted(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7", status_code=200))
        with tempfile.TemporaryDirectory() as d:
            def fake_run(cmd, **kwargs):
                out = cmd[cmd.index("--screenshot-path") + 1]
                open(os.path.join(out, "https---app.lab.test-443.png"), "wb").close()
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.dict(os.environ, {"ATARUS_OUTPUT_DIR": d}), \
                 mock.patch.object(screenshot.subprocess, "run", side_effect=fake_run):
                res = screenshot.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertIn("Captured 1 of 1 screenshots", res.message)

    def test_timestamps_carry_a_utc_offset(self):
        result = ScanResult(target="lab.test")
        result.finalize()
        for stamp in (result.started_at, result.finished_at):
            self.assertRegex(stamp, r"[+-]\d\d:\d\d$", stamp)


class WebUrlTests(unittest.TestCase):
    """Nuclei and gowitness are pointed at the URL httpx actually answered on.
    An HTTP-only site used to be handed to nuclei as https://, which fails on
    every template and then reads as a clean scan."""

    def _probe(self, url):
        def fake_run(cmd, **kwargs):
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                f.write(json.dumps({"input": "app.lab.test", "url": url, "status_code": 200}) + "\n")
            return mock.Mock(returncode=0, stdout="", stderr="")

        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7"))
        with mock.patch.object(webprobe, "_find_pd_httpx", return_value="/opt/bin/httpx"), \
             mock.patch.object(webprobe.subprocess, "run", side_effect=fake_run):
            webprobe.run(result, ScopeValidator("lab.test"), 10, False)
        return result

    def test_webprobe_records_the_url_httpx_answered_on(self):
        self.assertEqual(self._probe("http://app.lab.test").hosts[0].web_url, "http://app.lab.test")
        self.assertEqual(self._probe("https://app.lab.test:8443/login").hosts[0].web_url, "https://app.lab.test:8443")
        self.assertEqual(self._probe("https://other.test/").hosts[0].web_url, "", "a URL on another host is not recorded")

    def test_nuclei_and_gowitness_scan_that_url(self):
        result = self._probe("http://app.lab.test:8080")
        seen = {}

        def fake_run(cmd, **kwargs):
            flag = "-l" if "-l" in cmd else "-f"
            with open(cmd[cmd.index(flag) + 1]) as f:
                seen[os.path.basename(cmd[0])] = f.read().split()
            if "-o" in cmd:
                open(cmd[cmd.index("-o") + 1], "w").close()
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"ATARUS_OUTPUT_DIR": d}), \
             mock.patch.object(nuclei_scan, "_find_nuclei", return_value="/opt/bin/nuclei"), \
             mock.patch("subprocess.run", side_effect=fake_run):
            nuclei_scan.run(result, ScopeValidator("lab.test"), 10, False)
            screenshot.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertEqual(seen["nuclei"], ["http://app.lab.test:8080"])
        self.assertEqual(seen["gowitness"], ["http://app.lab.test:8080"])

    def test_gowitness_that_captures_nothing_is_not_run(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7", status_code=200))
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"ATARUS_OUTPUT_DIR": d}), \
             mock.patch.object(screenshot.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")):
            res = screenshot.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertFalse(res.success, res.message)
        self.assertIn("no screenshot", res.message)


if __name__ == "__main__":
    unittest.main()


# Names under the target zone whose DNS answer points off the client's
# assets: the operator's own loopback, a cloud metadata endpoint, a LAN.
NON_PUBLIC_ANSWERS = [
    ("lo.lab.test", "127.0.0.1"),
    ("meta.lab.test", "169.254.169.254"),
    ("lan.lab.test", "10.0.0.5"),
    ("zero.lab.test", "0.0.0.0"),
    ("mapped.lab.test", "::ffff:127.0.0.1"),
    ("v6lo.lab.test", "::1"),
    ("cgnat.lab.test", "100.64.0.9"),
]


class _TreatAsPublic:
    """Count the documentation ranges as globally routable for one test.

    Python counts 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 as not
    global, so a test that needs a "public" address and must not name a
    routable one patches the check instead.
    """

    def __init__(self, *nets):
        import ipaddress
        self._nets = [ipaddress.ip_network(n) for n in nets]

    def __enter__(self):
        from atarus_recon import scope as scope_module
        real = scope_module._is_global
        nets = self._nets

        def patched(addr):
            if any(addr.version == n.version and addr in n for n in nets):
                return True
            return real(addr)

        self._patch = mock.patch.object(scope_module, "_is_global", side_effect=patched)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        return False


class NonPublicAnswerTests(unittest.TestCase):
    """A name covered by a domain entry that resolves to a non-public address
    is not probed unless a network entry contains that address."""

    def test_domain_entry_does_not_admit_a_non_public_answer(self):
        s = ActiveScope(["*.lab.test", "lab.test"])
        for name, ip in NON_PUBLIC_ANSWERS:
            self.assertFalse(s.covers(name, ip), f"{name} -> {ip}")
            self.assertIn("address", s.exclusion_reason(name, ip))
        self.assertFalse(s.covers("lab.test", "127.0.0.1"), "a host entry is held to the same rule")

    def test_documentation_ranges_are_not_public(self):
        s = ActiveScope(["*.lab.test"])
        self.assertFalse(s.covers("app.lab.test", "203.0.113.7"))
        self.assertIn("documentation", s.exclusion_reason("app.lab.test", "203.0.113.7"))
        with _TreatAsPublic("203.0.113.0/24"):
            self.assertTrue(s.covers("app.lab.test", "203.0.113.7"))

    def test_reasons_name_the_kind_of_address(self):
        s = ActiveScope(["*.lab.test"])
        self.assertIn("loopback", s.exclusion_reason("lo.lab.test", "127.0.0.1"))
        self.assertIn("loopback", s.exclusion_reason("mapped.lab.test", "::ffff:127.0.0.1"))
        self.assertIn("link-local", s.exclusion_reason("meta.lab.test", "169.254.169.254"))
        self.assertIn("private", s.exclusion_reason("lan.lab.test", "10.0.0.5"))
        self.assertIn("unspecified", s.exclusion_reason("zero.lab.test", "0.0.0.0"))
        self.assertIn("multicast", s.exclusion_reason("mc.lab.test", "224.0.0.1"))

    def test_an_explicit_network_entry_opts_in(self):
        s = ActiveScope(["*.lab.test", "127.0.0.0/8", "169.254.169.254"])
        self.assertTrue(s.covers("lo.lab.test", "127.0.0.1"))
        self.assertTrue(s.covers("meta.lab.test", "169.254.169.254"))
        self.assertFalse(s.covers("lan.lab.test", "10.0.0.5"), "only the listed networks are opted in")

    def test_is_valid_ip_refuses_every_non_public_kind(self):
        for _, ip in NON_PUBLIC_ANSWERS + [("", "224.0.0.1"), ("", "203.0.113.7"), ("", "not-an-ip")]:
            self.assertFalse(ScopeValidator.is_valid_ip(ip), ip)
        with _TreatAsPublic("203.0.113.0/24"):
            self.assertTrue(ScopeValidator.is_valid_ip("203.0.113.7"))

    def test_no_active_module_reaches_a_non_public_answer(self):
        """End to end through the real active modules, with every sink stubbed."""
        hosts = NON_PUBLIC_ANSWERS + [("app.lab.test", "203.0.113.7")]

        def seed(result, scope, rate_limit, verbose):
            for name, ip in hosts:
                result.add_host(Host(hostname=name, ip=ip, status_code=200))
            return ModuleResult(True, "seeded")

        connects = []
        handed = []

        def fake_connect(addr, *a, **k):
            connects.append(addr[0])
            raise OSError("stubbed")

        def fake_run(cmd, **kwargs):
            for flag in ("-l", "-f"):
                if flag in cmd:
                    with open(cmd[cmd.index(flag) + 1], encoding="utf-8") as f:
                        handed.append(f.read())
            handed.append(" ".join(cmd))
            return mock.Mock(returncode=1, stdout="", stderr="stubbed")

        r = ReconRunner(target="lab.test", output_dir=tempfile.mkdtemp(), active=True,
                        active_scope=ActiveScope(["*.lab.test"]), assume_yes=True)
        r.register("Seed", "seed", seed, active=False)
        for name, key, func, is_active in cli.MODULE_REGISTRY:
            if is_active:
                r.register(name, key, func, active=True)
        out = io.StringIO()
        with _TreatAsPublic("203.0.113.0/24"), \
             mock.patch.object(runner_module, "console", Console(file=out, width=300)), \
             mock.patch("socket.create_connection", side_effect=fake_connect), \
             mock.patch.object(subprocess, "run", side_effect=fake_run), \
             mock.patch.object(webprobe, "_find_pd_httpx", return_value="/opt/bin/httpx"), \
             mock.patch("shutil.which", return_value="/opt/bin/tool"):
            result = r.run()

        self.assertTrue(connects, "the WAF and cert modules ran against the public host")
        self.assertEqual(set(connects), {"203.0.113.7"})
        text = "\n".join(handed)
        self.assertIn("app.lab.test", text)
        for name, ip in NON_PUBLIC_ANSWERS:
            self.assertNotIn(name, text)
            self.assertNotIn(f" {ip}", text)
        skipped = {h["hostname"]: h for h in result.out_of_scope}
        self.assertEqual(sorted(skipped), sorted(n for n, _ in NON_PUBLIC_ANSWERS))
        self.assertIn("loopback", skipped["lo.lab.test"]["reason"])
        self.assertIn("link-local", skipped["meta.lab.test"]["reason"])
        self.assertIn("link-local address", out.getvalue())

    def test_report_says_why_a_host_was_skipped(self):
        result = ScanResult(target="lab.test", mode="active")
        result.out_of_scope = [{"hostname": "meta.lab.test", "ip": "169.254.169.254",
                                "reason": "resolves to a link-local address; only a network entry in --scope that contains it admits it"}]
        result.finalize()
        with tempfile.TemporaryDirectory() as d:
            path = html_report.generate(result, d)
            with open(path, encoding="utf-8") as f:
                page = f.read()
        self.assertIn("resolves to a link-local address", page)



class TrailingNewlineNameTests(unittest.TestCase):
    """$ matches before a trailing newline, so ^...$ with re.match let one through."""

    def test_label_with_trailing_newline_is_not_a_name(self):
        from atarus_recon.scope import is_valid_name, normalize_name
        for name in ("a\n.lab.test", "lab.test\n", "lab.te\nst", "evil.invalid\n.lab.test", "lab.tes\nt"):
            self.assertFalse(is_valid_name(name), repr(name))
        self.assertEqual(normalize_name("a\n.lab.test"), "")
        self.assertFalse(ScopeValidator("lab.test").is_in_scope("a\n.lab.test"))

    def test_newline_in_target_or_scope_entry_is_a_usage_error(self):
        res = CliRunner().invoke(cli.main, ["-t", "a\n.lab.test", "-o", tempfile.mkdtemp()])
        self.assertEqual(res.exit_code, 2, res.output)
        with self.assertRaises(ValueError):
            ActiveScope.from_option("evil.invalid\n.lab.test,lab.test")



class _HeadersOnlyStatusLine(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_HEAD(self):
        self.wfile.write(b"HTTP/1.0 200 OK\r\n\r\n")
        self.close_connection = True

    def log_message(self, *args):
        pass


class WafStatusLineOnlyTests(unittest.TestCase):
    def test_answer_with_no_headers_counts_as_answered(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _HeadersOnlyStatusLine)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            answered, text = waf_detect._fetch_headers("http", "app.lab.test", "127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertTrue(answered, "a status line with no headers is an answer")
        self.assertEqual(text, "")

    def test_waf_module_counts_a_headerless_answer_as_checked(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="app.lab.test", ip="203.0.113.7", status_code=200))
        with mock.patch.object(waf_detect, "_fetch_headers", return_value=(True, "")):
            res = waf_detect.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertTrue(res.success, res.message)
        self.assertTrue(result.hosts[0].waf_checked)
        self.assertNotIn("did not answer", res.message)


def _stub_dns(answers_by_name):
    """A dnspython Resolver.resolve stand-in: name -> list of A answers, or a callable."""
    import dns.resolver

    def fake_resolve(self, name, rdtype="A", *a, **k):
        value = answers_by_name.get(name)
        if callable(value):
            value = value()
        if not value:
            raise dns.resolver.NXDOMAIN()
        return list(value)

    return mock.patch("dns.resolver.Resolver.resolve", fake_resolve)


def _run_with_real_modules(answers_by_name, scope_entries, skip=()):
    """The real resolve module and every real active module, every sink stubbed.

    Returns (result, terminal text, addresses connected to, text handed to tools).
    """
    from atarus_recon.modules import resolve

    connects = []
    handed = []

    def fake_connect(addr, *a, **k):
        connects.append(addr[0])
        raise OSError("stubbed")

    def fake_run(cmd, **kwargs):
        for flag in ("-l", "-f"):
            if flag in cmd:
                with open(cmd[cmd.index(flag) + 1], encoding="utf-8") as f:
                    handed.append(f.read())
        handed.append(" ".join(cmd))
        return mock.Mock(returncode=1, stdout="", stderr="stubbed")

    def seed(result, scope, rate_limit, verbose):
        for name in answers_by_name:
            if name != "lab.test":
                result.add_host(Host(hostname=name))
        return ModuleResult(True, "seeded")

    r = ReconRunner(target="lab.test", output_dir=tempfile.mkdtemp(), active=True,
                    active_scope=ActiveScope(scope_entries), assume_yes=True,
                    skip=list(skip) or None)
    r.register("Seed", "seed", seed, active=False)
    r.register("DNS resolution", "resolve", resolve.run, active=False)
    for name, key, func, is_active in cli.MODULE_REGISTRY:
        if is_active:
            r.register(name, key, func, active=True)
    out = io.StringIO()
    with _TreatAsPublic("203.0.113.0/24"), _stub_dns(answers_by_name), \
         mock.patch.object(runner_module, "console", Console(file=out, width=300)), \
         mock.patch("socket.create_connection", side_effect=fake_connect), \
         mock.patch.object(subprocess, "run", side_effect=fake_run), \
         mock.patch.object(webprobe, "_find_pd_httpx", return_value="/opt/bin/httpx"), \
         mock.patch("shutil.which", return_value="/opt/bin/tool"):
        result = r.run()
    return result, out.getvalue(), connects, "\n".join(handed)


class EveryARecordTests(unittest.TestCase):
    """Only the first A record was kept and judged, so a name
    with one public and one non-public record passed or failed by record order,
    and the tools that look the name up again could reach the non-public one."""

    def test_resolve_keeps_every_a_record(self):
        from atarus_recon.modules import resolve
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="two.lab.test"))
        with _stub_dns({"two.lab.test": ["203.0.113.11", "127.0.0.1", "203.0.113.11"],
                        "lab.test": ["203.0.113.10"]}):
            resolve.run(result, ScopeValidator("lab.test"), 10, False)
        two = next(h for h in result.hosts if h.hostname == "two.lab.test")
        self.assertEqual(two.ips, ["203.0.113.11", "127.0.0.1"])
        self.assertEqual(two.ip, "203.0.113.11")

    def test_a_mixed_set_is_refused_in_either_order(self):
        s = ActiveScope(["*.lab.test"])
        with _TreatAsPublic("203.0.113.0/24"):
            for ips in (["203.0.113.11", "127.0.0.1"], ["127.0.0.1", "203.0.113.11"]):
                host = Host(hostname="two.lab.test", ip=ips[0], ips=list(ips))
                inside, outside = s.split_hosts([host])
                self.assertEqual(inside, [], ips)
                self.assertIn("127.0.0.1", outside[0][1])
                self.assertIn("loopback", outside[0][1])
            both_public = Host(hostname="ok.lab.test", ip="203.0.113.11", ips=["203.0.113.11", "203.0.113.12"])
            self.assertEqual(s.split_hosts([both_public])[0], [both_public])

    def test_a_network_entry_can_admit_the_non_public_member(self):
        s = ActiveScope(["*.lab.test", "10.20.0.0/16"])
        with _TreatAsPublic("203.0.113.0/24"):
            self.assertTrue(s.covers("mix.lab.test", ips=["203.0.113.11", "10.20.0.5"]))
            self.assertFalse(s.covers("mix.lab.test", ips=["203.0.113.11", "10.30.0.5"]))
        # A name outside the domain entries needs every address inside a network entry.
        n = ActiveScope(["10.20.0.0/16"])
        self.assertTrue(n.covers("a.other.test", ips=["10.20.0.5", "10.20.0.6"]))
        self.assertFalse(n.covers("a.other.test", ips=["10.20.0.5", "10.30.0.6"]))

    def test_no_module_is_handed_a_mixed_name_in_either_order(self):
        for ips in (["203.0.113.11", "127.0.0.1"], ["127.0.0.1", "203.0.113.11"]):
            result, text, connects, handed = _run_with_real_modules(
                {"two.lab.test": ips, "lab.test": None}, ["*.lab.test"])
            self.assertNotIn("two.lab.test", handed, ips)
            self.assertEqual(connects, [], ips)
            skipped = {h["hostname"]: h for h in result.out_of_scope}
            self.assertEqual(skipped["two.lab.test"]["ips"], ips)
            self.assertIn("203.0.113.11, 127.0.0.1" if ips[0] != "127.0.0.1" else "127.0.0.1, 203.0.113.11", text)

    def test_gate_and_report_show_every_address(self):
        result, text, connects, handed = _run_with_real_modules(
            {"ok.lab.test": ["203.0.113.11", "203.0.113.12"], "lab.test": None}, ["*.lab.test"])
        self.assertIn("ok.lab.test -> 203.0.113.11, 203.0.113.12", text)
        self.assertIn("--max-rate 100 203.0.113.11", handed, "nmap is given an approved address")
        with tempfile.TemporaryDirectory() as d:
            with open(html_report.generate(result, d), encoding="utf-8") as f:
                page = f.read()
        self.assertIn("203.0.113.11, 203.0.113.12", page)


class NameResolvingToolsNoteTests(unittest.TestCase):
    """Httpx, nuclei and gowitness are handed names and look
    them up again, so a DNS answer that changes after the gate can move them.
    The gate and the report must say so, and say how to avoid it."""

    def test_gate_and_report_state_the_gap(self):
        result, text, _, _ = _run_with_real_modules(
            {"ok.lab.test": ["203.0.113.11"], "lab.test": None}, ["*.lab.test"])
        flat = " ".join(text.split())
        self.assertIn("httpx, nuclei and gowitness are given the host name", flat)
        self.assertIn("--skip webprobe,nuclei,screenshot", flat)
        self.assertIn("--skip webprobe,nuclei,screenshot", result.scope_note)
        with tempfile.TemporaryDirectory() as d:
            with open(html_report.generate(result, d), encoding="utf-8") as f:
                page = f.read()
        self.assertIn("look the name up again", page)

    def test_note_names_only_the_tools_that_run(self):
        result, text, _, _ = _run_with_real_modules(
            {"ok.lab.test": ["203.0.113.11"], "lab.test": None}, ["*.lab.test"], skip=("nuclei", "screenshot"))
        self.assertIn("httpx is given the host name", " ".join(text.split()))
        result, text, _, _ = _run_with_real_modules(
            {"ok.lab.test": ["203.0.113.11"], "lab.test": None}, ["*.lab.test"],
            skip=("webprobe", "nuclei", "screenshot"))
        self.assertEqual(result.scope_note, "")
        self.assertNotIn("look the name up again", text)


class InternalEngagementPortscanTests(unittest.TestCase):
    """A host admitted by an explicit network entry was listed
    under "Hosts to probe" but nmap skipped it with "No valid public IPs"."""

    def test_nmap_scans_a_private_host_the_network_entry_admits(self):
        result, text, _, handed = _run_with_real_modules(
            {"intra.lab.test": ["10.20.0.5"], "lab.test": None}, ["*.lab.test", "10.20.0.0/16"])
        self.assertIn("intra.lab.test -> 10.20.0.5", text)
        self.assertIn("--max-rate 100 10.20.0.5", handed)
        self.assertNotIn("No valid public IPs", text)

    def test_nmap_is_not_given_a_host_outside_the_scope(self):
        result, text, _, handed = _run_with_real_modules(
            {"intra.lab.test": ["10.20.0.5"], "lab.test": None}, ["*.lab.test"])
        self.assertNotIn("10.20.0.5", handed)
        self.assertIn("private address", text)

    def test_nmap_skips_values_that_are_not_a_host_address(self):
        result = ScanResult(target="lab.test")
        for ip in ("0.0.0.0", "224.0.0.1", "255.255.255.255", "not-an-ip"):
            result.add_host(Host(hostname="x.lab.test", ip=ip))
        with mock.patch.object(portscan.subprocess, "run") as run:
            res = portscan.run(result, ScopeValidator("lab.test"), 10, False)
        run.assert_not_called()
        self.assertFalse(res.success)
        self.assertIn("nmap scans unicast host addresses only", res.message)
        self.assertIn("4", res.message)

    def test_shared_address_space_is_named(self):
        from atarus_recon.scope import non_public_kind
        self.assertEqual(non_public_kind("100.64.1.1"), "shared")
        self.assertIn("shared address", ActiveScope(["*.lab.test"]).exclusion_reason("cg.lab.test", "100.64.1.1"))


class EmbeddedIPv4FormTests(unittest.TestCase):
    """IPv6 forms that carry an IPv4 address, and the Azure
    platform address, passed as public. Not reachable while discovery asks for
    A records only; the rule must already be right if AAAA lookups are added."""

    EMBEDDED = [
        ("::127.0.0.1", "IPv4-compatible"),
        ("::a9fe:a9fe", "IPv4-compatible"),
        ("::cb00:710b", "IPv4-compatible"),
        ("::ffff:0:7f00:1", "IPv4-translated"),
        ("::ffff:0:cb00:710b", "IPv4-translated"),
        ("64:ff9b::7f00:1", "NAT64"),
        ("64:ff9b::a9fe:a9fe", "NAT64"),
        ("64:ff9b::a00:1", "NAT64"),
        ("64:ff9b::cb00:710b", "NAT64"),
    ]

    def test_embedded_forms_are_refused(self):
        from atarus_recon.scope import non_public_kind
        with _TreatAsPublic("203.0.113.0/24"):
            for ip, form in self.EMBEDDED:
                kind = non_public_kind(ip)
                self.assertIn(form, kind, ip)
                self.assertFalse(ScopeValidator.is_valid_ip(ip), ip)
                self.assertFalse(ActiveScope(["*.lab.test"]).covers("v6.lab.test", ip), ip)

    def test_embedded_form_names_the_ipv4_address(self):
        from atarus_recon.scope import non_public_kind
        self.assertIn("127.0.0.1", non_public_kind("64:ff9b::7f00:1"))
        self.assertIn("169.254.169.254", non_public_kind("::a9fe:a9fe"))

    def test_azure_platform_address_is_refused(self):
        from atarus_recon.scope import non_public_kind
        self.assertEqual(non_public_kind("168.63.129.16"), "cloud platform")
        self.assertIn("cloud platform", ActiveScope(["*.lab.test"]).exclusion_reason("az.lab.test", "168.63.129.16"))
        self.assertTrue(ActiveScope(["*.lab.test", "168.63.129.16"]).covers("az.lab.test", "168.63.129.16"))

    def test_a_network_entry_still_opts_in(self):
        self.assertTrue(ActiveScope(["*.lab.test", "64:ff9b::/96"]).covers("v6.lab.test", "64:ff9b::a00:1"))

    def test_plain_forms_unchanged(self):
        from atarus_recon.scope import non_public_kind
        self.assertEqual(non_public_kind("::"), "unspecified")
        self.assertEqual(non_public_kind("::1"), "loopback")
        self.assertEqual(non_public_kind("::ffff:127.0.0.1"), "loopback")
        self.assertEqual(non_public_kind("fd00:ec2::254"), "private")
