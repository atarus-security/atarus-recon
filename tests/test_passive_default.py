"""Tests for the passive default, the scope lock and the confirmation gate.

Standard library plus click's own CliRunner. Every network sink is mocked;
the socket layer is additionally guarded so that no test can reach a real
host by accident.
"""
import contextlib
import io
import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from click.testing import CliRunner
from rich.console import Console

from atarus_recon import cli, scope as scope_module, runner as runner_module
from atarus_recon.models import ScanResult, Host
from atarus_recon.modules import crtsh, subfinder, resolve, whois_asn, credcheck
from atarus_recon.modules import portscan, webprobe, waf_detect, cert_analysis, nuclei_scan, screenshot
from atarus_recon.runner import ModuleResult, ReconRunner
from atarus_recon.scope import ActiveScope, ScopeValidator
from atarus_recon.reports import html


EXPECTED_ACTIVE = ["portscan", "webprobe", "waf", "cert", "nuclei", "screenshot"]
EXPECTED_PASSIVE = ["crtsh", "subfinder", "resolve", "whois", "credcheck", "risk"]


def _network_refused(*args, **kwargs):
    raise AssertionError("a real network call was attempted")


def _quiet_console():
    return mock.patch.object(runner_module, "console", Console(file=io.StringIO(), width=120))


class _FakeAnswer:
    def __init__(self, ip):
        self._ip = ip

    def __str__(self):
        return self._ip


class _FakeResolver:
    """Stands in for dns.resolver.Resolver. Resolves *.lab.test to a public IP."""
    timeout = 0
    lifetime = 0

    def resolve(self, name, rtype):
        if name.endswith("lab.test"):
            return [_FakeAnswer("203.0.113.5")]
        raise resolve.dns.resolver.NXDOMAIN()


class _FakeCrtshResponse:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


class _NetworkGuard:
    """Patches the socket layer so any unmocked connection fails loudly."""

    def __init__(self):
        self._patches = [
            mock.patch.object(socket.socket, "connect", side_effect=_network_refused),
            mock.patch.object(socket.socket, "connect_ex", side_effect=_network_refused),
            mock.patch.object(socket, "create_connection", side_effect=_network_refused),
            mock.patch.object(socket, "getaddrinfo", side_effect=_network_refused),
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


class ModuleClassificationTests(unittest.TestCase):
    def test_registry_marks_target_touching_modules_active(self):
        self.assertEqual(cli.ACTIVE_MODULES, EXPECTED_ACTIVE)
        self.assertEqual(cli.PASSIVE_MODULES, EXPECTED_PASSIVE)


class PassiveDefaultTests(unittest.TestCase):
    def test_passive_default_sends_nothing_to_the_target(self):
        """A bare run: the passive modules work offline against stand-ins, and no
        active sink (nmap, httpx, nuclei, gowitness, the WAF HEAD request, the
        TLS handshake) is ever reached."""
        invoked = []
        crt_body = json.dumps([{"name_value": "app.lab.test\nwww.lab.test"}]).encode()

        def fake_subprocess_run(cmd, *args, **kwargs):
            # subprocess.run is one function shared by every module, so tell the
            # modules apart by the command they issue.
            text = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
            invoked.append(text)
            if "subfinder" in text:
                return mock.Mock(returncode=0, stdout="mail.lab.test\n", stderr="")
            raise AssertionError(f"unexpected external command in passive mode: {text}")

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(crtsh.urllib.request, "urlopen", return_value=_FakeCrtshResponse(crt_body)))
            stack.enter_context(mock.patch.object(subprocess, "run", side_effect=fake_subprocess_run))
            stack.enter_context(mock.patch.object(resolve.dns.resolver, "Resolver", _FakeResolver))
            stack.enter_context(mock.patch.object(whois_asn.shutil, "which", return_value=None))
            stack.enter_context(mock.patch.object(whois_asn, "_whois_python", return_value={}))
            stack.enter_context(mock.patch.object(credcheck, "_request_with_retry", return_value=None))
            stack.enter_context(mock.patch.object(webprobe, "_find_pd_httpx", return_value="/nonexistent/httpx"))
            waf_sink = stack.enter_context(mock.patch.object(waf_detect, "urlopen", side_effect=_network_refused))
            cert_sink = stack.enter_context(mock.patch.object(cert_analysis.socket, "create_connection", side_effect=_network_refused))
            stack.enter_context(_NetworkGuard())
            stack.enter_context(_quiet_console())
            out = stack.enter_context(tempfile.TemporaryDirectory())

            result = CliRunner().invoke(cli.main, ["-t", "lab.test", "--format", "json", "-o", out])
            self.assertEqual(result.exit_code, 0, result.output)
            with open(os.path.join(out, "atarus-recon-lab.test.json")) as f:
                data = json.load(f)

        for binary in ("nmap", "httpx", "nuclei", "gowitness"):
            self.assertFalse(any(binary in c for c in invoked), f"{binary} was invoked in passive mode: {invoked}")
        self.assertTrue(any("subfinder" in c for c in invoked), "the passive subfinder module did run")
        self.assertFalse(waf_sink.called, "the WAF module sent a request in passive mode")
        self.assertFalse(cert_sink.called, "the certificate module opened a connection in passive mode")
        self.assertEqual(data["mode"], "passive")
        self.assertEqual(data["confirmation"], "")
        reasons = {m["module"]: m["reason"] for m in data["modules_not_run"]}
        self.assertEqual([m["module"] for m in data["modules_not_run"] if m["module"] in EXPECTED_ACTIVE], EXPECTED_ACTIVE)
        for key in EXPECTED_ACTIVE:
            self.assertIn("passive mode", reasons[key])
        # The stand-ins for whois and HIBP returned nothing, and a module that
        # could not do its job is a check not made, so both are listed too.
        self.assertEqual(sorted(set(reasons) - set(EXPECTED_ACTIVE)), ["credcheck", "whois"])
        self.assertIn("WHOIS lookup returned no data", reasons["whois"])
        # A new network sink would trip the socket guard inside a module, which
        # the runner records as a crash; none may appear.
        self.assertFalse([r for r in reasons.values() if r.startswith("module crashed")], reasons)
        # The passive modules still did their job.
        names = [h["hostname"] for h in data["hosts"]]
        self.assertIn("app.lab.test", names)
        self.assertIn("mail.lab.test", names)
        self.assertTrue(all(h["ip"] == "203.0.113.5" for h in data["hosts"]))

    def test_active_without_scope_exits_with_an_error(self):
        with mock.patch.object(ReconRunner, "run", side_effect=AssertionError("runner must not start")):
            result = CliRunner().invoke(cli.main, ["-t", "lab.test", "--active"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("--scope", result.output)

    def test_yes_without_scope_exits_with_an_error(self):
        with mock.patch.object(ReconRunner, "run", side_effect=AssertionError("runner must not start")):
            result = CliRunner().invoke(cli.main, ["-t", "lab.test", "--yes"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("--scope", result.output)

    def test_only_with_active_module_needs_active_flag(self):
        with mock.patch.object(ReconRunner, "run", side_effect=AssertionError("runner must not start")):
            result = CliRunner().invoke(cli.main, ["-t", "lab.test", "--only", "crtsh,nuclei"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("nuclei", result.output)
        self.assertIn("--active", result.output)

    def test_active_without_terminal_or_yes_exits_with_an_error(self):
        with mock.patch.object(cli, "tty_available", return_value=False), \
             mock.patch.object(ReconRunner, "run", side_effect=AssertionError("runner must not start")):
            result = CliRunner().invoke(cli.main, ["-t", "lab.test", "--active", "--scope", "lab.test"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("terminal", result.output)

    def test_bad_scope_entry_exits_with_an_error(self):
        with mock.patch.object(ReconRunner, "run", side_effect=AssertionError("runner must not start")):
            result = CliRunner().invoke(cli.main, ["-t", "lab.test", "--active", "--yes", "--scope", "not a host"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("not a host", result.output)


class ActiveScopeTests(unittest.TestCase):
    def test_entry_forms(self):
        s = ActiveScope(["app.lab.test", "*.corp.test", "203.0.113.7", "198.51.100.0/24", "https://Portal.lab.test:8443/x"])
        self.assertEqual(s.entries, ["app.lab.test", "*.corp.test", "203.0.113.7", "198.51.100.0/24", "portal.lab.test"])
        self.assertTrue(s.covers("app.lab.test", "192.0.2.1"))
        self.assertTrue(s.covers("APP.lab.test.", ""))
        self.assertFalse(s.covers("www.app.lab.test", "192.0.2.1"), "a host entry is exact")
        self.assertTrue(s.covers("a.b.corp.test", ""), "a domain entry covers any depth")
        self.assertFalse(s.covers("corp.test", ""), "a domain entry does not cover the apex")
        self.assertTrue(s.covers("anything.example", "203.0.113.7"))
        self.assertTrue(s.covers("anything.example", "198.51.100.200"))
        self.assertFalse(s.covers("anything.example", "198.51.101.1"))
        self.assertFalse(s.covers("anything.example", "not-an-ip"))

    def test_scope_file_with_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# client scope\n\n*.lab.test\n203.0.113.0/24  # office range\n")
            path = f.name
        try:
            s = ActiveScope.from_option(path)
        finally:
            os.unlink(path)
        self.assertEqual(s.entries, ["*.lab.test", "203.0.113.0/24"])

    def test_list_form_and_errors(self):
        self.assertEqual(ActiveScope.from_option("lab.test, *.lab.test").entries, ["lab.test", "*.lab.test"])
        with self.assertRaises(ValueError):
            ActiveScope.from_option("")
        with self.assertRaises(ValueError):
            ActiveScope.from_option("lab.test,bad_label.test")
        with self.assertRaises(ValueError):
            ActiveScope.from_option("localhost")


def _seed(hosts):
    """A passive stub module that adds the given (hostname, ip) pairs."""
    def run(result, scope, rate_limit, verbose):
        for hostname, ip in hosts:
            result.add_host(Host(hostname=hostname, ip=ip))
        return ModuleResult(success=True, message="seeded")
    return run


class _Probe:
    """An active stub module that records which hosts it was handed."""
    def __init__(self):
        self.calls = []

    def run(self, result, scope, rate_limit, verbose):
        self.calls.append([h.hostname for h in result.hosts])
        return ModuleResult(success=True, message="probed")


SEED_HOSTS = [("app.lab.test", "203.0.113.5"), ("cdn.lab.test", "198.51.100.7"), ("dead.lab.test", "")]


def _make_runner(active, assume_yes, scope_entries=("203.0.113.0/24",)):
    runner = ReconRunner(
        target="lab.test", output_dir=".", active=active,
        active_scope=ActiveScope(list(scope_entries)) if active else None,
        assume_yes=assume_yes,
    )
    probe = _Probe()
    runner.register("Seed", "seed", _seed(SEED_HOSTS), active=False)
    runner.register("Probe", "probe", probe.run, active=True)
    runner.register("Second probe", "probe2", probe.run, active=True)
    return runner, probe


class ScopeEnforcementTests(unittest.TestCase):
    def test_out_of_scope_hosts_are_skipped_and_reported(self):
        runner, probe = _make_runner(active=True, assume_yes=True)
        with _quiet_console(), _NetworkGuard():
            result = runner.run()
        self.assertEqual(probe.calls, [["app.lab.test"], ["app.lab.test"]])
        self.assertEqual(result.out_of_scope, [{"hostname": "cdn.lab.test", "ip": "198.51.100.7"}])
        self.assertEqual(len(result.hosts), 3, "the full host list is restored after each active module")
        self.assertEqual(result.mode, "active")
        self.assertEqual(result.active_scope, ["203.0.113.0/24"])
        self.assertIn("--yes", result.confirmation)
        self.assertEqual(result.modules_not_run, [])

    def test_name_scope_covers_by_name(self):
        runner, probe = _make_runner(active=True, assume_yes=True, scope_entries=("*.lab.test",))
        with _quiet_console(), _NetworkGuard():
            result = runner.run()
        self.assertEqual(probe.calls[0], ["app.lab.test", "cdn.lab.test"])
        self.assertEqual(result.out_of_scope, [])

    def test_nothing_in_scope_means_no_probe(self):
        runner, probe = _make_runner(active=True, assume_yes=True, scope_entries=("192.0.2.0/24",))
        with _quiet_console(), _NetworkGuard():
            result = runner.run()
        self.assertEqual(probe.calls, [])
        self.assertEqual([m["module"] for m in result.modules_not_run], ["probe", "probe2"])
        self.assertIn("no resolved host inside --scope", result.modules_not_run[0]["reason"])

    def test_passive_runner_never_calls_active_modules(self):
        runner, probe = _make_runner(active=False, assume_yes=False)
        with _quiet_console(), _NetworkGuard():
            result = runner.run()
        self.assertEqual(probe.calls, [])
        self.assertEqual(result.mode, "passive")
        self.assertEqual([m["module"] for m in result.modules_not_run], ["probe", "probe2"])

    def test_skipped_modules_are_recorded_as_not_run(self):
        runner, probe = _make_runner(active=True, assume_yes=True)
        runner.skip = ["probe2"]
        with _quiet_console(), _NetworkGuard():
            result = runner.run()
        self.assertEqual(probe.calls, [["app.lab.test"]])
        self.assertEqual(result.modules_not_run, [{"module": "probe2", "name": "Second probe", "reason": "skipped with --skip or --only"}])

    def test_active_runner_requires_a_scope(self):
        with self.assertRaises(ValueError):
            ReconRunner(target="lab.test", output_dir=".", active=True)


class ConfirmationGateTests(unittest.TestCase):
    def _run_with_answer(self, answer):
        runner, probe = _make_runner(active=True, assume_yes=False)
        with _quiet_console(), _NetworkGuard(), \
             mock.patch.object(runner_module, "read_tty_line", return_value=answer) as reader:
            result = runner.run()
        return result, probe, reader

    def test_gate_blocks_when_the_word_is_not_yes(self):
        for answer in ("", "no", "y", "YES please", "yes\x00"):
            result, probe, reader = self._run_with_answer(answer)
            self.assertEqual(probe.calls, [], f"probe ran after answer {answer!r}")
            self.assertEqual(reader.call_count, 1, "the gate asks once, not once per module")
            self.assertEqual([m["module"] for m in result.modules_not_run], ["probe", "probe2"])
            self.assertIn("confirmation not given", result.modules_not_run[0]["reason"])
            self.assertEqual(result.confirmation, "")

    def test_gate_blocks_without_a_terminal(self):
        result, probe, _ = self._run_with_answer(None)
        self.assertEqual(probe.calls, [])
        self.assertIn("no terminal", result.modules_not_run[0]["reason"])

    def test_gate_opens_on_yes(self):
        result, probe, reader = self._run_with_answer("yes")
        self.assertEqual(probe.calls, [["app.lab.test"], ["app.lab.test"]])
        self.assertEqual(result.confirmation, "typed yes on the terminal")
        prompt = reader.call_args[0][0]
        self.assertIn("203.0.113.0/24", prompt)

    def test_environment_cannot_open_the_gate(self):
        env = {"ATARUS_YES": "1", "ATARUS_RECON_YES": "yes", "ATARUS_RECON_ACTIVE": "1", "CI": "true", "YES": "yes"}
        with mock.patch.dict(os.environ, env):
            result, probe, _ = self._run_with_answer("no")
        self.assertEqual(probe.calls, [])
        self.assertEqual(result.confirmation, "")

    def test_read_tty_line_never_reads_stdin(self):
        with mock.patch.object(scope_module, "TTY_PATH", os.path.join(tempfile.gettempdir(), "atarus-no-such-tty")), \
             mock.patch.object(sys, "stdin", io.StringIO("yes\n")):
            self.assertIsNone(scope_module.read_tty_line("confirm: "))
            self.assertFalse(scope_module.tty_available())

    def test_read_tty_line_reads_the_terminal_device(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("yes\n")
            path = f.name
        try:
            with mock.patch.object(scope_module, "TTY_PATH", path):
                self.assertTrue(scope_module.tty_available())
                self.assertEqual(scope_module.read_tty_line(""), "yes")
        finally:
            os.unlink(path)


class PassiveReportTests(unittest.TestCase):
    def test_passive_report_does_not_read_as_clean(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5"))
        result.modules_not_run.append({"module": "nuclei", "name": "Nuclei vulnerability scan",
                                       "reason": "passive mode; add --active and --scope to run it"})
        result.out_of_scope.append({"hostname": "cdn.lab.test", "ip": "198.51.100.7"})
        result.finalize()
        with tempfile.TemporaryDirectory() as d:
            with open(html.generate(result, d)) as f:
                content = f.read()
        self.assertIn("passive", content)
        self.assertIn("no packets were sent", content)
        self.assertIn("Nuclei was not run", content)
        self.assertNotIn("No vulnerabilities detected", content)
        self.assertIn("Out of scope, not probed", content)
        self.assertIn("cdn.lab.test", content)
        self.assertIn("atarus-recon v0.6.0", content)


class FailedModuleTests(unittest.TestCase):
    """A module that returns success=False, or raises, is a check not made: it goes
    in modules_not_run and the terminal and HTML say not run, never clean."""

    def _run_with(self, func, key="nuclei", name="Nuclei vulnerability scan"):
        runner = ReconRunner(target="lab.test", output_dir=".")
        runner.register("Seed", "seed", _seed(SEED_HOSTS), active=False)
        runner.register(name, key, func, active=False)
        sink = io.StringIO()
        with mock.patch.object(runner_module, "console", Console(file=sink, width=200)), _NetworkGuard():
            result = runner.run()
        return result, sink.getvalue()

    def test_failed_module_is_recorded_and_the_report_says_not_run(self):
        def failing(result, scope, rate_limit, verbose):
            return ModuleResult(success=False, message="nuclei exited with code 1; check not completed. no templates provided")

        result, text = self._run_with(failing)
        self.assertEqual(result.modules_not_run, [
            {"module": "nuclei", "name": "Nuclei vulnerability scan",
             "reason": "nuclei exited with code 1; check not completed. no templates provided"},
        ])
        self.assertIn("not run", text)
        self.assertNotIn("warn", text)
        self.assertIn("Modules not run: nuclei", text)
        with tempfile.TemporaryDirectory() as d:
            with open(html.generate(result, d)) as f:
                content = f.read()
        self.assertIn("Nuclei was not run (nuclei exited with code 1", content)
        self.assertNotIn("No vulnerabilities detected", content)

    def test_crashed_module_is_recorded_as_not_run(self):
        def crashing(result, scope, rate_limit, verbose):
            raise RuntimeError("boom")

        result, text = self._run_with(crashing, key="portscan", name="Port scan")
        self.assertEqual([m["module"] for m in result.modules_not_run], ["portscan"])
        self.assertIn("module crashed: RuntimeError: boom", result.modules_not_run[0]["reason"])
        self.assertIn("fail", text)

    def test_httpx_no_output_reaches_the_report(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5"))
        with mock.patch.object(webprobe, "_find_pd_httpx", return_value="/opt/bin/httpx"), \
             mock.patch.object(webprobe.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")):
            res = webprobe.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertFalse(res.success)
        self.assertIn("httpx produced no output", res.message)


class TerminalEscapeTests(unittest.TestCase):
    """Text that came from the target is inert on the terminal: rich markup is
    shown literally and control characters are shown as escapes."""

    def _run(self, hosts, message):
        runner = ReconRunner(target="lab.test", output_dir=".", active=True,
                             active_scope=ActiveScope(["203.0.113.0/24"]), assume_yes=True)
        runner.register("Seed", "seed", _seed(hosts), active=False)
        runner.register("WHOIS lookup", "whois", lambda r, s, rl, v: ModuleResult(True, message), active=False)
        runner.register("Probe", "probe", _Probe().run, active=True)
        sink = io.StringIO()
        with mock.patch.object(runner_module, "console", Console(file=sink, width=200)), _NetworkGuard():
            runner.run()
        return sink.getvalue()

    def test_markup_in_a_host_name_is_shown_not_interpreted(self):
        text = self._run([("[red]evil[/red].lab.test", "203.0.113.9")], "Registrar: fine")
        self.assertIn("[red]evil[/red].lab.test", text)

    def test_control_characters_in_a_module_message_are_escaped(self):
        text = self._run(SEED_HOSTS, "Registrar: [bold red]owned[/] \x1b[2J\x1b]0;pwned\x07 Org: \u202ereversed")
        self.assertIn("Registrar: [bold red]owned[/] \\x1b[2J\\x1b]0;pwned\\x07 Org: \\u202ereversed", text)
        for ch in text:
            self.assertTrue(ord(ch) >= 0x20 or ch == "\n", f"control character reached the terminal: {ch!r}")

    def test_safe_text_matches_the_vendored_behaviour(self):
        self.assertEqual(scope_module.safe_text("PHP/8.2.0\x1b[2J\x1b]0;owned\x07"), "PHP/8.2.0\\x1b[2J\\x1b]0;owned\\x07")
        self.assertEqual(scope_module.safe_text("a\r\nb\tc"), "a b c")
        self.assertEqual(scope_module.safe_text("x\x7fy\x9bz"), "x\\x7fy\\x9bz")
        self.assertEqual(scope_module.safe_text("abcdefghij", 5), "abcde [cut]")
        self.assertEqual(scope_module.safe_text(None), "")


def _pty_supported():
    try:
        import pty  # noqa: F401
    except ImportError:
        return False
    return hasattr(os, "fork") and sys.platform != "win32"


class PseudoTerminalGateTests(unittest.TestCase):
    """The gate on a real terminal. The child of pty.fork has the pseudo-terminal
    as its controlling terminal, so /dev/tty is the real path here, not a file
    standing in for it; a regression in how the terminal is opened (the
    0.6.0 r+ bug) fails these tests."""

    PROMPT_MARK = b"Type yes to"
    DEADLINE = 30

    def _in_pty(self, child, answer):
        """Run child() in a pty.fork child, answer the prompt, return (output, exit code).

        child() returns the text the child prints after the prompt was answered."""
        import pty
        try:
            pid, fd = pty.fork()
        except OSError as e:
            self.skipTest(f"pseudo-terminal not available: {e}")
        if pid == 0:
            code = 3
            try:
                text = child()
                os.write(1, ("\nRESULT=" + text + "\n").encode("utf-8", "replace"))
                code = 0
            except BaseException as e:  # noqa: BLE001
                try:
                    os.write(1, f"\nCHILD ERROR {e!r}\n".encode("utf-8", "replace"))
                except OSError:
                    pass
            finally:
                os._exit(code)

        out = b""
        answered = False
        status = None
        deadline = time.time() + self.DEADLINE
        try:
            while time.time() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break  # EIO once the child has closed its side (Linux)
                    if not chunk:
                        break  # EOF (macOS)
                    out += chunk
                    if not answered and self.PROMPT_MARK in out:
                        os.write(fd, answer.encode() + b"\n")
                        answered = True
                    continue
                done, st = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = st
                    # Drain whatever is left.
                    while True:
                        ready, _, _ = select.select([fd], [], [], 0.2)
                        if not ready:
                            break
                        try:
                            chunk = os.read(fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        out += chunk
                    break
            else:
                os.kill(pid, 9)
                self.fail(f"child did not finish in {self.DEADLINE}s; output so far: {out!r}")
            if status is None:
                _, status = os.waitpid(pid, 0)
        finally:
            os.close(fd)
        return out.decode("utf-8", "replace"), os.waitstatus_to_exitcode(status)

    @unittest.skipUnless(_pty_supported(), "needs a POSIX pseudo-terminal")
    def test_read_tty_line_reads_from_the_real_controlling_terminal(self):
        def child():
            available = scope_module.tty_available()
            line = scope_module.read_tty_line("Type yes to continue: ")
            return f"available={available} line={line!r}"

        for answer in ("yes", "no"):
            out, code = self._in_pty(child, answer)
            self.assertEqual(code, 0, out)
            self.assertIn("Type yes to continue:", out, "the prompt must be written to the terminal")
            self.assertIn(f"RESULT=available=True line={answer!r}", out)

    @unittest.skipUnless(_pty_supported(), "needs a POSIX pseudo-terminal")
    def test_gate_opens_on_yes_and_blocks_on_no_typed_on_a_terminal(self):
        def child():
            runner, probe = _make_runner(active=True, assume_yes=False)
            result = runner.run()
            return f"confirmation={result.confirmation!r} probed={probe.calls!r} not_run={[m['module'] for m in result.modules_not_run]!r}"

        out, code = self._in_pty(child, "yes")
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT=confirmation='typed yes on the terminal' probed=[['app.lab.test'], ['app.lab.test']] not_run=[]", out)

        out, code = self._in_pty(child, "no")
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT=confirmation='' probed=[] not_run=['probe', 'probe2']", out)


if __name__ == "__main__":
    unittest.main()
