"""Offline unit tests for atarus-recon. Standard library only, no network."""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from atarus_recon.models import ScanResult, Host, Port, Finding, BreachExposure
from atarus_recon.scope import ScopeValidator
from atarus_recon.modules import nuclei_scan, credcheck, risk_score, screenshot, portscan
from atarus_recon.reports import html, json_export


class ScopeTests(unittest.TestCase):
    def test_clean_target(self):
        self.assertEqual(ScopeValidator("https://Example.com:443/path").target, "example.com")

    def test_in_scope(self):
        s = ScopeValidator("example.com")
        self.assertTrue(s.is_in_scope("api.example.com"))
        self.assertTrue(s.is_in_scope("example.com."))
        self.assertFalse(s.is_in_scope("example.com.evil.net"))
        self.assertFalse(s.is_in_scope("notexample.com"))

    def test_validate_target(self):
        self.assertTrue(ScopeValidator("lab.test").validate_target())
        self.assertTrue(ScopeValidator("xn--bcher-kva.example").validate_target())
        self.assertFalse(ScopeValidator("localhost").validate_target())
        self.assertFalse(ScopeValidator("bad_label.com").validate_target())

    def test_private_ips_rejected_for_active_scans(self):
        self.assertFalse(ScopeValidator.is_valid_ip("10.0.0.1"))
        self.assertFalse(ScopeValidator.is_valid_ip("127.0.0.1"))
        self.assertTrue(ScopeValidator.is_valid_ip("8.8.8.8"))


class NucleiTests(unittest.TestCase):
    """nuclei runs as an argument list and any failure is a check not made, never a clean result."""

    RECORDS = [
        {"template-id": "git-config", "host": "https://lab.test", "matched-at": "https://lab.test/.git/config",
         "info": {"severity": "medium", "name": "Git Configuration", "description": "d"}},
        {"template-id": "tech-detect", "host": "https://lab.test", "info": {"severity": "info"}},
    ]

    def _run(self, returncode=0, stderr="", records=None, side_effect=None, binary="/opt/bin/nuclei"):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5", status_code=200))
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            if side_effect is not None:
                raise side_effect
            out = cmd[cmd.index("-o") + 1]
            with open(out, "w") as f:
                f.write("\n".join(json.dumps(r) for r in (records or [])))
            return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

        with mock.patch.object(nuclei_scan, "_find_nuclei", return_value=binary), \
             mock.patch.object(nuclei_scan.subprocess, "run", side_effect=fake_run):
            res = nuclei_scan.run(result, ScopeValidator("lab.test"), 10, False)
        return res, result, seen

    def test_runs_as_an_argument_list_with_the_v3_flags_and_parses_jsonl(self):
        res, result, seen = self._run(records=self.RECORDS)
        cmd = seen["cmd"]
        self.assertIsInstance(cmd, list, "nuclei must be run as an argv list, never a shell string")
        self.assertEqual(cmd[0], "/opt/bin/nuclei")
        self.assertNotIn("shell", seen["kwargs"])
        self.assertTrue(seen["kwargs"].get("capture_output"), "stderr must be captured, not discarded")
        for flag in ("-jsonl", "-disable-update-check", "-ni", "-disable-redirects", "-o", "-l"):
            self.assertIn(flag, cmd)
        for gone in ("-json", "-no-update-templates"):
            self.assertNotIn(gone, cmd)
        self.assertTrue(res.success, res.message)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.hosts[0].findings[0].template_id, "git-config")

    def test_non_zero_exit_is_not_run_with_the_stderr_tail(self):
        res, result, _ = self._run(returncode=1, stderr="[FTL] Could not run nuclei: no templates provided")
        self.assertFalse(res.success)
        self.assertIn("exited with code 1", res.message)
        self.assertIn("not completed", res.message)
        self.assertIn("no templates provided", res.message)
        self.assertNotIn("No vulnerabilities", res.message)
        self.assertEqual(result.findings, [])

    def test_missing_binary_is_not_run(self):
        res, _, seen = self._run(binary="")
        self.assertFalse(res.success)
        self.assertIn("nuclei not found", res.message)
        self.assertNotIn("cmd", seen, "nothing is executed when nuclei is absent")

        res, _, _ = self._run(side_effect=FileNotFoundError("nuclei"))
        self.assertFalse(res.success)
        self.assertIn("could not be started", res.message)

    def test_timeout_is_not_run(self):
        res, _, _ = self._run(side_effect=nuclei_scan.subprocess.TimeoutExpired(cmd="nuclei", timeout=600))
        self.assertFalse(res.success)
        self.assertIn("timed out", res.message)
        self.assertIn("not completed", res.message)

    def test_empty_output_with_exit_0_is_clean_with_an_honest_detail(self):
        res, result, _ = self._run(returncode=0, records=[])
        self.assertTrue(res.success, res.message)
        self.assertEqual(res.message, "nuclei exited 0 with no findings; template load not verified")
        self.assertEqual(result.nuclei_detail, res.message)
        self.assertEqual(result.findings, [])

    def test_empty_output_with_no_templates_on_stderr_is_not_run(self):
        for stderr in ("[WRN] No templates provided for scan", "[INF] 0 templates loaded for current scan"):
            res, result, _ = self._run(returncode=0, records=[], stderr=stderr)
            self.assertFalse(res.success, stderr)
            self.assertIn("loaded no templates", res.message)
            self.assertIn("no check was made", res.message)
            self.assertEqual(result.nuclei_detail, "")
            self.assertEqual(result.findings, [])


class NmapTests(unittest.TestCase):
    """nmap's exit code is checked; a failure is a check not made, never zero open ports."""

    NMAP_XML = (
        '<?xml version="1.0"?><nmaprun><host><address addr="11.22.33.44"/><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.2"/></port>'
        '</ports></host></nmaprun>'
    )

    def _run(self, returncode=0, stderr="", side_effect=None, xml=None):
        # 203.0.113.0/24 is documentation space, which ipaddress treats as
        # private and the module refuses to scan; nothing is sent here anyway,
        # subprocess.run is replaced.
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="11.22.33.44"))
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            if side_effect is not None:
                raise side_effect
            with open(cmd[cmd.index("-oX") + 1], "w") as f:
                f.write(xml if xml is not None else self.NMAP_XML)
            return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

        with mock.patch.object(portscan.subprocess, "run", side_effect=fake_run):
            res = portscan.run(result, ScopeValidator("lab.test"), 10, False)
        return res, result, seen

    def test_clean_exit_parses_ports(self):
        res, result, seen = self._run()
        self.assertIsInstance(seen["cmd"], list)
        self.assertTrue(res.success, res.message)
        self.assertEqual([p.number for p in result.hosts[0].ports], [443])

    def test_non_zero_exit_is_not_run(self):
        res, result, _ = self._run(returncode=1, stderr="nmap: unable to open socket", xml="")
        self.assertFalse(res.success)
        self.assertIn("exited with code 1", res.message)
        self.assertIn("11.22.33.44", res.message)
        self.assertIn("unknown", res.message)
        self.assertIn("unable to open socket", res.message)
        self.assertEqual(result.hosts[0].ports, [])

    def test_missing_binary_is_not_run(self):
        res, _, _ = self._run(side_effect=FileNotFoundError("nmap"))
        self.assertFalse(res.success)
        self.assertIn("nmap could not be started", res.message)

    def test_timeout_is_not_run(self):
        res, _, _ = self._run(side_effect=portscan.subprocess.TimeoutExpired(cmd="nmap", timeout=300))
        self.assertFalse(res.success)
        self.assertIn("timed out", res.message)


class GowitnessTests(unittest.TestCase):
    """gowitness's exit code is checked; a failure is a check not made, never zero screenshots."""

    def _run(self, returncode=0, stderr="", side_effect=None):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5", status_code=200))
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            if side_effect is not None:
                raise side_effect
            return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"ATARUS_OUTPUT_DIR": d}), \
             mock.patch.object(screenshot.subprocess, "run", side_effect=fake_run):
            res = screenshot.run(result, ScopeValidator("lab.test"), 10, False)
        return res, seen

    def test_clean_exit_counts_captures(self):
        res, seen = self._run()
        self.assertIsInstance(seen["cmd"], list)
        self.assertTrue(res.success, res.message)
        self.assertIn("Captured 0 screenshots", res.message)

    def test_non_zero_exit_is_not_run(self):
        res, _ = self._run(returncode=2, stderr="could not find chrome")
        self.assertFalse(res.success)
        self.assertIn("exited with code 2", res.message)
        self.assertIn("not captured", res.message)
        self.assertIn("could not find chrome", res.message)

    def test_missing_binary_is_not_run(self):
        res, _ = self._run(side_effect=FileNotFoundError("gowitness"))
        self.assertFalse(res.success)
        self.assertIn("gowitness could not be started", res.message)

    def test_timeout_is_not_run(self):
        res, _ = self._run(side_effect=screenshot.subprocess.TimeoutExpired(cmd="gowitness", timeout=300))
        self.assertFalse(res.success)
        self.assertIn("timed out", res.message)


class CredcheckTests(unittest.TestCase):
    def test_no_breaches_is_clean(self):
        self.assertEqual(credcheck._compute_hygiene_score([]), (100, "clean"))

    def test_large_recent_breach_lowers_score(self):
        b = BreachExposure(name="X", breach_date="2026-01-01", pwn_count=200_000_000,
                           data_classes=["Passwords"], is_sensitive=True)
        score, rating = credcheck._compute_hygiene_score([b])
        self.assertLess(score, 60)
        self.assertIn(rating, ("poor", "critical", "severe"))

    def test_description_html_stripped(self):
        self.assertEqual(credcheck._clean_description("<a href='x'>Hi</a>  there"), "Hi there")


class RiskAndScreenshotTests(unittest.TestCase):
    def test_risk_scoring(self):
        result = ScanResult(target="lab.test")
        h = Host(hostname="lab.test", ip="203.0.113.5", status_code=200)
        h.ports = [Port(number=3389)]
        h.findings = [Finding(title="x", severity="high")]
        result.add_host(h)
        risk_score.run(result, ScopeValidator("lab.test"), 10, False)
        self.assertEqual(h.risk_score, 5 + 15 + 10 + 25)
        self.assertEqual(h.risk_level, "high")

    def test_gowitness_filename_parsing(self):
        self.assertEqual(screenshot._extract_hostname_from_filename("https---app.lab.test-443.png"), "app.lab.test")
        self.assertEqual(screenshot._extract_hostname_from_filename("http---lab.test.png"), "lab.test")


class ReportTests(unittest.TestCase):
    def test_html_and_json_reports_render_from_package(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5", status_code=200, title="<script>x</script>"))
        result.finalize()
        with tempfile.TemporaryDirectory() as d:
            html_path = html.generate(result, d)
            with open(html_path) as f:
                content = f.read()
            self.assertIn("lab.test", content)
            self.assertNotIn("<script>x</script>", content)
            json_path = json_export.generate(result, d)
            with open(json_path) as f:
                self.assertEqual(json.load(f)["target"], "lab.test")

    def test_template_ships_inside_package(self):
        import atarus_recon
        pkg = os.path.dirname(atarus_recon.__file__)
        self.assertTrue(os.path.exists(os.path.join(pkg, "templates", "report.html")))


if __name__ == "__main__":
    unittest.main()
