"""Offline unit tests for atarus-recon. Standard library only, no network."""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from atarus_recon.models import ScanResult, Host, Port, Finding, BreachExposure
from atarus_recon.scope import ScopeValidator
from atarus_recon.modules import nuclei_scan, credcheck, risk_score, screenshot
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
    def test_uses_nuclei_v3_flags_and_parses_jsonl(self):
        result = ScanResult(target="lab.test")
        result.add_host(Host(hostname="lab.test", ip="203.0.113.5", status_code=200))
        records = [
            {"template-id": "git-config", "host": "https://lab.test", "matched-at": "https://lab.test/.git/config",
             "info": {"severity": "medium", "name": "Git Configuration", "description": "d"}},
            {"template-id": "tech-detect", "host": "https://lab.test", "info": {"severity": "info"}},
        ]
        seen = {}

        def fake_run(cmd, shell, timeout, env):
            seen["cmd"] = cmd
            out = re.search(r"> (\S+) 2>/dev/null", cmd).group(1)
            with open(out, "w") as f:
                f.write("\n".join(json.dumps(r) for r in records))

        with mock.patch.object(nuclei_scan.subprocess, "run", side_effect=fake_run):
            res = nuclei_scan.run(result, ScopeValidator("lab.test"), 10, False)

        self.assertIn("-jsonl", seen["cmd"].split())
        self.assertIn("-disable-update-check", seen["cmd"].split())
        self.assertNotIn("-json", seen["cmd"].split())
        self.assertNotIn("-no-update-templates", seen["cmd"].split())
        self.assertTrue(res.success)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.hosts[0].findings[0].template_id, "git-config")


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
