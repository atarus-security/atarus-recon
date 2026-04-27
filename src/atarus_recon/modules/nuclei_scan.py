import subprocess
import json
import os
import tempfile
from urllib.parse import urlparse
from atarus_recon.models import ScanResult, Finding
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Run nuclei vulnerability scanner against discovered web hosts"""

    web_hosts = [h for h in result.hosts if h.ip and h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="No web hosts to scan")

    nuclei_path = os.path.expanduser("~/go/bin/nuclei")
    if not os.path.exists(nuclei_path):
        nuclei_path = "nuclei"

    fd, url_file = tempfile.mkstemp(suffix=".txt")
    output_file = tempfile.mktemp(suffix=".jsonl")

    try:
        with os.fdopen(fd, "w") as f:
            for host in web_hosts:
                has_443 = any(p.number == 443 for p in host.ports)
                scheme = "https" if has_443 or host.status_code == 200 else "http"
                f.write(f"{scheme}://{host.hostname}\n")

        shell_cmd = (
            f"{nuclei_path} -l {url_file} "
            f"-severity low,medium,high,critical "
            f"-silent -json "
            f"-rate-limit {rate_limit * 5} "
            f"-timeout 10 "
            f"-no-update-templates "
            f"> {output_file} 2>/dev/null"
        )

        env = os.environ.copy()
        env["PATH"] = os.path.expanduser("~/go/bin") + ":" + env.get("PATH", "")

        subprocess.run(shell_cmd, shell=True, timeout=600, env=env)

        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            return ModuleResult(success=True, message="No vulnerabilities found")

        with open(output_file, "r") as f:
            output_lines = f.read().strip().split("\n")

        if verbose:
            print(f"  nuclei results: {len(output_lines)} findings")

    except subprocess.TimeoutExpired:
        return ModuleResult(success=False, message="nuclei timed out (10 min limit)")
    except FileNotFoundError:
        return ModuleResult(success=False, message="nuclei not found")
    finally:
        for path in [url_file, output_file]:
            if os.path.exists(path):
                os.remove(path)

    host_map = {h.hostname.lower(): h for h in web_hosts}
    total_findings = 0

    for line in output_lines:
        if not line.strip():
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        matched_host = _match_finding_to_host(entry, host_map)

        info = entry.get("info", {})
        severity = info.get("severity", "info")
        if severity == "info":
            continue

        finding = Finding(
            title=entry.get("template-id", info.get("name", "Unknown")),
            severity=severity,
            description=info.get("description", ""),
            url=entry.get("matched-at", entry.get("host", "")),
            matcher_name=entry.get("matcher-name", ""),
            template_id=entry.get("template-id", ""),
        )

        result.findings.append(finding)
        total_findings += 1

        if matched_host:
            matched_host.findings.append(finding)

    return ModuleResult(success=True, message=f"Found {total_findings} vulnerabilities")


def _match_finding_to_host(entry: dict, host_map: dict):
    """Exact-match a nuclei finding to a host. Avoids substring collisions
    like api.example.com matching internal-api.example.com."""
    candidates = []

    host_str = entry.get("host", "")
    if host_str:
        try:
            if "://" in host_str:
                parsed = urlparse(host_str)
                if parsed.hostname:
                    candidates.append(parsed.hostname.lower())
            else:
                candidates.append(host_str.lower().split(":")[0])
        except Exception:
            pass

    matched_at = entry.get("matched-at", "")
    if matched_at:
        try:
            parsed = urlparse(matched_at)
            if parsed.hostname:
                candidates.append(parsed.hostname.lower())
        except Exception:
            pass

    for c in candidates:
        if c in host_map:
            return host_map[c]

    return None
