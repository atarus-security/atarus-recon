import subprocess
import json
import os
import tempfile
import shutil
from urllib.parse import urlparse
from atarus_recon.models import ScanResult, Technology
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Probe alive hosts with ProjectDiscovery httpx for web service details"""
    alive_hosts = [h for h in result.hosts if h.ip]
    if not alive_hosts:
        return ModuleResult(success=False, message="No alive hosts to probe")

    httpx_path = _find_pd_httpx()
    if not httpx_path:
        return ModuleResult(
            success=False,
            message="ProjectDiscovery httpx not found. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )

    if verbose:
        print(f"  using httpx binary: {httpx_path}")

    fd, host_file = tempfile.mkstemp(suffix=".txt")
    output_file = tempfile.mktemp(suffix=".jsonl")

    try:
        with os.fdopen(fd, "w") as f:
            for h in alive_hosts:
                f.write(h.hostname + "\n")

        shell_cmd = (
            f"cat {host_file} | {httpx_path} "
            f"-status-code -title -tech-detect -follow-redirects "
            f"-silent -json -rate-limit {rate_limit} "
            f"-timeout 10 "
            f"> {output_file} 2>/dev/null"
        )

        env = os.environ.copy()
        env["PATH"] = env.get("PATH", "") + ":" + os.path.expanduser("~/go/bin")

        subprocess.run(shell_cmd, shell=True, timeout=180, env=env)

        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            return ModuleResult(success=False, message="httpx produced no output")

        with open(output_file, "r") as f:
            output_lines = f.read().strip().split("\n")

        if verbose:
            print(f"  httpx results: {len(output_lines)} lines")

    except subprocess.TimeoutExpired:
        return ModuleResult(success=False, message="httpx timed out")
    finally:
        for path in [host_file, output_file]:
            if os.path.exists(path):
                os.remove(path)

    host_map = {h.hostname.lower(): h for h in alive_hosts}
    probed = 0
    seen_hosts = set()

    for line in output_lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        matched_host = _match_host_exact(entry, host_map)
        if not matched_host:
            continue

        if matched_host.hostname in seen_hosts:
            continue
        seen_hosts.add(matched_host.hostname)

        matched_host.status_code = entry.get("status_code", 0)
        matched_host.title = entry.get("title", "")
        if entry.get("cdn", False):
            matched_host.cdn = True
            matched_host.cdn_name = entry.get("cdn_name", "")

        techs = entry.get("tech", [])
        for tech_name in techs:
            matched_host.technologies.append(
                Technology(name=tech_name, category="web")
            )
        probed += 1

    return ModuleResult(success=True, message=f"Probed {probed} web services")


def _match_host_exact(entry: dict, host_map: dict):
    """Exact-match the httpx result back to a host in our scan list.
    Avoids substring collisions like api.example.com matching internal-api.example.com.
    """
    candidates = [
        entry.get("input", ""),
        entry.get("host", ""),
    ]

    url = entry.get("url", "")
    if url:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                candidates.append(parsed.hostname)
        except Exception:
            pass

    for c in candidates:
        if not c:
            continue
        c_lower = c.strip().lower()
        if c_lower in host_map:
            return host_map[c_lower]

    return None


def _find_pd_httpx():
    """Find the ProjectDiscovery httpx binary, NOT the Python httpx library."""
    candidates = [
        os.path.expanduser("~/go/bin/httpx"),
        "/root/go/bin/httpx",
        "/usr/local/bin/httpx",
        "/snap/bin/httpx",
    ]

    for path in candidates:
        if os.path.exists(path) and _is_pd_httpx(path):
            return path

    path = shutil.which("httpx")
    if path and _is_pd_httpx(path):
        return path

    return None


def _is_pd_httpx(path: str) -> bool:
    """Verify a binary is ProjectDiscovery's httpx, not the Python httpx library."""
    try:
        result = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout + result.stderr).lower()
        return "projectdiscovery" in output or "httpx version" in output
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False
