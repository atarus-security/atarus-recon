"""Templated vulnerability scanning with nuclei.

Active module: nuclei sends many requests to every in-scope web host, so it
runs only behind --active, inside --scope and after the confirmation gate.

nuclei is run as an argument list, never through a shell. Its exit code is
checked and its stderr is kept, so a missing binary, a template error, a
crash, a timeout or a run that wrote nothing is reported as the check not
having run, with the reason, never as a clean result. Interactsh (out of
band callbacks through a third-party server) and redirects are disabled.
"""
import json
import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse
from atarus_recon.models import ScanResult, Finding
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


# How much of nuclei's stderr is kept for the not-run reason.
STDERR_TAIL = 200

# Whole-run limit, in seconds.
NUCLEI_TIMEOUT = 600

# What a clean run says about itself: nuclei exited 0 and matched nothing, and
# the module did not verify that templates were loaded.
CLEAN_DETAIL = "nuclei exited 0 with no findings; template load not verified"

# Phrases nuclei prints when it had nothing to run.
NO_TEMPLATES_MARKERS = ("no templates provided", "no templates loaded", "no templates found", "0 templates loaded")


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Run nuclei against the discovered web hosts that are in scope"""

    web_hosts = [h for h in result.hosts if h.ip and h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="no web hosts to scan (webprobe found none)")

    nuclei_path = _find_nuclei()
    if not nuclei_path:
        return ModuleResult(
            success=False,
            message="nuclei not found; install with ./install-deps.sh or "
                    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        )

    fd, url_file = tempfile.mkstemp(suffix=".txt")
    out_fd, output_file = tempfile.mkstemp(suffix=".jsonl")
    os.close(out_fd)

    try:
        with os.fdopen(fd, "w") as f:
            for host in web_hosts:
                has_443 = any(p.number == 443 for p in host.ports)
                scheme = "https" if has_443 or host.status_code == 200 else "http"
                f.write(f"{scheme}://{host.hostname}\n")

        cmd = [
            nuclei_path,
            "-l", url_file,
            "-severity", "low,medium,high,critical",
            "-silent",
            "-jsonl",
            "-o", output_file,
            "-no-color",
            "-rate-limit", str(rate_limit * 5),
            "-timeout", "10",
            "-disable-update-check",
            # No interactsh: no out of band callbacks through a third-party server.
            "-ni",
            # Stay on the hosts in scope: nuclei must not follow redirects elsewhere.
            "-disable-redirects",
        ]

        env = os.environ.copy()
        env["PATH"] = os.path.expanduser("~/go/bin") + ":" + env.get("PATH", "")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT, env=env)
        except subprocess.TimeoutExpired:
            return ModuleResult(
                success=False,
                message=f"nuclei timed out after {NUCLEI_TIMEOUT} seconds; check not completed",
            )
        except OSError as e:
            return ModuleResult(success=False, message=f"nuclei could not be started: {type(e).__name__}")

        if proc.returncode != 0:
            return ModuleResult(
                success=False,
                message=f"nuclei exited with code {proc.returncode}; check not completed. {_stderr_tail(proc)}".strip(),
            )

        try:
            with open(output_file, "r") as f:
                raw = f.read()
        except OSError:
            return ModuleResult(success=False, message="nuclei wrote no output file; check not completed")

        if not raw.strip():
            # An empty file is what a clean scan writes. When nuclei said on
            # stderr that it loaded no templates, the check was not made; in
            # every other case this is a clean result, reported with the one
            # thing it does not vouch for.
            if _no_templates_loaded(proc):
                return ModuleResult(
                    success=False,
                    message=f"nuclei loaded no templates, so no check was made. {_stderr_tail(proc)}".strip(),
                )
            result.nuclei_detail = CLEAN_DETAIL
            return ModuleResult(success=True, message=CLEAN_DETAIL)

        output_lines = raw.strip().split("\n")

        if verbose:
            print(f"  nuclei results: {len(output_lines)} lines")

    finally:
        for path in (url_file, output_file):
            try:
                os.remove(path)
            except OSError:
                pass

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

    return ModuleResult(
        success=True,
        message=f"Found {total_findings} findings at low severity or above across {len(web_hosts)} web hosts",
    )


def _find_nuclei() -> str:
    """Locate the nuclei binary; empty string when it is not installed."""
    candidates = [
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("nuclei") or ""


def _no_templates_loaded(proc) -> bool:
    """True when nuclei's own output says it loaded no templates."""
    text = (proc.stderr or "") + "\n" + (proc.stdout or "")
    text = text.lower()
    return any(marker in text for marker in NO_TEMPLATES_MARKERS)


def _stderr_tail(proc) -> str:
    """The last STDERR_TAIL characters of what the binary said, on one line."""
    text = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
    return text[-STDERR_TAIL:]


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
