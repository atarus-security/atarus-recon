"""Screenshot capture using gowitness, with output_dir respected and exact host matching"""
import subprocess
import os
import tempfile
from urllib.parse import urlparse
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


# How much of gowitness's stderr is kept for the not-run reason.
STDERR_TAIL = 200

# Whole-run limit, in seconds.
GOWITNESS_TIMEOUT = 300


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Capture screenshots of web services using gowitness v3.

    Writes screenshots into <output_dir>/screenshots/ where output_dir is the
    directory containing the rest of the report files. Falls back to ./output
    only if no other location can be determined.

    gowitness is run as an argument list and its exit code is checked: a
    missing binary, a non-zero exit or a timeout is returned as the check not
    having run, with the reason, never as zero screenshots.
    """

    web_hosts = [h for h in result.hosts if h.ip and h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="No web services to screenshot")

    gowitness_path = os.path.expanduser("~/go/bin/gowitness")
    if not os.path.exists(gowitness_path):
        gowitness_path = "gowitness"

    output_root = os.environ.get("ATARUS_OUTPUT_DIR") or os.path.join(os.getcwd(), "output")
    screenshot_dir = os.path.join(output_root, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    url_to_host = {}
    urls = []
    for host in web_hosts:
        has_443 = any(p.number == 443 for p in host.ports)
        has_80 = any(p.number == 80 for p in host.ports)

        if host.web_url:
            url = host.web_url
        elif has_443 or host.status_code == 200:
            url = f"https://{host.hostname}"
        elif has_80:
            url = f"http://{host.hostname}"
        else:
            url = f"https://{host.hostname}"

        url_to_host[url.lower()] = host
        urls.append(url)

    # Files already in the directory belong to an earlier run into the same
    # output directory; only files written or rewritten by this run count.
    before = _snapshot(screenshot_dir)

    fd, url_file = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            for url in urls:
                f.write(url + "\n")

        cmd = [
            gowitness_path,
            "scan", "file",
            "-f", url_file,
            "--screenshot-path", screenshot_dir,
            "--screenshot-format", "png",
            "--write-none",
            "--threads", "2",
            "--timeout", "15",
            "--quiet",
        ]

        env = os.environ.copy()
        env["PATH"] = os.path.expanduser("~/go/bin") + ":" + env.get("PATH", "")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=GOWITNESS_TIMEOUT,
            env=env,
        )

    except OSError as e:
        # FileNotFoundError when gowitness is not installed, PermissionError and the like.
        return ModuleResult(
            success=False,
            message=f"gowitness could not be started ({type(e).__name__}); install gowitness and a Chromium browser",
        )
    except subprocess.TimeoutExpired:
        return ModuleResult(
            success=False,
            message=f"gowitness timed out after {GOWITNESS_TIMEOUT} seconds; screenshots not captured",
        )
    finally:
        if os.path.exists(url_file):
            os.remove(url_file)

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-STDERR_TAIL:]
        return ModuleResult(
            success=False,
            message=f"gowitness exited with code {proc.returncode}; screenshots not captured. {tail}".strip(),
        )

    captured = _match_screenshots_exact(web_hosts, screenshot_dir, before)

    if not captured:
        # gowitness exits 0 even when the browser failed on every page.
        return ModuleResult(
            success=False,
            message=f"Captured 0 screenshots: gowitness exited 0 but wrote no screenshot for any of the "
                    f"{len(web_hosts)} web hosts. {(proc.stderr or '').strip()[-STDERR_TAIL:]}".strip(),
        )

    return ModuleResult(success=True, message=f"Captured {captured} of {len(web_hosts)} screenshots")


def _snapshot(directory: str) -> dict:
    """{file name: modification time in ns} for the files now in directory."""
    out = {}
    try:
        for entry in os.scandir(directory):
            if entry.is_file():
                out[entry.name] = entry.stat().st_mtime_ns
    except OSError:
        pass
    return out


def _match_screenshots_exact(hosts: list, screenshot_dir: str, before: dict = None) -> int:
    """Match screenshot files to hosts using exact filename anchors.

    gowitness names files like https---hostname-port.png. We extract the
    hostname segment between the scheme dashes and the port and require an
    exact match against the host's hostname.
    """

    if not os.path.isdir(screenshot_dir):
        return 0

    files = os.listdir(screenshot_dir)
    if not files:
        return 0

    before = before or {}
    now = _snapshot(screenshot_dir)
    file_to_hostname = {}
    for filename in files:
        if not filename.endswith(".png"):
            continue
        if filename in before and now.get(filename) == before[filename]:
            continue  # left over from an earlier run
        hostname = _extract_hostname_from_filename(filename)
        if hostname:
            file_to_hostname[filename] = hostname.lower()

    captured = 0

    for host in hosts:
        host_lower = host.hostname.lower()
        for filename, fname_host in file_to_hostname.items():
            if fname_host == host_lower:
                host.screenshot_path = os.path.join(screenshot_dir, filename)
                captured += 1
                break

    return captured


def _extract_hostname_from_filename(filename: str) -> str:
    """Parse hostname out of gowitness filenames like 'https---example.com-443.png'."""
    base = filename.replace(".png", "")
    parts = base.split("---", 1)
    if len(parts) != 2:
        return ""
    rest = parts[1]
    last_dash = rest.rfind("-")
    if last_dash <= 0:
        return rest
    candidate_port = rest[last_dash + 1:]
    if candidate_port.isdigit():
        return rest[:last_dash]
    return rest
