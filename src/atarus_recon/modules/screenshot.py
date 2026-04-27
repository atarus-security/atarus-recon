"""Screenshot capture using gowitness, with output_dir respected and exact host matching"""
import subprocess
import os
import tempfile
from urllib.parse import urlparse
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Capture screenshots of web services using gowitness v3.

    Writes screenshots into <output_dir>/screenshots/ where output_dir is the
    directory containing the rest of the report files. Falls back to ./output
    only if no other location can be determined.
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

        if has_443 or host.status_code == 200:
            url = f"https://{host.hostname}"
        elif has_80:
            url = f"http://{host.hostname}"
        else:
            url = f"https://{host.hostname}"

        url_to_host[url.lower()] = host
        urls.append(url)

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

        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )

    except FileNotFoundError:
        return ModuleResult(success=False, message="gowitness not found")
    except subprocess.TimeoutExpired:
        return ModuleResult(success=False, message="gowitness timed out")
    finally:
        if os.path.exists(url_file):
            os.remove(url_file)

    captured = _match_screenshots_exact(web_hosts, screenshot_dir)

    return ModuleResult(success=True, message=f"Captured {captured} screenshots")


def _match_screenshots_exact(hosts: list, screenshot_dir: str) -> int:
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

    file_to_hostname = {}
    for filename in files:
        if not filename.endswith(".png"):
            continue
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
