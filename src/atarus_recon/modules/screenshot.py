import subprocess
import os
import tempfile
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Capture screenshots of web services using gowitness v3"""

    web_hosts = [h for h in result.hosts if h.ip and h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="No web services to screenshot")

    gowitness_path = os.path.expanduser("~/go/bin/gowitness")
    if not os.path.exists(gowitness_path):
        gowitness_path = "gowitness"

    screenshot_dir = os.path.join(os.getcwd(), "output", "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    urls = []
    for host in web_hosts:
        has_443 = any(p.number == 443 for p in host.ports)
        has_80 = any(p.number == 80 for p in host.ports)

        if has_443 or host.status_code == 200:
            urls.append(f"https://{host.hostname}")
        elif has_80:
            urls.append(f"http://{host.hostname}")
        else:
            urls.append(f"https://{host.hostname}")

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
            timeout=120,
            env=env,
        )

    except FileNotFoundError:
        return ModuleResult(success=False, message="gowitness not found")
    except subprocess.TimeoutExpired:
        return ModuleResult(success=False, message="gowitness timed out")
    finally:
        if os.path.exists(url_file):
            os.remove(url_file)

    captured = _match_screenshots(web_hosts, screenshot_dir)

    return ModuleResult(success=True, message=f"Captured {captured} screenshots")


def _match_screenshots(hosts: list, screenshot_dir: str) -> int:
    """Match screenshot files to hosts"""

    if not os.path.isdir(screenshot_dir):
        return 0

    files = os.listdir(screenshot_dir)
    if not files:
        return 0

    captured = 0

    for host in hosts:
        hostname_clean = host.hostname.replace(".", "-")

        for filename in files:
            if hostname_clean in filename or host.hostname in filename:
                host.screenshot_path = os.path.join(screenshot_dir, filename)
                captured += 1
                break

    return captured
