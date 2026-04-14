import subprocess
import os
from atarus_recon.models import ScanResult, Host
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Run subfinder for passive subdomain enumeration"""

    subfinder_path = "subfinder"
    for path in ["/usr/bin/subfinder", os.path.expanduser("~/go/bin/subfinder")]:
        if os.path.exists(path):
            subfinder_path = path
            break

    try:
        cmd = [
            subfinder_path,
            "-d", scope.target,
            "-silent",
            "-timeout", "30",
        ]

        env = os.environ.copy()
        env["PATH"] = os.path.expanduser("~/go/bin") + ":" + env.get("PATH", "")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

        if proc.returncode != 0 and not proc.stdout:
            return ModuleResult(success=False, message=f"subfinder failed: {proc.stderr[:100]}")

    except FileNotFoundError:
        return ModuleResult(success=False, message="subfinder not found in PATH")
    except subprocess.TimeoutExpired:
        return ModuleResult(success=False, message="subfinder timed out")

    raw_names = set()
    for line in proc.stdout.strip().split("\n"):
        name = line.strip().lower()
        if name:
            raw_names.add(name)

    in_scope = scope.filter_in_scope(list(raw_names))

    existing = {h.hostname for h in result.hosts}
    new_hosts = [name for name in in_scope if name not in existing]

    for hostname in sorted(new_hosts):
        result.add_host(Host(hostname=hostname))

    return ModuleResult(success=True, message=f"Found {len(new_hosts)} new subdomains ({len(in_scope)} total)")
