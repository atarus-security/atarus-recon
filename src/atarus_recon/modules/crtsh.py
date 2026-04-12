import json
import ssl
import urllib.request
import urllib.error
from atarus_recon.models import ScanResult, Host
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Query crt.sh certificate transparency logs for subdomains"""

    url = f"https://crt.sh/?q=%.{scope.target}&output=json"

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "atarus-recon/0.1.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
            raw = response.read()
            if len(raw) == 0:
                return ModuleResult(success=True, message="No CT records found")
            data = json.loads(raw.decode())

    except urllib.error.URLError as e:
        return ModuleResult(success=False, message=f"crt.sh request failed: {e}")
    except json.JSONDecodeError:
        return ModuleResult(success=False, message="crt.sh returned invalid JSON")
    except Exception as e:
        return ModuleResult(success=False, message=f"crt.sh error: {e}")

    raw_names = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*"):
                raw_names.add(name)

    in_scope = scope.filter_in_scope(list(raw_names))

    existing = {h.hostname for h in result.hosts}
    new_hosts = [name for name in in_scope if name not in existing]

    for hostname in sorted(new_hosts):
        result.add_host(Host(hostname=hostname))

    return ModuleResult(success=True, message=f"Found {len(new_hosts)} subdomains")
