import json
import ssl
import time
import urllib.request
import urllib.error
from atarus_recon.models import ScanResult, Host
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


CRTSH_TIMEOUT = 30
RETRY_COUNT = 2
RETRY_BACKOFF = 4


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Query crt.sh certificate transparency logs for subdomains.

    Retries once on 502/timeout. Drops wildcards from the host list (they're
    not directly resolvable) but logs that wildcards exist.
    """

    url = f"https://crt.sh/?q=%.{scope.target}&output=json"
    data = None
    last_error = ""

    for attempt in range(RETRY_COUNT):
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "atarus-recon/0.5.0"})
            with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT, context=ctx) as response:
                raw = response.read()
                if len(raw) == 0:
                    return ModuleResult(success=True, message="No CT records found")
                data = json.loads(raw.decode())
                break
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}"
            if e.code in (502, 503, 504, 429) and attempt < RETRY_COUNT - 1:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
                continue
            return ModuleResult(success=False, message=f"crt.sh request failed: {last_error}")
        except urllib.error.URLError as e:
            last_error = str(e)
            if attempt < RETRY_COUNT - 1:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
                continue
            return ModuleResult(success=False, message=f"crt.sh request failed: {last_error}")
        except json.JSONDecodeError:
            return ModuleResult(success=False, message="crt.sh returned invalid JSON")
        except Exception as e:
            return ModuleResult(success=False, message=f"crt.sh error: {type(e).__name__}: {e}")

    if data is None:
        return ModuleResult(success=False, message=f"crt.sh failed: {last_error}")

    raw_names = set()
    wildcards = 0
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*"):
                wildcards += 1
                continue
            raw_names.add(name)

    in_scope = scope.filter_in_scope(list(raw_names))

    existing = {h.hostname for h in result.hosts}
    new_hosts = [name for name in in_scope if name not in existing]

    for hostname in sorted(new_hosts):
        result.add_host(Host(hostname=hostname))

    msg = f"Found {len(new_hosts)} subdomains"
    if wildcards:
        msg += f" ({wildcards} wildcard certs noted)"
    return ModuleResult(success=True, message=msg)
