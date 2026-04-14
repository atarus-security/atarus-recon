import whois
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Perform WHOIS lookup on the target domain"""

    try:
        w = whois.whois(scope.target)

        result.whois_data = {
            "registrar": w.registrar or "",
            "creation_date": str(w.creation_date) if w.creation_date else "",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "",
            "name_servers": w.name_servers if w.name_servers else [],
            "org": w.org or "",
            "registrant": w.name or "",
        }

        registrar = w.registrar or "unknown"
        org = w.org or "not listed"

        return ModuleResult(
            success=True,
            message=f"Registrar: {registrar}, Org: {org}"
        )

    except Exception as e:
        result.whois_data = {}
        return ModuleResult(success=False, message=f"WHOIS lookup failed: {str(e)[:80]}")
