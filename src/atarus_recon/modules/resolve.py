import dns.resolver
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Resolve hostnames to IP addresses and filter alive hosts"""

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolved = 0
    failed = 0

    for host in result.hosts:
        try:
            answers = resolver.resolve(host.hostname, "A")
            host.ip = str(answers[0])
            resolved += 1
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.DNSException,
        ):
            failed += 1

    return ModuleResult(
        success=True,
        message=f"Resolved {resolved}, failed {failed}"
    )
