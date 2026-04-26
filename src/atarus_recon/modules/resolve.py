import dns.resolver
from atarus_recon.models import ScanResult, Host
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Resolve hostnames to IP addresses and filter alive hosts.

    Always includes the root target domain so the pipeline still works when
    upstream subdomain enumeration modules return zero results (crt.sh down,
    subfinder not installed, etc).
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    existing_hostnames = {h.hostname for h in result.hosts}

    if scope.target not in existing_hostnames:
        result.hosts.insert(0, Host(hostname=scope.target))
        existing_hostnames.add(scope.target)

    www_variant = f"www.{scope.target}"
    if www_variant not in existing_hostnames and scope.target.count(".") == 1:
        result.hosts.append(Host(hostname=www_variant))

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

    alive_hosts = [h for h in result.hosts if h.ip]
    dead_hosts = [h for h in result.hosts if not h.ip]
    result.hosts = alive_hosts + dead_hosts

    return ModuleResult(
        success=True,
        message=f"Resolved {resolved}, failed {failed}"
    )
