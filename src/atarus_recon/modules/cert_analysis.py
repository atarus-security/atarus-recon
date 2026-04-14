import ssl
import socket
from datetime import datetime
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Analyze SSL/TLS certificates on HTTPS hosts"""

    https_hosts = [h for h in result.hosts if h.ip and h.status_code > 0]

    if not https_hosts:
        return ModuleResult(success=False, message="No HTTPS hosts to analyze")

    analyzed = 0
    issues = 0

    for host in https_hosts:
        cert_info = _get_cert_info(host.hostname, verbose)
        if cert_info:
            host.cert_data = cert_info
            analyzed += 1

            if cert_info.get("expired", False):
                issues += 1
            if cert_info.get("days_until_expiry", 999) < 30:
                issues += 1
            if cert_info.get("self_signed", False):
                issues += 1

    msg = f"Analyzed {analyzed} certificates"
    if issues:
        msg += f", {issues} issues found"

    return ModuleResult(success=True, message=msg)


def _get_cert_info(hostname: str, verbose: bool) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                parsed = ssl._ssl._test_decode_cert(cert) if hasattr(ssl._ssl, '_test_decode_cert') else None

        if parsed is None:
            ctx2 = ssl.create_default_context()
            try:
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                        parsed = ssock.getpeercert()
            except ssl.SSLCertVerificationError:
                return {"hostname": hostname, "error": "verification failed", "self_signed": True}

        if not parsed:
            return {}

        subject = dict(x[0] for x in parsed.get("subject", []))
        issuer = dict(x[0] for x in parsed.get("issuer", []))

        not_before = parsed.get("notBefore", "")
        not_after = parsed.get("notAfter", "")

        expired = False
        days_until_expiry = 999
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry - datetime.utcnow()).days
                expired = days_until_expiry < 0
            except ValueError:
                pass

        sans = []
        for san_type, san_value in parsed.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_value)

        self_signed = subject.get("organizationName", "") == issuer.get("organizationName", "") and \
                      subject.get("commonName", "") == issuer.get("commonName", "")

        return {
            "hostname": hostname,
            "common_name": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_until_expiry,
            "expired": expired,
            "self_signed": self_signed,
            "san_count": len(sans),
            "sans": sans[:20],
            "wildcard": any(s.startswith("*.") for s in sans),
        }

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return {}
    except Exception:
        return {}
