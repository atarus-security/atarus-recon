"""TLS certificate analysis using the cryptography library.

Replaces the old implementation that relied on ssl._ssl._test_decode_cert,
which is a private API removed in Python 3.12+. The cryptography library
parses certificates directly and supports self-signed certs without
requiring a trusted CA chain.
"""
import ssl
import socket
from datetime import datetime, timezone

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
    """Fetch the cert chain and parse the leaf with the cryptography library."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return _get_cert_info_fallback(hostname)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)

        if not der:
            return {}

        cert = x509.load_der_x509_certificate(der, default_backend())

        common_name = ""
        org_name = ""
        for attr in cert.subject:
            if attr.oid._name == "commonName":
                common_name = attr.value
            elif attr.oid._name == "organizationName":
                org_name = attr.value

        issuer_cn = ""
        issuer_org = ""
        for attr in cert.issuer:
            if attr.oid._name == "commonName":
                issuer_cn = attr.value
            elif attr.oid._name == "organizationName":
                issuer_org = attr.value

        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days_until_expiry = (not_after - now).days
        expired = days_until_expiry < 0

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            raw_sans = san_ext.value.get_values_for_type(x509.DNSName)
            for s in raw_sans:
                if isinstance(s, str):
                    sans.append(s)
                elif hasattr(s, "value"):
                    sans.append(s.value)
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        self_signed = (
            cert.subject == cert.issuer
            or (issuer_cn and issuer_cn == common_name and issuer_org == org_name)
        )

        sig_algo = ""
        try:
            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
        except Exception:
            pass

        weak_signature = sig_algo.lower() in ("md5", "sha1")

        return {
            "hostname": hostname,
            "common_name": common_name,
            "issuer": issuer_org or issuer_cn,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "expired": expired,
            "self_signed": self_signed,
            "san_count": len(sans),
            "sans": sans[:20],
            "wildcard": any(s.startswith("*.") for s in sans),
            "signature_algorithm": sig_algo,
            "weak_signature": weak_signature,
        }

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError, ssl.SSLError):
        return {}
    except Exception:
        return {}


def _get_cert_info_fallback(hostname: str) -> dict:
    """Best-effort fallback when cryptography is unavailable."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                parsed = ssock.getpeercert()
    except Exception:
        return {}

    if not parsed:
        return {}

    subject = dict(x[0] for x in parsed.get("subject", []))
    issuer = dict(x[0] for x in parsed.get("issuer", []))
    not_after_str = parsed.get("notAfter", "")

    days_until_expiry = 999
    expired = False
    if not_after_str:
        try:
            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_until_expiry = (expiry - datetime.utcnow()).days
            expired = days_until_expiry < 0
        except ValueError:
            pass

    return {
        "hostname": hostname,
        "common_name": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
        "not_after": not_after_str,
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "self_signed": False,
        "san_count": 0,
        "sans": [],
        "wildcard": False,
    }
