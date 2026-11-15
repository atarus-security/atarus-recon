"""WAF and CDN detection via active header probing.

Sends a single HEAD request per host, over HTTPS and then over HTTP if that
gets no answer, and inspects the response headers for known WAF/CDN
signatures. Falls back to webprobe-collected CDN data if direct probing
finds nothing.

The request goes to the address the scope check approved (host.ip), with
the host name only in SNI and the Host header, so the name is not resolved
again. Redirects are never followed: a 3xx answer is read for its headers
and nothing more is sent.
"""
import http.client
import socket
import ssl
from atarus_recon import __version__

from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


WAF_HEADER_SIGNATURES = {
    "Cloudflare": ["server: cloudflare", "cf-ray:", "cf-cache-status:"],
    "AWS WAF": ["x-amzn-requestid:", "x-amz-cf-id:"],
    "AWS CloudFront": ["x-amz-cf-id:", "via: cloudfront"],
    "Akamai": ["x-akamai-transformed:", "server: akamaighost", "x-akamai-edgescape:"],
    "Imperva": ["x-cdn: imperva", "x-iinfo:", "set-cookie: incap_ses_"],
    "Sucuri": ["server: sucuri", "x-sucuri-id:", "x-sucuri-cache:"],
    "F5 BIG-IP": ["server: big-ip", "x-cnection:", "x-wa-info:"],
    "Barracuda": ["server: barracuda", "set-cookie: barra_counter_"],
    "Fortinet FortiWeb": ["server: fortiweb", "set-cookie: fortiwafsid="],
    "Citrix NetScaler": ["via: ns-cache", "cneonction:"],
    "ModSecurity": ["server: mod_security", "x-mod-security-message:"],
    "Wordfence": ["server: wordfence"],
    "Google Cloud CDN": ["server: gws", "via: 1.1 google"],
    "Fastly": ["x-served-by: cache-", "x-fastly-request-id:"],
    "Azure": ["x-azure-ref:", "x-msedge-ref:"],
    "Vercel": ["x-vercel-id:", "server: vercel"],
}

PROBE_TIMEOUT = 6


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Detect WAF/CDN presence via active probing of response headers"""

    web_hosts = [h for h in result.hosts if h.ip and h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="No web hosts to check")

    detected = 0
    unanswered = 0

    for host in web_hosts:
        answered, waf_name = _probe_for_waf(host.hostname, host.ip, verbose)
        if not answered:
            unanswered += 1
        host.waf_checked = answered

        if not waf_name:
            waf_name = _check_cdn_metadata(host)

        if waf_name:
            host.waf = waf_name
            detected += 1
        else:
            host.waf = ""

    if unanswered == len(web_hosts):
        return ModuleResult(
            success=False,
            message=f"none of the {len(web_hosts)} web hosts answered the HEAD request; WAF presence unknown",
        )

    msg = f"Detected WAF/protection on {detected} hosts"
    if unanswered:
        msg += f"; {unanswered} hosts did not answer the HEAD request, so their WAF status is unknown"
    return ModuleResult(success=True, message=msg)


def _probe_for_waf(hostname: str, ip: str, verbose: bool) -> tuple:
    """HEAD / over HTTPS, then HTTP. Returns (answered, waf_name)."""
    answered, headers_text = _fetch_headers("https", hostname, ip)

    if not answered:
        answered, headers_text = _fetch_headers("http", hostname, ip)

    if not answered:
        return False, ""

    headers_lower = headers_text.lower()

    for waf_name, signatures in WAF_HEADER_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in headers_lower:
                return True, waf_name

    return True, ""


def _fetch_headers(scheme: str, hostname: str, ip: str, port: int = None) -> tuple:
    """Send one HEAD / to ip. Returns (answered, headers_text).

    answered is True when a valid HTTP response came back, even one with no
    headers at all; headers_text is then the headers as text, possibly "".
    (False, "") means no answer: refused, timed out, TLS failure or a reply
    that is not HTTP. The connection goes to ip, never to a fresh lookup of
    hostname, and the response is read once: http.client does not follow
    redirects.
    """
    if not ip:
        return False, ""
    port = port or (443 if scheme == "https" else 80)
    sock = None
    conn = None
    try:
        sock = socket.create_connection((ip, port), timeout=PROBE_TIMEOUT)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=hostname)
            conn = http.client.HTTPSConnection(hostname, port, timeout=PROBE_TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(hostname, port, timeout=PROBE_TIMEOUT)
        conn.sock = sock
        conn.request("HEAD", "/", headers={"User-Agent": f"atarus-recon/{__version__}"})
        resp = conn.getresponse()
        return True, _format_headers(resp.getheaders())
    except (OSError, http.client.HTTPException, ValueError):
        return False, ""
    finally:
        if conn is not None:
            conn.close()
        elif sock is not None:
            sock.close()


def _format_headers(headers) -> str:
    """Format headers as 'name: value' lines for substring matching.
    Takes a list of (name, value) pairs, so repeated headers such as
    Set-Cookie are all kept, or a dict."""
    items = headers.items() if isinstance(headers, dict) else headers
    return "\n".join(f"{k}: {v}" for k, v in items)


def _check_cdn_metadata(host) -> str:
    """Fall back to webprobe-detected CDN/technology data."""
    if host.cdn and host.cdn_name:
        cdn = host.cdn_name.lower()
        if "cloudflare" in cdn:
            return "Cloudflare"
        if "akamai" in cdn:
            return "Akamai"
        if "google" in cdn:
            return "Google Cloud CDN"
        if "fastly" in cdn:
            return "Fastly"
        if "amazon" in cdn or "cloudfront" in cdn:
            return "AWS CloudFront"
        if "azure" in cdn:
            return "Azure CDN"
        return cdn.title()

    for tech in host.technologies:
        name = tech.name.lower()
        if "cloudflare" in name:
            return "Cloudflare"
        if "akamai" in name:
            return "Akamai"
        if "incapsula" in name or "imperva" in name:
            return "Imperva"
        if "sucuri" in name:
            return "Sucuri"

    return ""
