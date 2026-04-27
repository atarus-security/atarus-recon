"""WAF and CDN detection via active header probing.

Sends a single HTTPS HEAD request per host and inspects response headers
for known WAF/CDN signatures. Falls back to webprobe-collected CDN data
if direct probing fails.
"""
import socket
import ssl
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

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

    web_hosts = [h for h in result.hosts if h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="No web hosts to check")

    detected = 0

    for host in web_hosts:
        waf_name = _probe_for_waf(host.hostname, verbose)

        if not waf_name:
            waf_name = _check_cdn_metadata(host)

        if waf_name:
            host.waf = waf_name
            detected += 1
        else:
            host.waf = ""

    return ModuleResult(success=True, message=f"Detected WAF/protection on {detected} hosts")


def _probe_for_waf(hostname: str, verbose: bool) -> str:
    """Send HEAD request to https://hostname/ and inspect response headers."""
    headers_text = _fetch_headers(f"https://{hostname}/")

    if not headers_text:
        headers_text = _fetch_headers(f"http://{hostname}/")

    if not headers_text:
        return ""

    headers_lower = headers_text.lower()

    for waf_name, signatures in WAF_HEADER_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in headers_lower:
                return waf_name

    return ""


def _fetch_headers(url: str) -> str:
    """Send a HEAD request and return concatenated header text. Returns empty on failure."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, method="HEAD", headers={"User-Agent": "atarus-recon/0.5.0"})
        with urlopen(req, timeout=PROBE_TIMEOUT, context=ctx) as resp:
            return _format_headers(dict(resp.headers))
    except HTTPError as e:
        try:
            return _format_headers(dict(e.headers))
        except Exception:
            return ""
    except (URLError, socket.timeout, ssl.SSLError, OSError, ConnectionError):
        return ""
    except Exception:
        return ""


def _format_headers(headers: dict) -> str:
    """Format headers as 'name: value' lines for substring matching."""
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


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
