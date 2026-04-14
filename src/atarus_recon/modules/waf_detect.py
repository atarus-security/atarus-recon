from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": ""},
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": "", "x-amz-cf-id": ""},
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": "", "server": "akamaighost"},
    },
    "Imperva": {
        "headers": {"x-cdn": "imperva", "x-iinfo": ""},
    },
    "Sucuri": {
        "headers": {"server": "sucuri", "x-sucuri-id": ""},
    },
    "F5 BIG-IP": {
        "headers": {"server": "big-ip", "x-cnection": ""},
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
    },
    "Fortinet FortiWeb": {
        "headers": {"server": "fortiweb"},
    },
    "Citrix NetScaler": {
        "headers": {"via": "ns-cache", "cneonction": ""},
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
    },
}


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Detect WAF/CDN presence from response headers and behaviors"""

    web_hosts = [h for h in result.hosts if h.status_code > 0]

    if not web_hosts:
        return ModuleResult(success=False, message="No web hosts to check")

    detected = 0

    for host in web_hosts:
        waf_name = _check_cdn_waf(host)
        if waf_name:
            host.waf = waf_name
            detected += 1
        else:
            host.waf = ""

    return ModuleResult(success=True, message=f"Detected WAF/protection on {detected} hosts")


def _check_cdn_waf(host) -> str:
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
