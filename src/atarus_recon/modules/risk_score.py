from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
}


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Calculate risk scores for each host based on all collected data"""

    scored = 0

    for host in result.hosts:
        if not host.ip:
            host.risk_score = 0
            host.risk_level = "none"
            continue

        score = 0

        score += len(host.ports) * 5

        high_risk_ports = {21, 23, 445, 3389, 1433, 3306, 5432, 6379, 27017, 11211}
        for port in host.ports:
            if port.number in high_risk_ports:
                score += 15

        if not host.waf and not host.cdn:
            score += 10

        if host.cert_data:
            if host.cert_data.get("expired", False):
                score += 20
            if host.cert_data.get("self_signed", False):
                score += 15
            days = host.cert_data.get("days_until_expiry", 999)
            if 0 < days < 30:
                score += 10

        for finding in host.findings:
            weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
            score += weight

        if host.status_code in (401, 403):
            score += 5
        if host.status_code >= 500:
            score += 8

        for tech in host.technologies:
            name = tech.name.lower()
            if any(old in name for old in ["php/5", "apache/2.2", "nginx/1.0", "iis/6", "iis/7"]):
                score += 15

        host.risk_score = min(score, 100)

        if score >= 70:
            host.risk_level = "critical"
        elif score >= 45:
            host.risk_level = "high"
        elif score >= 20:
            host.risk_level = "medium"
        elif score > 0:
            host.risk_level = "low"
        else:
            host.risk_level = "info"

        scored += 1

    risk_counts = {}
    for host in result.hosts:
        level = getattr(host, "risk_level", "none")
        risk_counts[level] = risk_counts.get(level, 0) + 1

    summary_parts = []
    for level in ["critical", "high", "medium", "low"]:
        count = risk_counts.get(level, 0)
        if count:
            summary_parts.append(f"{count} {level}")

    msg = f"Scored {scored} hosts"
    if summary_parts:
        msg += f": {', '.join(summary_parts)}"

    return ModuleResult(success=True, message=msg)
