"""Credential exposure checking via HaveIBeenPwned"""
import time
import requests
from atarus_recon.models import ScanResult, Finding, BreachExposure, CredentialExposure
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
USER_AGENT = "atarus-recon/0.4.0 (atarus-security)"
REQUEST_TIMEOUT = 12


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Check for credential exposures affecting the target domain"""

    target_domain = scope.target

    try:
        resp = requests.get(
            HIBP_BREACHES_URL,
            params={"domain": target_domain},
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        return ModuleResult(success=False, message="HIBP request timed out")
    except requests.exceptions.RequestException as e:
        return ModuleResult(success=False, message=f"HIBP request failed: {e}")

    if resp.status_code == 404:
        exposure = CredentialExposure(
            target_domain=target_domain,
            credential_hygiene_score=100,
            credential_hygiene_rating="clean",
        )
        result.credential_exposure = exposure
        return ModuleResult(success=True, message="No breaches found on HIBP for domain")

    if resp.status_code == 429:
        time.sleep(6)
        try:
            resp = requests.get(
                HIBP_BREACHES_URL,
                params={"domain": target_domain},
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as e:
            return ModuleResult(success=False, message=f"HIBP rate-limited and retry failed: {e}")

    if resp.status_code != 200:
        return ModuleResult(success=False, message=f"HIBP returned HTTP {resp.status_code}")

    try:
        breaches_data = resp.json()
    except ValueError:
        return ModuleResult(success=False, message="HIBP returned invalid JSON")

    if not isinstance(breaches_data, list) or not breaches_data:
        exposure = CredentialExposure(
            target_domain=target_domain,
            credential_hygiene_score=100,
            credential_hygiene_rating="clean",
        )
        result.credential_exposure = exposure
        return ModuleResult(success=True, message="No breaches found affecting this domain")

    breaches = []
    for b in breaches_data:
        breaches.append(BreachExposure(
            name=b.get("Name", ""),
            title=b.get("Title", ""),
            domain=b.get("Domain", ""),
            breach_date=b.get("BreachDate", ""),
            added_date=b.get("AddedDate", ""),
            modified_date=b.get("ModifiedDate", ""),
            pwn_count=b.get("PwnCount", 0),
            description=_clean_description(b.get("Description", "")),
            data_classes=b.get("DataClasses", []) or [],
            is_verified=b.get("IsVerified", True),
            is_sensitive=b.get("IsSensitive", False),
        ))

    breaches.sort(key=lambda x: x.breach_date, reverse=True)

    total_accounts = sum(b.pwn_count for b in breaches)
    most_recent = breaches[0].breach_date if breaches else ""

    score, rating = _compute_hygiene_score(breaches)

    exposure = CredentialExposure(
        target_domain=target_domain,
        breaches=breaches,
        total_accounts_affected=total_accounts,
        most_recent_breach=most_recent,
        credential_hygiene_score=score,
        credential_hygiene_rating=rating,
    )
    result.credential_exposure = exposure

    _add_findings(result, exposure)

    return ModuleResult(
        success=True,
        message=f"{len(breaches)} breach(es) found, {total_accounts:,} accounts affected, hygiene {rating}",
    )


def _clean_description(html: str) -> str:
    """HIBP descriptions contain HTML. Strip the tags for cleaner output."""
    import re
    text = re.sub(r"<[^>]+>", "", html or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _compute_hygiene_score(breaches: list) -> tuple:
    """Compute 0-100 credential hygiene score. Lower = worse."""
    if not breaches:
        return 100, "clean"

    score = 100
    current_year = __import__("datetime").datetime.now().year

    high_impact_classes = {
        "passwords", "password hashes", "password hints",
        "credit cards", "bank account numbers", "social security numbers",
        "mfa secrets", "security questions and answers",
    }

    for b in breaches:
        score -= 8
        if b.pwn_count >= 100_000_000:
            score -= 20
        elif b.pwn_count >= 10_000_000:
            score -= 15
        elif b.pwn_count >= 1_000_000:
            score -= 10
        elif b.pwn_count >= 100_000:
            score -= 6

        try:
            year = int((b.breach_date or "").split("-")[0])
            if year >= current_year - 1:
                score -= 15
            elif year >= current_year - 3:
                score -= 8
            elif year >= current_year - 5:
                score -= 3
        except (ValueError, IndexError):
            pass

        data_classes_lower = {dc.lower() for dc in b.data_classes}
        if data_classes_lower & high_impact_classes:
            score -= 10

        if b.is_sensitive:
            score -= 5

    score = max(0, min(100, score))

    if score >= 80:
        rating = "clean"
    elif score >= 60:
        rating = "fair"
    elif score >= 40:
        rating = "poor"
    elif score >= 20:
        rating = "critical"
    else:
        rating = "severe"

    return score, rating


def _add_findings(result: ScanResult, exposure: CredentialExposure):
    """Translate breach data into findings that flow into reports"""
    current_year = __import__("datetime").datetime.now().year

    for b in exposure.breaches:
        severity = "medium"
        try:
            year = int((b.breach_date or "").split("-")[0])
            if year >= current_year - 2:
                severity = "high"
            elif year <= current_year - 7:
                severity = "low"
        except (ValueError, IndexError):
            pass

        high_impact = {"passwords", "password hashes", "credit cards", "bank account numbers", "social security numbers", "mfa secrets"}
        data_classes_lower = {dc.lower() for dc in b.data_classes}
        if data_classes_lower & high_impact:
            if severity == "medium":
                severity = "high"
            elif severity == "low":
                severity = "medium"

        exposed = ", ".join(b.data_classes[:8]) if b.data_classes else "unspecified data"

        description = (
            f"{b.pwn_count:,} accounts affected in the {b.title or b.name} breach ({b.breach_date}). "
            f"Exposed data classes: {exposed}. "
            f"Employees or customers with accounts on this service may have reused credentials."
        )

        result.findings.append(Finding(
            title=f"Credential exposure via {b.title or b.name} breach",
            severity=severity,
            description=description,
            url=f"https://haveibeenpwned.com/PwnedWebsites#{b.name}",
            matcher_name="hibp-domain-breach",
            template_id="atarus-credcheck",
        ))

    if exposure.credential_hygiene_rating in ("critical", "severe"):
        result.findings.append(Finding(
            title=f"Domain credential hygiene rated {exposure.credential_hygiene_rating}",
            severity="high" if exposure.credential_hygiene_rating == "severe" else "medium",
            description=(
                f"The target domain has {len(exposure.breaches)} known breach(es) affecting approximately "
                f"{exposure.total_accounts_affected:,} accounts. Credential hygiene score: {exposure.credential_hygiene_score}/100. "
                f"Employees with accounts in these breaches should be required to reset passwords and enable MFA."
            ),
            url="https://haveibeenpwned.com/DomainSearch",
            matcher_name="credential-hygiene-rating",
            template_id="atarus-credcheck",
        ))
