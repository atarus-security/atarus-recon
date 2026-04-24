"""CSV export for credential exposure findings"""
import os
import csv
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator


def generate(result: ScanResult, output_dir: str) -> list:
    """Generate two CSVs: raw breaches, and remediation actions. Returns list of paths written."""
    if not result.credential_exposure or not result.credential_exposure.breaches:
        return []

    os.makedirs(output_dir, exist_ok=True)
    safe_target = ScopeValidator.sanitize_filename(result.target)

    paths = []

    breaches_path = os.path.join(output_dir, f"credcheck-breaches-{safe_target}.csv")
    with open(breaches_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "breach_name",
            "breach_title",
            "breach_date",
            "accounts_affected",
            "data_classes",
            "is_verified",
            "is_sensitive",
            "description",
            "reference_url",
        ])
        for b in result.credential_exposure.breaches:
            writer.writerow([
                b.name,
                b.title,
                b.breach_date,
                b.pwn_count,
                "; ".join(b.data_classes) if b.data_classes else "",
                "yes" if b.is_verified else "no",
                "yes" if b.is_sensitive else "no",
                b.description,
                f"https://haveibeenpwned.com/PwnedWebsites#{b.name}",
            ])
    paths.append(breaches_path)

    remediation_path = os.path.join(output_dir, f"credcheck-remediation-{safe_target}.csv")
    with open(remediation_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "priority",
            "breach_name",
            "severity",
            "affected_group",
            "remediation_action",
            "estimated_effort",
            "rationale",
        ])

        priority = 1
        current_year = __import__("datetime").datetime.now().year

        for b in result.credential_exposure.breaches:
            try:
                year = int((b.breach_date or "").split("-")[0])
            except (ValueError, IndexError):
                year = current_year - 10

            data_classes_lower = {dc.lower() for dc in b.data_classes}
            has_passwords = any(k in " ".join(data_classes_lower) for k in ["password", "credential"])
            has_financial = any(k in " ".join(data_classes_lower) for k in ["credit card", "bank account"])
            has_sensitive = any(k in " ".join(data_classes_lower) for k in ["social security", "passport", "drivers license"])

            if year >= current_year - 2:
                severity = "high"
                effort = "1-2 weeks"
            elif year >= current_year - 5:
                severity = "medium"
                effort = "2-4 weeks"
            else:
                severity = "low"
                effort = "policy update"

            if has_financial or has_sensitive:
                severity = "high"
                effort = "immediate"

            actions = []
            affected = f"Employees and customers with {b.title or b.name} accounts"

            if has_passwords:
                actions.append("Require password reset for affected accounts")
                actions.append("Enforce MFA on all corporate systems")
            if has_financial:
                actions.append("Notify affected individuals per breach notification law")
                actions.append("Monitor credit for affected accounts")
            if has_sensitive:
                actions.append("Coordinate with legal and compliance teams")
            if not actions:
                actions.append("Review whether organization uses this service")
                actions.append("Audit reused credentials across systems")

            rationale_parts = []
            if year >= current_year - 2:
                rationale_parts.append(f"recent breach ({b.breach_date})")
            else:
                rationale_parts.append(f"legacy breach from {b.breach_date}")
            rationale_parts.append(f"{b.pwn_count:,} accounts exposed")
            if has_passwords:
                rationale_parts.append("credentials exposed increases reuse risk")

            writer.writerow([
                priority,
                b.name,
                severity,
                affected,
                "; ".join(actions),
                effort,
                ". ".join(rationale_parts).capitalize(),
            ])
            priority += 1

        rating = result.credential_exposure.credential_hygiene_rating
        if rating in ("poor", "critical", "severe"):
            writer.writerow([
                priority,
                "(overall)",
                "high" if rating == "severe" else "medium",
                "Organization-wide",
                "Conduct credential hygiene audit; enforce MFA on all external-facing services; implement password manager for staff; subscribe to breach monitoring service",
                "1-3 months",
                f"Domain credential hygiene rated {rating} based on {len(result.credential_exposure.breaches)} known breaches affecting {result.credential_exposure.total_accounts_affected:,} accounts",
            ])

    paths.append(remediation_path)

    return paths
