"""WHOIS lookup with subprocess-level timeout to prevent hangs.

The python-whois library does not support timeouts. We invoke the system
'whois' command directly with a timeout and parse the output ourselves.
Falls back to python-whois if the system command is unavailable.
"""
import re
import subprocess
import shutil

from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


WHOIS_TIMEOUT = 12


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Perform WHOIS lookup on the target domain"""

    target = scope.target

    if shutil.which("whois"):
        whois_data = _whois_subprocess(target)
    else:
        whois_data = _whois_python(target)

    if not whois_data:
        result.whois_data = {}
        return ModuleResult(success=False, message="WHOIS lookup returned no data")

    result.whois_data = whois_data

    registrar = whois_data.get("registrar") or "unknown"
    org = whois_data.get("org") or "not listed"

    return ModuleResult(
        success=True,
        message=f"Registrar: {registrar}, Org: {org}"
    )


def _whois_subprocess(domain: str) -> dict:
    """Run system whois command with strict timeout"""
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=WHOIS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {}
    except (FileNotFoundError, OSError):
        return {}

    output = proc.stdout or ""
    if not output:
        return {}

    return _parse_whois_text(output)


def _parse_whois_text(text: str) -> dict:
    """Parse common WHOIS fields from raw text output"""
    fields = {
        "registrar": ["Registrar:", "registrar:"],
        "creation_date": ["Creation Date:", "Created:", "created:"],
        "expiration_date": ["Registry Expiry Date:", "Expiration Date:", "Expires:", "expires:"],
        "org": ["Registrant Organization:", "Organization:", "org:"],
        "registrant": ["Registrant Name:", "Registrant:"],
    }

    result = {
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "org": "",
        "registrant": "",
        "name_servers": [],
    }

    for key, patterns in fields.items():
        for pattern in patterns:
            for line in text.split("\n"):
                if line.strip().startswith(pattern):
                    value = line.split(":", 1)[1].strip()
                    if value and value.lower() not in ("redacted for privacy", "redacted", ""):
                        result[key] = value
                        break
            if result[key]:
                break

    name_servers = set()
    for line in text.split("\n"):
        if re.match(r"^\s*Name Server:\s*(.+)", line, re.IGNORECASE):
            ns = line.split(":", 1)[1].strip().lower()
            if ns:
                name_servers.add(ns)
    result["name_servers"] = sorted(name_servers)

    return result


def _whois_python(domain: str) -> dict:
    """Fallback to python-whois library when system whois is unavailable"""
    try:
        import whois
    except ImportError:
        return {}

    try:
        w = whois.whois(domain)
    except Exception:
        return {}

    return {
        "registrar": w.registrar or "",
        "creation_date": str(w.creation_date) if w.creation_date else "",
        "expiration_date": str(w.expiration_date) if w.expiration_date else "",
        "name_servers": w.name_servers if w.name_servers else [],
        "org": w.org or "",
        "registrant": w.name or "",
    }
