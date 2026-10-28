from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Technology:
    name: str
    version: str = ""
    category: str = ""


@dataclass
class Finding:
    title: str
    severity: str = "info"
    description: str = ""
    url: str = ""
    matcher_name: str = ""
    template_id: str = ""


@dataclass
class Host:
    hostname: str
    ip: str = ""
    ports: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    screenshot_path: str = ""
    status_code: int = 0
    title: str = ""
    cdn: bool = False
    cdn_name: str = ""
    waf: str = ""
    cert_data: dict = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = ""


@dataclass
class BreachExposure:
    """A single data breach affecting the target domain"""
    name: str
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    modified_date: str = ""
    pwn_count: int = 0
    description: str = ""
    data_classes: list = field(default_factory=list)
    is_verified: bool = True
    is_sensitive: bool = False


@dataclass
class CredentialExposure:
    """Container for credential exposure data for the target domain"""
    target_domain: str = ""
    breaches: list = field(default_factory=list)
    total_accounts_affected: int = 0
    most_recent_breach: str = ""
    credential_hygiene_score: int = 100
    credential_hygiene_rating: str = "clean"


@dataclass
class ScanResult:
    target: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: str = ""
    hosts: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    total_subdomains: int = 0
    total_alive: int = 0
    total_ports: int = 0
    whois_data: dict = field(default_factory=dict)
    credential_exposure: Optional[CredentialExposure] = None
    # Run mode record. "passive" means no packet was sent to the target's own
    # hosts; "active" means the user placed hosts in scope and confirmed.
    mode: str = "passive"
    active_scope: list = field(default_factory=list)
    confirmation: str = ""
    # Modules that were selected but did not run, with the reason, so a report
    # never reads as clean for a check that was never made.
    modules_not_run: list = field(default_factory=list)
    # Resolved hosts that fell outside --scope and were therefore not probed.
    out_of_scope: list = field(default_factory=list)
    # Set by the nuclei module when it ran to completion and found nothing:
    # says plainly what that result does and does not vouch for.
    nuclei_detail: str = ""

    def add_host(self, host):
        self.hosts.append(host)

    def finalize(self):
        self.finished_at = datetime.now().isoformat()
        self.total_subdomains = len(self.hosts)
        self.total_alive = len([h for h in self.hosts if h.ip])
        self.total_ports = sum(len(h.ports) for h in self.hosts)
