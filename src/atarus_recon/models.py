from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Port:
    """A single open port on a host"""
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Technology:
    """A detected technology on a web service"""
    name: str
    version: str = ""
    category: str = ""


@dataclass
class Finding:
    """A vulnerability or issue discovered during scanning"""
    title: str
    severity: str = "info"
    description: str = ""
    url: str = ""
    matcher_name: str = ""
    template_id: str = ""


@dataclass
class Host:
    """A single host discovered during recon"""
    hostname: str
    ip: str = ""
    ports: list[Port] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
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
class ScanResult:
    """Top-level container for an entire scan"""
    target: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: str = ""
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    total_subdomains: int = 0
    total_alive: int = 0
    total_ports: int = 0
    whois_data: dict = field(default_factory=dict)

    def add_host(self, host: Host):
        self.hosts.append(host)

    def finalize(self):
        self.finished_at = datetime.now().isoformat()
        self.total_subdomains = len(self.hosts)
        self.total_alive = len([h for h in self.hosts if h.ip])
        self.total_ports = sum(len(h.ports) for h in self.hosts)
