import os
import re
import ipaddress
from urllib.parse import urlparse


LABEL_PATTERN = re.compile(r"^(xn--)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

# The controlling terminal. The confirmation for active checks is read from
# here and nowhere else: not stdin, not an environment variable, not a file.
TTY_PATH = "/dev/tty"


def is_valid_name(name: str) -> bool:
    """True when name is a properly formed FQDN with at least two labels.
    Supports standard ASCII domains and Punycode (xn-- prefixed) IDN domains.
    """
    if not name or len(name) > 253:
        return False
    if "." not in name:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not LABEL_PATTERN.match(label):
            return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    if not re.match(r"^[a-zA-Z]{2,}$", tld) and not tld.startswith("xn--"):
        return False
    return True


class ScopeValidator:
    """Ensures all recon activity stays within the target scope"""

    def __init__(self, target: str):
        self.target = self._clean_target(target)

    def _clean_target(self, target: str) -> str:
        target = target.strip().lower()
        if target.startswith(("http://", "https://")):
            target = urlparse(target).hostname or target
        if "/" in target:
            target = target.split("/")[0]
        if ":" in target:
            target = target.split(":")[0]
        target = target.rstrip(".")
        return target

    def is_in_scope(self, hostname: str) -> bool:
        hostname = hostname.strip().lower().rstrip(".")
        if hostname == self.target:
            return True
        if hostname.endswith(f".{self.target}"):
            return True
        return False

    def filter_in_scope(self, hostnames: list) -> list:
        return [h for h in hostnames if self.is_in_scope(h)]

    def validate_target(self) -> bool:
        """Validate target is a properly-formed FQDN with at least 2 labels.
        Supports standard ASCII domains and Punycode (xn-- prefixed) IDN domains.
        """
        return is_valid_name(self.target)

    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
            return True
        except ValueError:
            return False

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return re.sub(r'[^a-zA-Z0-9.\-_]', '_', name)


class ActiveScope:
    """The hosts, networks and domains the user has placed in scope for active checks.

    Entries come from --scope, either a file (one entry per line, blank lines
    and # comments ignored) or a comma-separated list. Four forms:

        app.example.com     exactly that host
        *.example.com       every name under example.com, at any depth, not the apex
        203.0.113.7         that address
        203.0.113.0/24      every address in that network

    A host is covered when its name matches a host or domain entry, or its
    resolved address falls inside a network entry. Anything else is out of
    scope and is never handed to an active module.
    """

    def __init__(self, entries: list):
        self.entries = []
        self.hosts = set()
        self.domains = set()
        self.networks = []
        for raw in entries:
            kind, value = self._parse_entry(raw)
            if kind == "host":
                self.hosts.add(value)
                self.entries.append(value)
            elif kind == "domain":
                self.domains.add(value)
                self.entries.append(f"*.{value}")
            else:
                self.networks.append(value)
                shown = str(value.network_address) if value.num_addresses == 1 else str(value)
                self.entries.append(shown)
        if not self.entries:
            raise ValueError("scope is empty: list at least one host, network or domain")

    @classmethod
    def from_option(cls, spec: str) -> "ActiveScope":
        """Build a scope from the --scope value: a file path or a comma-separated list."""
        spec = (spec or "").strip()
        if not spec:
            raise ValueError("scope is empty")
        if os.path.isfile(spec):
            with open(spec, "r") as f:
                lines = f.read().splitlines()
            raw = []
            for line in lines:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
            if not raw:
                raise ValueError(f"scope file has no entries: {spec}")
            return cls(raw)
        return cls([part for part in spec.split(",") if part.strip()])

    @staticmethod
    def _parse_entry(raw: str) -> tuple:
        text = raw.strip().lower()
        if not text:
            raise ValueError("empty scope entry")
        try:
            return "network", ipaddress.ip_network(text, strict=False)
        except ValueError:
            pass
        if text.startswith(("http://", "https://")):
            text = urlparse(text).hostname or ""
        if "/" in text:
            text = text.split("/")[0]
        kind = "host"
        if text.startswith("*."):
            kind = "domain"
            text = text[2:]
        if ":" in text:
            text = text.split(":")[0]
        text = text.rstrip(".")
        if not is_valid_name(text):
            raise ValueError(f"not a host, network or domain: {raw.strip()}")
        return kind, text

    def covers(self, hostname: str, ip: str = "") -> bool:
        """True when the name or the resolved address is inside the scope."""
        name = (hostname or "").strip().lower().rstrip(".")
        if name and name in self.hosts:
            return True
        for domain in self.domains:
            if name.endswith(f".{domain}"):
                return True
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            for net in self.networks:
                if addr.version == net.version and addr in net:
                    return True
        return False

    def split_hosts(self, hosts: list) -> tuple:
        """Split resolved hosts into (in_scope, out_of_scope). Unresolved hosts are in neither."""
        in_scope = []
        out_of_scope = []
        for host in hosts:
            if not host.ip:
                continue
            if self.covers(host.hostname, host.ip):
                in_scope.append(host)
            else:
                out_of_scope.append(host)
        return in_scope, out_of_scope

    def describe(self) -> str:
        return ", ".join(self.entries)


def tty_available() -> bool:
    """True when a controlling terminal can be opened for the confirmation prompt."""
    try:
        with open(TTY_PATH, "r+"):
            return True
    except OSError:
        return False


def read_tty_line(prompt: str):
    """Write prompt to the controlling terminal and read one line back from it.

    Returns the stripped line, or None when there is no terminal or it hit
    end of file. Nothing else can answer: stdin is not read, and no
    environment variable or configuration file is consulted.
    """
    try:
        tty = open(TTY_PATH, "r+", buffering=1)
    except OSError:
        return None
    with tty:
        tty.write(prompt)
        tty.flush()
        line = tty.readline()
    if not line:
        return None
    return line.strip()
