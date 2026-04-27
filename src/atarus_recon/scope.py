import re
import ipaddress
from urllib.parse import urlparse


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
        if not self.target or len(self.target) > 253:
            return False
        if "." not in self.target:
            return False
        labels = self.target.split(".")
        if len(labels) < 2:
            return False
        label_pattern = r"^(xn--)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
        for label in labels:
            if not re.match(label_pattern, label):
                return False
        tld = labels[-1]
        if len(tld) < 2:
            return False
        if not re.match(r"^[a-zA-Z]{2,}$", tld) and not tld.startswith("xn--"):
            return False
        return True

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
