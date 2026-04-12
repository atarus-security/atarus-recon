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
        target = target.rstrip(".")
        return target

    def is_in_scope(self, hostname: str) -> bool:
        hostname = hostname.strip().lower().rstrip(".")
        if hostname == self.target:
            return True
        if hostname.endswith(f".{self.target}"):
            return True
        return False

    def filter_in_scope(self, hostnames: list[str]) -> list[str]:
        return [h for h in hostnames if self.is_in_scope(h)]

    def validate_target(self) -> bool:
        pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, self.target))

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
