import os
import re
import unicodedata
import ipaddress
from urllib.parse import urlparse


# Used with fullmatch: "$" alone also matches before a trailing newline, so
# re.match with ^...$ let a label such as "a\n" through.
LABEL_PATTERN = re.compile(r"(xn--)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?")
TLD_PATTERN = re.compile(r"[a-zA-Z]{2,}")

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
        if not LABEL_PATTERN.fullmatch(label):
            return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    if not TLD_PATTERN.fullmatch(tld) and not tld.startswith("xn--"):
        return False
    return True


def normalize_name(name) -> str:
    """A discovered host name in canonical form, or "" when it is not a DNS name.

    Lower case, surrounding space and one trailing dot removed, then held to
    is_valid_name (letters, digits and hyphens only). A name from crt.sh, a
    subfinder source or a resolver is third-party text: one such as
    127.0.0.1:8080#.example.com or other.host/x.example.com ends in the target
    domain, but put in a URL it names a different host. Refusing it here keeps
    it out of the host list and away from every active module.
    """
    if not isinstance(name, str):
        return ""
    name = name.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    return name if is_valid_name(name) else ""


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
        hostname = normalize_name(hostname)
        if not hostname:
            return False
        if hostname == self.target:
            return True
        if hostname.endswith(f".{self.target}"):
            return True
        return False

    def filter_in_scope(self, hostnames: list) -> list:
        """The in-scope names in canonical form, without duplicates, in input order."""
        seen = []
        for h in hostnames:
            if self.is_in_scope(h):
                name = normalize_name(h)
                if name not in seen:
                    seen.append(name)
        return seen

    def validate_target(self) -> bool:
        """Validate target is a properly-formed FQDN with at least 2 labels.
        Supports standard ASCII domains and Punycode (xn-- prefixed) IDN domains.
        """
        return is_valid_name(self.target)

    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """True when ip_str is a globally routable address (see non_public_kind).

        Loopback, link-local (cloud metadata at 169.254.169.254), private,
        shared (100.64.0.0/10), unspecified (0.0.0.0), multicast, reserved
        and documentation addresses are all refused, as is an IPv4-mapped
        IPv6 form of any of them, every IPv4-compatible, IPv4-translated and
        NAT64 (64:ff9b::/96) address, and the Azure platform address
        168.63.129.16.
        """
        return non_public_kind(ip_str) == ""

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return re.sub(r'[^a-zA-Z0-9.\-_]', '_', name)


_DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))


# RFC 6598 shared address space (carrier-grade NAT).
_SHARED_NET = ipaddress.ip_network("100.64.0.0/10")

# Public addresses that only answer from inside one provider's platform, where
# they serve the platform's own agent and metadata (Azure WireServer).
_CLOUD_PLATFORM_ADDRESSES = frozenset({ipaddress.ip_address("168.63.129.16")})

# IPv6 forms that carry an IPv4 address in their last 32 bits. Where such an
# answer leads depends on a translator or a host stack the tool cannot see,
# so a name match never admits one; a network entry can.
_IPV4_COMPATIBLE_NET = ipaddress.ip_network("::/96")
_IPV4_TRANSLATED_NET = ipaddress.ip_network("::ffff:0:0:0/96")
_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4_form(addr) -> str:
    """For an IPv6 address that embeds an IPv4 one, the form's name and the embedded address; else ""."""
    if addr.version != 6:
        return ""
    if addr in _NAT64_NET:
        form = "NAT64"
    elif addr in _IPV4_TRANSLATED_NET:
        form = "IPv4-translated"
    elif addr in _IPV4_COMPATIBLE_NET and int(addr) > 1:
        # :: and ::1 are the unspecified and loopback addresses, judged as such.
        form = "IPv4-compatible"
    else:
        return ""
    embedded = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return f"{form} (embeds {embedded})"


def _is_global(addr) -> bool:
    return bool(addr.is_global)


def non_public_kind(ip_str: str) -> str:
    """"" when ip_str is a globally routable address, otherwise what it is.

    The answer ("loopback", "link-local", "private", ...) is used to tell the
    user why a host was not probed. A value that is not an address at all is
    "not an IP address".
    """
    try:
        addr = ipaddress.ip_address((ip_str or "").strip())
    except ValueError:
        return "not an IP address"
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    embedded = _embedded_ipv4_form(addr)
    if embedded:
        return embedded
    if addr in _CLOUD_PLATFORM_ADDRESSES:
        return "cloud platform"
    if _is_global(addr) and not addr.is_multicast:
        return ""
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if any(addr in net for net in _DOCUMENTATION_NETS if net.version == addr.version):
        return "documentation"
    if addr.version == 4 and addr in _SHARED_NET:
        return "shared"
    if addr.is_private:
        return "private"
    return "non-public"


def _describe_kind(kind: str) -> str:
    """"loopback" -> "a loopback address", "NAT64 (embeds x)" -> "a NAT64 address (embeds x)"."""
    head, sep, tail = kind.partition(" (")
    article = "an" if head[:1].lower() in "aeiou" else "a"
    return f"{article} {head} address" + (f" ({tail}" if sep else "")


class ActiveScope:
    """The hosts, networks and domains the user has placed in scope for active checks.

    Entries come from --scope, either a file (one entry per line, blank lines
    and # comments ignored) or a comma-separated list. Four forms:

        app.example.com     exactly that host
        *.example.com       every name under example.com, at any depth, not the apex
        203.0.113.7         that address
        203.0.113.0/24      every address in that network

    A host is covered when every address it resolved to is admitted: an
    address inside a network entry, or a globally routable address of a name
    that matches a host or domain entry. A loopback, link-local, private or
    other non-public address is admitted only by a network entry that
    contains it. A host that is not covered is out of scope and is not handed
    to an active module. (httpx, nuclei and gowitness look the name up again
    themselves; see the README on DNS answers that change after the gate.)
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

    # Extensions that mark a --scope value as a file the user meant to name.
    FILE_SUFFIXES = (".txt", ".lst", ".list", ".csv", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".scope")

    @classmethod
    def from_option(cls, spec) -> "ActiveScope":
        """Build a scope from the --scope value: a file path or a comma-separated list.

        spec may also be a list or tuple of such values (--scope given more
        than once); the scope is then every entry they name.
        """
        specs = list(spec) if isinstance(spec, (list, tuple)) else [spec]
        raw = []
        for one in specs:
            raw.extend(cls._raw_entries(one))
        if not raw:
            raise ValueError("scope is empty")
        return cls(raw)

    @classmethod
    def _raw_entries(cls, spec: str) -> list:
        spec = (spec or "").strip()
        if not spec:
            raise ValueError("scope is empty")
        if os.path.isfile(spec):
            with open(spec, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
            raw = []
            for line in lines:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
            if not raw:
                raise ValueError(f"scope file has no entries: {spec}")
            return raw
        if "," not in spec and cls._looks_like_a_path(spec):
            # A mistyped file name must not quietly become a one-host scope.
            raise ValueError(f"scope file not found: {spec}")
        return [part for part in spec.split(",") if part.strip()]

    @classmethod
    def _looks_like_a_path(cls, spec: str) -> bool:
        if spec.startswith(("http://", "https://")):
            return False
        try:
            ipaddress.ip_network(spec, strict=False)
            return False
        except ValueError:
            pass
        if os.sep in spec or spec.startswith(("~", ".")):
            return True
        return spec.lower().endswith(cls.FILE_SUFFIXES)

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

    def _in_network(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return True
        return False

    def exclusion_reason(self, hostname: str, ip: str = "", ips=None) -> str:
        """"" when the host is inside the scope, otherwise why it is not.

        ips is every address the name resolved to; ip, when given and not in
        ips, is judged too. Every one of them must be admitted on its own: an
        address is admitted when it falls inside a network entry, or when the
        name matches a host or domain entry and the address is globally
        routable. A name match alone is not enough for an address that is not
        globally routable (loopback, link-local such as 169.254.169.254,
        private, and the like): whoever controls a DNS record under the target
        zone could otherwise point the active modules at the operator's own
        machine, its LAN or a cloud metadata endpoint. Such an address is
        admitted only by a network entry that contains it. The whole set is
        judged, not one member, because httpx, nuclei and gowitness are handed
        the name and may connect to any address it answers with.

        A host whose name is not a well formed DNS name is never covered, not
        even by a network entry: the active modules address hosts by name, and
        such a name would send them somewhere other than the checked address.
        """
        name = ""
        if hostname:
            name = normalize_name(hostname)
            if not name:
                return "not a well formed DNS name"
        addresses = [a for a in (ips or []) if a]
        if ip and ip not in addresses:
            addresses.append(ip)
        by_name = bool(name) and (
            name in self.hosts or any(name.endswith(f".{d}") for d in self.domains)
        )
        if not addresses:
            return "" if by_name else "not covered by --scope"
        several = len(addresses) > 1
        for addr in addresses:
            if self._in_network(addr):
                continue
            if not by_name:
                if several and any(self._in_network(a) for a in addresses):
                    return f"one of its addresses, {addr}, is not covered by --scope"
                return "not covered by --scope"
            kind = non_public_kind(addr)
            if kind:
                described = _describe_kind(kind)
                if several:
                    return (
                        f"one of its addresses, {addr}, is {described}; only a network "
                        f"entry in --scope that contains it admits it"
                    )
                return (
                    f"resolves to {described}; only a network entry in --scope "
                    f"that contains it admits it"
                )
        return ""

    def covers(self, hostname: str, ip: str = "", ips=None) -> bool:
        """True when the name and every resolved address are inside the scope (see exclusion_reason)."""
        return self.exclusion_reason(hostname, ip, ips) == ""

    def split_hosts(self, hosts: list) -> tuple:
        """Split resolved hosts into (in_scope, out_of_scope). Unresolved hosts are in neither.

        Each out-of-scope entry is (host, reason).
        """
        in_scope = []
        out_of_scope = []
        for host in hosts:
            if not host.ip:
                continue
            reason = self.exclusion_reason(host.hostname, host.ip, getattr(host, "ips", None))
            if reason:
                out_of_scope.append((host, reason))
            else:
                in_scope.append(host)
        return in_scope, out_of_scope

    def describe(self) -> str:
        return ", ".join(self.entries)


def _open_tty() -> int:
    """A raw read-write descriptor on the controlling terminal.

    Opened with os.open rather than open(path, "r+"): the latter builds a
    BufferedRandom, which demands a seekable stream, and a terminal is not
    one, so it raises io.UnsupportedOperation (an OSError) on every real
    terminal and the gate would never open.
    """
    return os.open(TTY_PATH, os.O_RDWR | getattr(os, "O_NOCTTY", 0))


def tty_available() -> bool:
    """True when a controlling terminal can be opened for the confirmation prompt."""
    try:
        fd = _open_tty()
    except OSError:
        return False
    os.close(fd)
    return True


def read_tty_line(prompt: str):
    """Write prompt to the controlling terminal and read one line back from it.

    Returns the stripped line, or None when there is no terminal or it hit
    end of file. Nothing else can answer: stdin is not read, and no
    environment variable or configuration file is consulted.
    """
    try:
        fd = _open_tty()
    except OSError:
        return None
    try:
        if prompt:
            os.write(fd, prompt.encode("utf-8", "replace"))
        with open(fd, "r", encoding="utf-8", errors="replace", closefd=False) as reader:
            line = reader.readline()
    except OSError:
        return None
    finally:
        os.close(fd)
    if not line:
        return None
    return line.strip()


# Characters that must not reach a terminal or a report as they are:
#   Cc  C0 and C1 control characters, including ESC, BEL, CR, LF, DEL
#   Cf  format characters: bidirectional overrides, zero-width joiners, soft hyphen
#   Cs  lone surrogates
#   Zl  line separator, Zp  paragraph separator
_UNSAFE_CATEGORIES = ("Cc", "Cf", "Cs", "Zl", "Zp")
_BLANK = ("\t", "\n", "\r", "\x0b", "\x0c", " ", " ")


def safe_text(text: object, limit: int = None) -> str:
    """Text taken from a target, made safe to print on one line.

    Tabs, newlines and other line breaks become single spaces. Every other
    control, format or separator character is shown in escaped form
    (\\x1b, \\u202e) so that it is visible in the evidence but inert. Runs of
    spaces are collapsed. With limit, longer text is cut and marked.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    out = []
    for ch in text:
        if ch in _BLANK:
            out.append(" ")
        elif unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            code = ord(ch)
            out.append("\\x%02x" % code if code < 0x100 else "\\u%04x" % code)
        else:
            out.append(ch)
    cleaned = re.sub(r" {2,}", " ", "".join(out)).strip()
    if limit is not None and limit > 0 and len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip() + " [cut]"
    return cleaned
