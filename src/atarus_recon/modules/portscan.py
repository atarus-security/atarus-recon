import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
from atarus_recon.models import ScanResult, Port
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


# How much of nmap's stderr is kept for the not-run reason.
STDERR_TAIL = 200

# Per-address limit, in seconds.
NMAP_TIMEOUT = 300


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Run nmap against the alive hosts in scope.

    nmap is run as an argument list and its exit code is checked. A missing
    binary, a non-zero exit, a timeout or unparseable output is returned as
    the check not having run, with the reason, never as zero open ports.
    """

    alive_hosts = [h for h in result.hosts if h.ip]

    if not alive_hosts:
        return ModuleResult(success=False, message="No alive hosts to scan")

    ip_to_hosts = {}
    skipped = 0
    for host in alive_hosts:
        if not ScopeValidator.is_valid_ip(host.ip):
            skipped += 1
            continue
        if host.ip not in ip_to_hosts:
            ip_to_hosts[host.ip] = []
        ip_to_hosts[host.ip].append(host)

    if not ip_to_hosts:
        return ModuleResult(success=False, message=f"No valid public IPs (skipped {skipped})")

    unique_ips = list(ip_to_hosts.keys())
    total_ports = 0
    failures = []

    for ip in unique_ips:
        xml_path = None
        try:
            fd, xml_path = tempfile.mkstemp(suffix=".xml")
            os.close(fd)

            cmd = [
                "nmap", "-sT", "-T3",
                "--top-ports", "100",
                "-sV", "--open",
                "-oX", xml_path,
                "--max-rate", str(rate_limit * 10),
                ip,
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
            if proc.returncode != 0:
                tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-STDERR_TAIL:]
                failures.append(f"{ip}: nmap exited with code {proc.returncode} {tail}".strip())
                continue
            try:
                ports_found = _parse_nmap_xml(xml_path, ip, ip_to_hosts)
            except ET.ParseError:
                failures.append(f"{ip}: nmap output could not be parsed")
                continue
            total_ports += ports_found

        except subprocess.TimeoutExpired:
            failures.append(f"{ip}: nmap timed out after {NMAP_TIMEOUT} seconds")
        except OSError as e:
            # FileNotFoundError when nmap is not installed, PermissionError and the like.
            return ModuleResult(
                success=False,
                message=f"nmap could not be started ({type(e).__name__}); install nmap and make sure it is on PATH",
            )
        finally:
            if xml_path and os.path.exists(xml_path):
                os.remove(xml_path)

    if failures:
        # Ports found on the other addresses stay on their hosts; the module as a
        # whole did not complete, and the report must not read as a clean scan
        # for the addresses that were not covered.
        return ModuleResult(
            success=False,
            message=(f"nmap did not complete on {len(failures)} of {len(unique_ips)} addresses, so their open "
                     f"ports are unknown: " + "; ".join(failures))[:600],
        )

    return ModuleResult(success=True, message=f"Found {total_ports} open ports across {len(unique_ips)} IPs")


def _parse_nmap_xml(xml_path: str, ip: str, ip_to_hosts: dict) -> int:
    """Read open ports out of nmap's XML. Raises ET.ParseError on a broken file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    ports_found = 0

    for host_elem in root.findall(".//host"):
        for port_elem in host_elem.findall(".//port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_num = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = ""
            service_version = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                service_version = f"{product} {version}".strip()

            port = Port(
                number=port_num, protocol=protocol,
                state="open", service=service_name, version=service_version,
            )

            if ip in ip_to_hosts:
                for host in ip_to_hosts[ip]:
                    host.ports.append(port)
                    ports_found += 1

    return ports_found
