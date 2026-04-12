import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
from atarus_recon.models import ScanResult, Port
from atarus_recon.scope import ScopeValidator
from atarus_recon.runner import ModuleResult


def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Run nmap port scan against alive hosts"""

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

            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            ports_found = _parse_nmap_xml(xml_path, ip, ip_to_hosts)
            total_ports += ports_found

        except subprocess.TimeoutExpired:
            if verbose:
                print(f"  Nmap timeout on {ip}")
        except FileNotFoundError:
            return ModuleResult(success=False, message="nmap not found in PATH")
        finally:
            if xml_path and os.path.exists(xml_path):
                os.remove(xml_path)

    return ModuleResult(success=True, message=f"Found {total_ports} open ports across {len(unique_ips)} IPs")


def _parse_nmap_xml(xml_path: str, ip: str, ip_to_hosts: dict) -> int:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return 0

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
