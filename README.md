# atarus-recon

External attack surface reconnaissance tool by [Atarus Offensive Security](https://atarussecurity.com).

Single CLI command chains subdomain enumeration, DNS resolution, port scanning, service fingerprinting, WAF detection, certificate analysis, vulnerability scanning, screenshot capture, credential exposure checks, and risk scoring into a unified, branded report.

## Modules

| Key | Description |
|---|---|
| crtsh | Certificate transparency subdomain enumeration |
| subfinder | Passive subdomain enumeration via subfinder |
| resolve | DNS resolution and alive filtering |
| whois | WHOIS and ASN lookup |
| portscan | Port scanning via nmap |
| webprobe | Web service fingerprinting (httpx) |
| waf | WAF and protection detection |
| cert | TLS certificate analysis |
| nuclei | Vulnerability scanning via nuclei templates |
| screenshot | Screenshot capture of alive web services |
| credcheck | Credential exposure check via HaveIBeenPwned domain API |
| risk | Per-host risk scoring |

## What each run produces

- **HTML report**: dark-themed, branded, includes risk overview, credential exposure section, per-host details with technologies and screenshots, and ranked findings
- **PDF export**: same content as HTML, ready to hand to a client
- **JSON**: full machine-readable output for SIEM/SOAR integration
- **CSV exports** (when credential exposures are found):
  - `credcheck-breaches-<domain>.csv`: raw breach data (name, date, accounts affected, data classes)
  - `credcheck-remediation-<domain>.csv`: actionable remediation plan with priority, severity, effort estimate, and rationale

## Install

```bash
git clone https://github.com/atarus-security/atarus-recon.git
cd atarus-recon
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Requirements

- Python 3.10+
- External tools (optional, for full module coverage):
  - subfinder
  - nmap
  - httpx (projectdiscovery)
  - nuclei

Core modules (crtsh, resolve, credcheck, risk) work without any external tools.

## Usage

```bash
# Full scan, HTML report only
atarus-recon -t example.com

# Full scan, all output formats
atarus-recon -t example.com --format all

# Skip slow or noisy modules
atarus-recon -t example.com --skip nuclei,screenshot

# Run only specific modules
atarus-recon -t example.com --only crtsh,credcheck

# List all modules
atarus-recon --list-modules

# Verbose output
atarus-recon -t example.com -v
```

## Credential exposure (credcheck module)

Queries the free HaveIBeenPwned domain breach endpoint to identify data breaches affecting the target domain. No API key required.

For each breach found:
- Breach name, date, and number of accounts affected
- Data classes exposed (passwords, emails, credit cards, etc.)
- Whether the breach is marked sensitive

Generates a credential hygiene score (0-100) and rating (clean, fair, poor, critical, severe) based on:
- Number of breaches
- Recency (breaches in the last 2 years weighted heavily)
- Scale of exposure (millions of accounts vs. thousands)
- Severity of exposed data classes (passwords and financial data weighted highest)

**What this module does NOT do:**
- Does not retrieve individual compromised email addresses (requires paid HIBP API key)
- Does not check paste sites or dark web (requires different data sources)
- Does not validate that breach data is still actively being used

Results are best used as a starting point for client conversations about credential hygiene and MFA enforcement policy.

## Try it

```bash
# Quick test against adobe.com (known breach)
atarus-recon -t adobe.com --only credcheck --format all -v
```

## Part of the atarus- tool suite

- **atarus-recon** - External attack surface recon (you are here)
- **[atarus-cloud](https://github.com/atarus-security/atarus-cloud)** - Multi-cloud security scanner (AWS + Azure)
- **[atarus-phishcheck](https://github.com/atarus-security/atarus-phishcheck)** - Email security analyzer
- **[atarus-report-kit](https://github.com/atarus-security/atarus-report-kit)** - Pentest report builder for juniors and students

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)

We are building the groundwork for the AI pentesting tool of the future, one module at a time.
