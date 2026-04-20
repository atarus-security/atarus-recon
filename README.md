# atarus-recon

External attack surface reconnaissance and vulnerability scanning tool by [Atarus Offensive Security](https://atarussecurity.com).

One command. Full recon. Clean report.

## What it does

**Discovery**
- Subdomain enumeration via certificate transparency logs and Subfinder (40+ passive sources)
- DNS resolution with alive host detection
- WHOIS and ASN lookup

**Scanning**
- Port scanning with service version detection (nmap)
- Web service probing with HTTP status codes, page titles, and tech fingerprinting
- WAF and CDN detection
- SSL/TLS certificate analysis (expiry, self-signed, wildcard detection)
- Screenshot capture of all live web services

**Vulnerability detection**
- Nuclei vulnerability scanning with severity-based findings
- Risk scoring engine that rates each host by exposure level

**Output**
- Professional HTML report with executive summary, risk indicators, and inline screenshots
- JSON export for integration with other tools
- Module toggle system to run only what you need

## Install

```bash
git clone https://github.com/atarus-security/atarus-recon.git
cd atarus-recon
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Requirements

- Python 3.10+
- nmap
- httpx (ProjectDiscovery)
- gowitness v3
- nuclei
- subfinder
- Linux (tested on Kali Linux)

### Install dependencies on Kali

```bash
sudo apt install nmap golang -y
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
echo 'export PATH="\$HOME/go/bin:\$PATH"' >> ~/.zshrc
source ~/.zshrc
nuclei -update-templates
```

## Usage

```bash
# Full scan with all 11 modules
atarus-recon -t example.com

# Skip slow modules for fast recon
atarus-recon -t example.com --skip portscan,screenshot

# Run only subdomain enumeration
atarus-recon -t example.com --only crtsh,subfinder,resolve

# Both HTML and JSON output
atarus-recon -t example.com --format both -v

# List all available modules
atarus-recon --list-modules

# Check version
atarus-recon --version
```

## Modules

| Key | Module | Phase |
|---|---|---|
| crtsh | crt.sh certificate transparency | Discovery |
| subfinder | Subfinder passive enumeration | Discovery |
| resolve | DNS resolution | Discovery |
| whois | WHOIS and ASN lookup | Discovery |
| portscan | nmap port scanning | Scanning |
| webprobe | httpx web probing and tech detection | Scanning |
| waf | WAF and CDN detection | Scanning |
| cert | SSL/TLS certificate analysis | Scanning |
| nuclei | Nuclei vulnerability scanning | Vulnerability |
| screenshot | gowitness screenshot capture | Evidence |
| risk | Risk scoring engine | Analysis |

All modules run by default. Use --skip or --only to customize.

## Pipeline

atarus-recon runs modules in sequence:

1. Subdomain enumeration (crt.sh + subfinder)
2. DNS resolution
3. WHOIS/ASN lookup
4. Port scanning
5. Web probing and tech fingerprinting
6. WAF/CDN detection
7. Certificate analysis
8. Vulnerability scanning (nuclei)
9. Screenshot capture
10. Risk scoring

## Output

Reports saved to ./output/ by default.

- HTML: Visual report with summary dashboard, risk scores, tech tags, findings, and screenshots
- JSON: Machine-readable output for piping into other tools
- Screenshots: Saved to ./output/screenshots/

## Adding modules

Every module is a function with this signature:

```python
def run(result, scope, rate_limit, verbose) -> ModuleResult:
```

Register it in cli.py:

```python
runner.register("My module", "mykey", my_module.run)
```

## Roadmap

- Email enumeration and password spray prep
- Cloud resource discovery (S3, Azure blobs, dangling DNS)
- JavaScript secrets scraping
- Executive summary auto-generation
- PDF export with Atarus branding
- Scan comparison mode (diff two scans)
- GitHub/GitLab dorking

## Part of the atarus- tool suite

Open source offensive security tools built by practitioners.

- **atarus-recon** - External attack surface recon (you are here)
- **[atarus-cloud](https://github.com/atarus-security/atarus-cloud)** - Multi-cloud misconfiguration scanner
- **[atarus-report-kit](https://github.com/atarus-security/atarus-report-kit)** - Single-file offline pentest reporting tool

## License

MIT License. See LICENSE for details.

## Built by

[Atarus Offensive Security LLC](https://atarussecurity.com)
