# atarus-recon

External attack surface reconnaissance tool by [Atarus Offensive Security](https://atarussecurity.com).

One command. Full recon. Clean report.

## What it does

- Subdomain enumeration via certificate transparency logs
- DNS resolution with alive host detection
- Port scanning with service version detection (via nmap)
- Web service probing with HTTP status codes and page titles
- Technology fingerprinting (frameworks, CDNs, web servers)
- CDN detection and identification
- Screenshot capture of all live web services
- Professional HTML report with executive summary and inline screenshots
- JSON export for integration with other tools
- Scope enforcement to prevent out-of-scope scanning

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
- Linux (tested on Kali Linux)

### Install dependencies on Kali

```bash
sudo apt install nmap -y
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/sensepost/gowitness@latest
```

## Usage

```bash
# Basic scan with HTML report
atarus-recon -t example.com

# JSON output
atarus-recon -t example.com --format json

# Both HTML and JSON
atarus-recon -t example.com --format both

# Custom output directory and verbose
atarus-recon -t example.com -o ./reports -v

# Adjust rate limiting
atarus-recon -t example.com --rate-limit 20

# Check version
atarus-recon --version
```

## Pipeline

atarus-recon runs five modules in sequence:

1. Subdomain enumeration (crt.sh certificate transparency)
2. DNS resolution (filters alive hosts)
3. Port scanning (nmap top 100 ports with service detection)
4. Web probing (httpx for status codes, titles, tech stack)
5. Screenshot capture (gowitness for visual evidence)

## Output

Reports are saved to ./output/ by default.

- HTML: Visual report with summary dashboard, per-host breakdown, tech tags, and inline screenshots
- JSON: Machine-readable output for piping into other tools
- Screenshots: Saved to ./output/screenshots/

## Adding modules

Every module is a function with this signature:

```python
def run(result, scope, rate_limit, verbose) -> ModuleResult:
```

Register it in cli.py:

```python
runner.register("My new module", my_module.run)
```

## Roadmap

- Subfinder integration for expanded subdomain coverage
- Nuclei vulnerability scanning
- Email enumeration
- PDF report export

## License

MIT License. See LICENSE for details.

## Built by

[Atarus Offensive Security LLC](https://atarussecurity.com)
