# atarus-recon

External attack surface reconnaissance tool by [Atarus Offensive Security](https://atarussecurity.com).

Single command. Twelve modules. Every external recon step a pentester runs at the start of an engagement, chained into one branded report.

## Quick start

```bash
git clone https://github.com/atarus-security/atarus-recon.git
cd atarus-recon

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Install external tools (subfinder, httpx, nuclei, gowitness, nmap, whois)
./install-deps.sh

# Add Go binaries to PATH (one-time)
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc

# Run a scan
atarus-recon -t example.com --format all
```

The `install-deps.sh` script downloads prebuilt binaries directly from GitHub releases. No Go toolchain required. Works on Kali, Debian, Ubuntu, Arch, and Fedora.

If you prefer to install dependencies manually, see the per-module reference section below.

That single command produces:

- `atarus-recon-example.com.html` - tabbed report with risk overview, credential exposure, per-host findings
- `atarus-recon-example.com.pdf` - branded PDF export
- `atarus-recon-example.com.json` - machine-readable output
- `screenshots/` - PNG of every alive web service
- `credcheck-breaches-example.com.csv` and `credcheck-remediation-example.com.csv` if any breach exposure is found

## Modules

| Key | Description | External tool required |
|---|---|---|
| crtsh | Certificate transparency subdomain enumeration | None |
| subfinder | Passive subdomain enumeration | subfinder |
| resolve | DNS resolution and alive filtering | None |
| whois | WHOIS lookup and ASN identification | None |
| portscan | TCP port scan with service detection | nmap |
| webprobe | Web service fingerprinting | httpx (projectdiscovery) |
| waf | WAF and CDN protection detection | None |
| cert | TLS certificate inspection | None |
| nuclei | Templated vulnerability scanning | nuclei |
| screenshot | Visual capture of alive web services | gowitness |
| credcheck | Credential exposure via HaveIBeenPwned | None |
| risk | Per-host risk scoring | None |

Every module is independently toggleable via `--skip` or `--only`. The pipeline order is fixed (recon -> enrichment -> analysis) so dependent modules always have the data they need.

## Module reference

### crtsh

Queries `crt.sh` certificate transparency logs for subdomains of the target. Pulls every certificate ever issued for `*.example.com` and extracts the Common Names and Subject Alternative Names.

**Output added to scan**: new `Host` entries (hostname only, no IP yet)

**Notes for pentesters**:
- crt.sh times out occasionally on large domains. The module logs a warning and continues. Other modules still run.
- This is your first source of subdomain coverage. Combine with subfinder for breadth.
- Returns historical certificates, including subdomains that no longer resolve. The `resolve` module filters out the dead ones.

**No external tool required.** Pure Python via urllib.

---

### subfinder

Wraps the [subfinder](https://github.com/projectdiscovery/subfinder) binary to perform passive subdomain enumeration across multiple sources (VirusTotal, AlienVault, Wayback, etc).

**Output added to scan**: new `Host` entries

**Install subfinder**:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**Notes for pentesters**:
- Some sources require API keys configured in `~/.config/subfinder/provider-config.yaml`. Without keys you still get coverage from free sources.
- Combine with crtsh for maximum coverage. Each finds subdomains the other misses.
- If subfinder is not installed, the module logs a warning and skips. Pipeline continues.

---

### resolve

Resolves every collected subdomain via DNS. Hosts that resolve to an IP are kept. Dead subdomains are filtered out.

**Output added to scan**: `Host.ip` populated for every alive host

**Notes for pentesters**:
- Uses dnspython for direct DNS resolution. Honors system resolver config.
- Handles wildcards by detecting hosts that all resolve to the same catch-all IP.
- This is the gate between "we found a subdomain string" and "this subdomain actually exists."

**No external tool required.**

---

### whois

Pulls WHOIS data for the root domain plus ASN information for the primary IP.

**Output added to scan**: `result.whois_data` dict with registrar, creation date, expiration date, name servers, organization, registrant

**Notes for pentesters**:
- WHOIS can hang on certain TLDs. Module has a 10 second timeout per record.
- Most registrars now redact registrant info. You will often see "REDACTED FOR PRIVACY". This is normal.
- ASN lookup tells you the network the target is hosted on (AWS, Cloudflare, GoDaddy, etc).

**No external tool required.**

---

### portscan

Runs nmap against every alive host. Default scope is the top 100 TCP ports with service version detection (`-sV --top-ports 100`).

**Output added to scan**: `Host.ports` list of `Port` objects with number, protocol, state, service name, version, banner

**Install nmap**:
```bash
sudo apt install nmap
```

**Notes for pentesters**:
- This module IS noisy. Nmap with version detection probes every port. If your engagement requires stealth, skip this module with `--skip portscan`.
- Service detection accuracy depends on nmap version and signature database. Run `sudo nmap --script-updatedb` to refresh.
- Banner grabbing is on by default. Sensitive services like SMB and RDP get probed. Be sure your scope authorizes this.
- Rate limit (`--rate-limit`) controls nmap's `--max-rate` option. Default 10 req/s is conservative.

---

### webprobe

Wraps [httpx](https://github.com/projectdiscovery/httpx) to identify alive web services. Pulls HTTP status code, page title, technology stack via Wappalyzer signatures, and CDN indicators.

**Output added to scan**: `Host.status_code`, `Host.title`, `Host.technologies`, `Host.cdn`, `Host.cdn_name`

**Install httpx**:
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Notes for pentesters**:
- Tech detection is signature-based. False positives happen, especially on minified or proxied sites.
- HTTP/2 and HTTP/3 are detected and surfaced as technologies.
- Status codes flag interesting responses: 401 (auth required), 403 (access denied), 500 (server error). Useful for prioritizing which subdomains to dig into.

---

### waf

Inspects HTTP responses for headers and behaviors that indicate a Web Application Firewall or CDN protection layer.

**Output added to scan**: `Host.waf` populated with detected protection name (Cloudflare, Akamai, AWS WAF, F5, Imperva, etc)

**Notes for pentesters**:
- Detection is passive. No probing or rule fingerprinting. Just header inspection.
- A detected WAF does NOT mean exploitation is impossible. It means your nuclei results need to be validated manually because some templates trigger WAF blocks before reaching the actual app.
- CDN identification often overlaps with WAF detection (Cloudflare runs both).

**No external tool required.**

---

### cert

Pulls and analyzes TLS certificates from every web service identified by webprobe. Extracts issuer, subject, validity period, SANs, and signature algorithm.

**Output added to scan**: `Host.cert_data` dict per host

**Notes for pentesters**:
- Expired certs and weak signature algorithms (SHA-1, MD5) are flagged.
- SANs in the cert often expose additional subdomains. Cross-reference against your subfinder results.
- Self-signed certs on production-looking domains are immediately suspicious.

**No external tool required.** Uses Python ssl module.

---

### nuclei

Runs the [nuclei](https://github.com/projectdiscovery/nuclei) scanner with default templates against every web service. Produces per-host findings.

**Output added to scan**: `Host.findings` list per host, plus aggregated `result.findings`

**Install nuclei**:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

**Notes for pentesters**:
- Nuclei is loud. WAFs will see this. Plan accordingly.
- The default template set includes thousands of checks. Expect false positives on heavily customized sites.
- Severity levels from nuclei (info/low/medium/high/critical) flow directly into the report.
- This is the slowest module in the pipeline. Use `--skip nuclei` for fast scans.
- Run `nuclei -update-templates` periodically. The default template set updates frequently.

---

### screenshot

Captures full-page screenshots of every alive web service using [gowitness](https://github.com/sensepost/gowitness).

**Output added to scan**: `Host.screenshot_path` populated, PNGs saved to `output/screenshots/`

**Install gowitness**:
```bash
go install github.com/sensepost/gowitness@latest
```

**Notes for pentesters**:
- Screenshots embed inline in the HTML report. Critical for client-facing deliverables.
- Headless browser drives Chrome under the hood. Requires Chromium installed.
- Slow against large host counts. Each screenshot takes 5-10 seconds.

---

### credcheck

Checks for known data breaches affecting the target domain via the HaveIBeenPwned `/breaches?domain=` endpoint. Computes credential hygiene score and produces actionable remediation CSVs.

**Output added to scan**: `result.credential_exposure` populated with breaches list, total accounts affected, hygiene score 0-100, hygiene rating (clean / fair / poor / critical / severe), plus per-breach `Finding` entries

**No external tool required.**

**No API key required.** Uses HIBP free domain endpoint.

**What this module does**:
- Identifies every breach affecting the target domain
- Returns breach date, accounts exposed, data classes leaked, and severity
- Scores credential hygiene weighted by breach count, recency, scale, and data class severity
- Generates `credcheck-breaches-<domain>.csv` (raw data)
- Generates `credcheck-remediation-<domain>.csv` (priority-sorted action plan for client)

**What this module does NOT do**:
- Does not retrieve individual compromised email addresses (requires paid HIBP API key)
- Does not check paste sites, dark web, or stealer logs (requires different data sources)
- Does not validate that breach data is still active or weaponizable

**Hygiene scoring weights**:
- Each breach: -8 points baseline
- Breach within last year: additional -15 points
- Breach within last 3 years: additional -8 points
- 100M+ accounts exposed: -20 points
- 10M-100M accounts: -15 points
- Passwords/credit cards/SSNs in data classes: -10 points
- Sensitive flag set: -5 points

Ratings: clean (80-100), fair (60-79), poor (40-59), critical (20-39), severe (0-19)

---

### risk

Aggregates module outputs into a per-host risk score. Considers open ports, exposed admin services, technology age, missing protections, and any nuclei findings.

**Output added to scan**: `Host.risk_score` (0-100) and `Host.risk_level` (low / medium / high / critical) per host

**Notes for pentesters**:
- This is a heuristic score, not a CVSS calculation. Use it for prioritization, not as a final risk rating.
- Hosts with no WAF, exposed admin panels (status 401/403 on /admin paths), and outdated technology stacks score highest.
- The HTML report's risk overview tab shows hosts ranked by this score.

**No external tool required.**

## Usage

### Common patterns

```bash
# Default: full scan, HTML report only
atarus-recon -t example.com

# All output formats (HTML, PDF, JSON, CSVs)
atarus-recon -t example.com --format all

# Quick scan: skip slow or noisy modules
atarus-recon -t example.com --skip nuclei,screenshot,portscan

# Targeted: only credential exposure check
atarus-recon -t example.com --only credcheck --format all

# Targeted: subdomain discovery only
atarus-recon -t example.com --only crtsh,subfinder,resolve

# Stealth mode: passive only, no active scanning
atarus-recon -t example.com --skip portscan,nuclei,webprobe,screenshot

# Custom output directory
atarus-recon -t example.com -o ./engagements/acme/recon

# List all modules
atarus-recon --list-modules

# Show version
atarus-recon --version
```

### Rate limiting

```bash
# Default: 10 req/s
atarus-recon -t example.com

# Conservative (avoid WAF triggers)
atarus-recon -t example.com --rate-limit 5

# Aggressive (own infrastructure or authorized stress test)
atarus-recon -t example.com --rate-limit 50
```

### Scope enforcement

The tool enforces scope to the target domain and its subdomains. Hosts outside `*.example.com` discovered during recon are filtered out before any active probing. This prevents accidental out-of-scope scanning.

If you need to scan multiple unrelated domains, run the tool once per target.

## Reports

### HTML

Tabbed dark-themed report with sections for risk overview, credential exposure, top findings, per-host details, and infrastructure. Inline screenshots. Designed to be the artifact you hand to a client without any post-processing.

### PDF

Branded export of the HTML report. Page numbers, confidential footer, Atarus branding. Ready to attach to a client email.

### JSON

Full machine-readable output of every collected datapoint. Use for SIEM/SOAR integration, custom dashboards, or piping into other tools.

### CSV (credcheck only)

Two CSVs generated when credential exposures are found:
- `credcheck-breaches-<domain>.csv`: raw breach data
- `credcheck-remediation-<domain>.csv`: priority-sorted remediation plan

## Adding a custom module

Every module is a function with this signature:

```python
def run(result: ScanResult, scope: ScopeValidator, rate_limit: int, verbose: bool) -> ModuleResult:
    """Module docstring"""
    # ... do work ...
    return ModuleResult(success=True, message="Did the thing")
```

Save it as `src/atarus_recon/modules/yourmodule.py`. Register it in `cli.py`:

```python
from atarus_recon.modules import yourmodule

MODULE_REGISTRY = [
    # ... existing modules ...
    ("My new module", "yourmodule", yourmodule.run),
]
```

Reinstall with `pip install -e .` and your module is now available via `--only yourmodule`.

The module receives the running `ScanResult`, a `ScopeValidator` for safety checks, the rate limit setting, and a verbose flag. Mutate `result` to add findings, hosts, or custom data.

## Try it

Quick credcheck-only test against a domain with known breach exposure:

```bash
atarus-recon -t adobe.com --only credcheck --format all -v
```

Full scan against your own domain (always safe):

```bash
atarus-recon -t yourcompany.com --format all -v
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
