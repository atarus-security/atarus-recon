# atarus-recon

External attack surface reconnaissance tool by [Atarus Offensive Security](https://atarussecurity.com).

Single command. Twelve modules. Every external recon step a pentester runs at the start of an engagement, chained into one branded report.

Passive by default. A plain run only asks public sources (certificate transparency, subfinder's passive sources, DNS, whois, HaveIBeenPwned) and sends nothing to the target's own hosts. The six modules that do send packets to the target (port scan, web probe, WAF check, certificate grab, nuclei, screenshots) run only behind `--active`, only against hosts inside a `--scope` you provide, and only after you type `yes` on the terminal. See [Passive by default, active on request](#passive-by-default-active-on-request).

## Quick start

```bash
git clone https://github.com/atarus-security/atarus-recon.git
cd atarus-recon

# Install Python dependencies (Python 3.10 or newer)
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Install external tools (subfinder, httpx, nuclei, gowitness, nmap, whois)
# plus the Pango libraries WeasyPrint needs for PDF export
./install-deps.sh

# Add Go binaries to PATH (one-time)
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc

# Passive run (default): public sources only, nothing sent to example.com's hosts
atarus-recon -t example.com

# Active run: port scan, web probe, nuclei and screenshots against the hosts you
# place in scope. Prints the scope and the hosts to be probed, then waits for
# you to type yes on the terminal.
atarus-recon -t example.com --active --scope 'example.com,*.example.com'
```

The `install-deps.sh` script downloads prebuilt binaries directly from GitHub releases. No Go toolchain required. Works on Kali, Debian, Ubuntu, Arch, and Fedora.

PDF export uses WeasyPrint, which needs the Pango system libraries. `install-deps.sh` installs them; to install them by hand on Debian or Kali run `sudo apt install libpango-1.0-0 libpangoft2-1.0-0`. Without them the scan, HTML and JSON reports still work and the PDF step prints an error.

nuclei v3 is required (the module uses the v3 `-jsonl` and `-disable-update-check` flags). The screenshot module needs Chromium or Chrome installed for gowitness; `install-deps.sh` does not install a browser.

`constraints.txt` lists the dependency versions the test suite last passed with. To reproduce that environment: `pip install -c constraints.txt -e .`

If you prefer to install dependencies manually, see the per-module reference section below.

A run produces:

- `atarus-recon-example.com.html` - tabbed report with risk overview, credential exposure, per-host findings, the run mode, and every module that did not run with the reason
- `atarus-recon-example.com.pdf` - branded PDF export
- `atarus-recon-example.com.json` - machine-readable output, including `mode`, `active_scope`, `confirmation`, `modules_not_run` and `out_of_scope`
- `screenshots/` - PNG of every alive web service (active runs only)
- `credcheck-breaches-example.com.csv` and `credcheck-remediation-example.com.csv` if any breach exposure is found

A passive report has no open ports, web fingerprints, certificate data, nuclei findings or screenshots. It says so: the report lists the six active modules as not run rather than showing an empty, clean-looking section.

## Modules

| Key | Mode | Description | External tool required |
|---|---|---|---|
| crtsh | passive | Certificate transparency subdomain enumeration | None |
| subfinder | passive | Passive subdomain enumeration | subfinder |
| resolve | passive | DNS resolution and alive filtering | None |
| whois | passive | WHOIS lookup | None (uses the system `whois` command when present) |
| portscan | active | TCP port scan with service detection | nmap |
| webprobe | active | Web service fingerprinting | httpx (projectdiscovery) |
| waf | active | WAF and CDN protection detection | None |
| cert | active | TLS certificate inspection | None |
| nuclei | active | Templated vulnerability scanning | nuclei |
| screenshot | active | Visual capture of alive web services | gowitness |
| credcheck | passive | Credential exposure via HaveIBeenPwned | None |
| risk | passive | Per-host risk scoring | None |

Every module is independently toggleable via `--skip` or `--only`. The pipeline order is fixed (recon -> enrichment -> analysis) so dependent modules always have the data they need. Active modules additionally need `--active` and `--scope`; `--only portscan` without them is an error, not a silent scan. `atarus-recon --list-modules` shows the mode of each module.

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
- Wildcard DNS is not detected. If the target has a wildcard record, every enumerated name will resolve; check for this manually.
- This is the gate between "we found a subdomain string" and "this subdomain actually exists."

**No external tool required.**

---

### whois

Pulls WHOIS data for the root domain.

**Output added to scan**: `result.whois_data` dict with registrar, creation date, expiration date, name servers, organization, registrant

**Notes for pentesters**:
- WHOIS can hang on certain TLDs. The module runs the system `whois` command with a 12 second timeout and falls back to python-whois if the command is missing.
- Most registrars now redact registrant info. You will often see "REDACTED FOR PRIVACY". This is normal.

**No external tool required.**

---

### portscan

**Active module.** Runs only with `--active`, against hosts inside `--scope`, after the terminal confirmation.

Runs nmap against every in-scope alive host. Default scope is the top 100 TCP ports with service version detection (`-sV --top-ports 100`).

**Output added to scan**: `Host.ports` list of `Port` objects with number, protocol, state, service name, version, banner

**Install nmap**:
```bash
sudo apt install nmap
```

**Notes for pentesters**:
- This module IS noisy. Nmap with version detection probes every port. If your engagement requires stealth, leave `--active` off or skip this module with `--skip portscan`.
- Service detection accuracy depends on nmap version and signature database. Run `sudo nmap --script-updatedb` to refresh.
- Banner grabbing is on by default. Sensitive services like SMB and RDP get probed. Be sure your scope authorizes this.
- nmap's `--max-rate` is set to ten times `--rate-limit`, so the default of 10 gives 100 packets per second.
- Only public IP addresses are scanned. Hosts that resolve to private, loopback or link-local addresses are skipped.

---

### webprobe

**Active module.** Runs only with `--active`, against hosts inside `--scope`, after the terminal confirmation.

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

**Active module.** Runs only with `--active`, against hosts inside `--scope`, after the terminal confirmation.

Sends one HTTPS HEAD request to `/` on every in-scope web host (then HTTP if HTTPS fails) and inspects the response headers for signatures of a Web Application Firewall or CDN protection layer.

**Output added to scan**: `Host.waf` populated with detected protection name (Cloudflare, Akamai, AWS WAF, F5, Imperva, etc)

**Notes for pentesters**:
- One HEAD request per host, no rule fingerprinting or attack payloads. Header inspection only, but it is a request to the target, so it is an active module.
- A detected WAF does NOT mean exploitation is impossible. It means your nuclei results need to be validated manually because some templates trigger WAF blocks before reaching the actual app.
- CDN identification often overlaps with WAF detection (Cloudflare runs both).

**No external tool required.**

---

### cert

**Active module.** Runs only with `--active`, against hosts inside `--scope`, after the terminal confirmation.

Opens a TLS connection to port 443 on every in-scope web host and analyzes the certificate from every web service identified by webprobe. Extracts issuer, subject, validity period, SANs, and signature algorithm.

**Output added to scan**: `Host.cert_data` dict per host

**Notes for pentesters**:
- Expired certs and weak signature algorithms (SHA-1, MD5) are flagged.
- SANs in the cert often expose additional subdomains. Cross-reference against your subfinder results.
- Self-signed certs on production-looking domains are immediately suspicious.

**No external tool required.** Uses Python ssl module.

---

### nuclei

**Active module.** Runs only with `--active`, against hosts inside `--scope`, after the terminal confirmation.

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
- This is the slowest module in the pipeline. Use `--skip nuclei` for fast active scans.
- Run `nuclei -update-templates` periodically. The default template set updates frequently.

---

### screenshot

**Active module.** Runs only with `--active`, against hosts inside `--scope`, after the terminal confirmation.

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
# Default: passive run, all report formats (HTML, PDF, JSON, CSVs). Nothing is
# sent to example.com's hosts.
atarus-recon -t example.com

# Active run against the apex and every subdomain. You are shown the scope,
# the active modules and each host with its resolved IP, then type yes.
atarus-recon -t example.com --active --scope 'example.com,*.example.com'

# Active run limited to the client's address ranges; names that resolve
# elsewhere (CDN, SaaS front ends) are reported as out of scope and skipped
atarus-recon -t example.com --active --scope ./engagements/acme/scope.txt

# Non-interactive active run (CI, cron): --yes stands in for the typed word,
# is only accepted together with --scope, and is recorded in the report
atarus-recon -t example.com --active --scope ./scope.txt --yes

# Quick active scan: skip the slow modules
atarus-recon -t example.com --active --scope ./scope.txt --skip nuclei,screenshot

# Targeted: only credential exposure check
atarus-recon -t example.com --only credcheck --format all

# Targeted: subdomain discovery only
atarus-recon -t example.com --only crtsh,subfinder,resolve

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

## Passive by default, active on request

atarus-recon follows one rule: it observes and reports by default, and it probes a live system only when you placed that system in scope and confirmed it yourself.

### Passive mode (default)

Without `--active`, only the passive modules run: `crtsh`, `subfinder`, `resolve`, `whois`, `credcheck` and `risk`. They ask public sources about the target; none of them sends a packet to the target's own hosts. The six active modules are listed in the terminal and in the report as "not run", with the reason, so a passive report never reads as a clean active scan.

### Active mode

`--active` enables `portscan`, `webprobe`, `waf`, `cert`, `nuclei` and `screenshot`. It needs two more things:

1. **A scope lock.** `--scope` takes a file (one entry per line, `#` comments allowed) or a comma-separated list. Four entry forms:

   | Entry | Covers |
   |---|---|
   | `app.example.com` | exactly that host |
   | `*.example.com` | every name under `example.com`, at any depth, but not the apex |
   | `203.0.113.7` | that address |
   | `203.0.113.0/24` | every address in that network |

   A discovered host is probed only if its name matches a host or domain entry, or its resolved address falls inside a network entry. Everything else is listed as out of scope, in the terminal, the HTML report and the JSON (`out_of_scope`), and is never handed to an active module. Discovery (crt.sh, subfinder) is still limited to the target domain and its subdomains, as before.

2. **A confirmation the software cannot give for you.** Before the first packet to the target, after the passive modules have resolved the hosts, the tool prints the exact scope, the list of active modules, and every host that will be probed with its resolved IP, then waits for you to type the word `yes` on the controlling terminal (`/dev/tty`). Anything else, end of file, or no terminal at all means the active modules do not run; the passive results and the report are still written.

   For non-interactive runs, `--yes` stands in for the typed word. It is accepted only together with `--scope`, it is printed at the start of the run, and it is recorded in the report (`confirmation`). No environment variable and no configuration file can stand in for the confirmation: the tool reads neither for these options. An automation or AI agent driving the CLI can pass flags, but it cannot answer `/dev/tty`, which is the point.

   `--active` without `--scope`, `--yes` without `--scope`, `--only` naming an active module without `--active`, and `--active` with neither a terminal nor `--yes` all stop with a usage error before anything runs.

If you need to scan multiple unrelated domains, run the tool once per target, each with its own scope.

### What this tool sends over the network

| Module | Mode | Destination | What is sent | When |
|---|---|---|---|---|
| crtsh | passive | crt.sh over HTTPS | one GET with the target domain in the query | every run |
| subfinder | passive | the passive sources subfinder is configured for (third parties, not the target) | the target domain, once per source | when subfinder is installed |
| resolve | passive | your system's DNS resolver | an A query per discovered name. The recursive resolver may in turn ask the target's authoritative name servers; atarus-recon itself sends nothing to the target | every run |
| whois | passive | the registry's whois server, via the system `whois` command or python-whois | the target domain | every run |
| credcheck | passive | haveibeenpwned.com over HTTPS | one GET with the target domain | every run |
| risk | passive | nothing | nothing, computed offline | every run |
| portscan | active | every in-scope resolved public IP | nmap TCP connect scan of the top 100 ports with version probes (`-sT -sV`), up to ten times `--rate-limit` packets per second | `--active` only, after confirmation |
| webprobe | active | every in-scope alive host, HTTP and HTTPS | httpx GET requests, following redirects | `--active` only, after confirmation |
| waf | active | every in-scope web host | one HTTPS HEAD request to `/`, then HTTP if that fails | `--active` only, after confirmation |
| cert | active | every in-scope web host, port 443 | one TLS handshake | `--active` only, after confirmation |
| nuclei | active | every in-scope web host | nuclei templates at low severity and above: many HTTP requests per host | `--active` only, after confirmation |
| screenshot | active | every in-scope web host | headless browser page loads through gowitness, following navigations | `--active` only, after confirmation |

The target domain is disclosed to the passive third parties (crt.sh, subfinder's sources, whois, HaveIBeenPwned). Skip a module with `--skip` if an engagement forbids that.

### Known issues

- Redirects: httpx (`-follow-redirects`) and gowitness follow redirects wherever they point, so an in-scope host that redirects off-domain still causes a request to the redirect target. Off-scope redirect blocking is planned.
- The scope check is by name or by resolved IP; it does not yet show the owner of each IP (CNAME target, ASN) at the confirmation prompt. Check the printed IPs against your authorization before typing yes.

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
    # (name, key, function, active). active=True if the module sends anything
    # to the target's own hosts; it then runs only behind --active and --scope.
    ("My new module", "yourmodule", yourmodule.run, True),
]
```

Reinstall with `pip install -e .` and your module is now available via `--only yourmodule`.

The module receives the running `ScanResult`, a `ScopeValidator` for safety checks, the rate limit setting, and a verbose flag. Mutate `result` to add findings, hosts, or custom data. An active module is only ever handed the hosts inside `--scope`: the runner swaps `result.hosts` for the in-scope subset while the module runs, so you do not need to check scope yourself, and you must not cache or replace `result.hosts`. Add a row to the network table above for any new module.

## Try it

Quick credcheck-only test against a domain with known breach exposure:

```bash
atarus-recon -t adobe.com --only credcheck --format all -v
```

Passive run against your own domain:

```bash
atarus-recon -t yourcompany.com --format all -v
```

Active run against your own domain, once you have confirmed the resolved IPs are yours:

```bash
atarus-recon -t yourcompany.com --active --scope 'yourcompany.com,*.yourcompany.com' -v
```

## Part of the atarus- tool suite

- **atarus-recon** - External attack surface recon (you are here)
- **[atarus-cloud](https://github.com/atarus-security/atarus-cloud)** - Multi-cloud security scanner (AWS + Azure)
- **[atarus-phishcheck](https://github.com/atarus-security/atarus-phishcheck)** - Email security analyzer
- **[atarus-report-kit](https://github.com/atarus-security/atarus-report-kit)** - Pentest report builder for juniors and students
- **[atarus-webscan](https://github.com/atarus-security/atarus-webscan)** - Web application security scanner

## Testing

```bash
python -m unittest discover -s tests -v
```

The tests are offline and use only the standard library. GitHub Actions runs them on every push and pull request (`.github/workflows/tests.yml`).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability. The default run is passive. Only use `--active` against hosts you own or are authorized in writing to test, and put exactly those hosts in `--scope`.

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)

We are building the groundwork for the AI pentesting tool of the future, one module at a time.
