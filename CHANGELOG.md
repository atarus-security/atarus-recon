# Changelog

All notable changes to atarus-recon. Dates are commit dates. Version numbers in the early history were not strictly increasing (0.5.x builds landed before the 0.4.0 credcheck release); the git tags v0.4.0, v0.4.1 and v0.5.0 are the published releases.

## 0.6.0 (unreleased, refresh-2026-10)

### Security

- Fixed: the typed confirmation gate could never open on a real terminal. The terminal was opened in a mode that needs a seekable stream, which a terminal is not, so every interactive active run was refused with the no-terminal error and only --yes worked. The terminal is now opened as a raw descriptor and the prompt is written and read through it; verified on a pseudo-terminal.

- **Passive by default; active checks need `--active`, `--scope` and a typed confirmation.**

  What was wrong: a bare `atarus-recon -t example.com` port scanned every resolved IP with nmap, probed every web service with httpx, sent HEAD requests for WAF detection, opened TLS connections, ran every nuclei template at low severity and above, and drove a headless browser across the hosts, with no question asked. The only limit on where that traffic went was the name filter (anything ending in the target domain), so a subdomain pointing at a CDN, a SaaS vendor or a dangling record owned by someone else was scanned too. The person running the tool carried that exposure, and the project's own statement that active checks always ask was not true.

  What changed, in plain terms: a plain run now only asks public sources (crt.sh, subfinder's sources, DNS, whois, HaveIBeenPwned) and sends nothing to the target's hosts. To probe, you pass `--active` and a `--scope` listing the hosts, networks or domains you are authorized to touch; the tool resolves the names, shows you the scope, the active modules and every host with its IP, and waits for you to type `yes` on the terminal. Hosts that resolve outside the scope are listed as out of scope and never probed. The report records the mode, the scope, how the run was confirmed, and every module that did not run and why, so a passive report cannot be mistaken for a clean active one.

  Technically: `cli.MODULE_REGISTRY` carries an `active` flag per module (portscan, webprobe, waf, cert, nuclei and screenshot are active; crtsh, subfinder, resolve, whois, credcheck and risk are passive). `ReconRunner` refuses active modules unless constructed with `active=True` and an `ActiveScope`, runs the confirmation gate once before the first active module, and hands active modules a `result.hosts` restricted to the in-scope subset (`ActiveScope.split_hosts`), so a module cannot see an out-of-scope host at all. `scope.ActiveScope` parses `--scope` (file or list) into exact hosts, `*.domain` wildcards, addresses and CIDR networks, and `covers(name, ip)` matches by name or by resolved address. The confirmation is read from `/dev/tty` by `scope.read_tty_line`; stdin, environment variables and configuration files are not consulted, and click's environment-variable support is not enabled. `--yes` is accepted only with `--scope`, is printed at the start of the run and is stored in `ScanResult.confirmation`. `--active` without `--scope`, `--yes` without `--scope`, `--only` naming an active module without `--active`, and `--active` with neither a terminal nor `--yes` exit with a usage error (code 2) before any module runs. `ScanResult` gained `mode`, `active_scope`, `confirmation`, `modules_not_run` and `out_of_scope`; the HTML report shows them and says "Nuclei was not run" instead of "No vulnerabilities detected" when it did not run. Modules left out with `--skip` or `--only` are recorded there too. The version string now lives in `atarus_recon.__version__` and feeds the CLI, the User-Agent headers and the report.

  Known limits, still open: httpx and gowitness follow redirects off-domain, and the confirmation prompt shows resolved IPs but not their owner (CNAME target or ASN). Both are tracked in the README's Known issues.

### Fixed
- nuclei module: nuclei v3 removed `-json` and `-no-update-templates`, so nuclei exited with an error and every scan silently reported "No vulnerabilities found". The module now passes `-jsonl` and `-disable-update-check`.
- HTML report template moved into the package (`src/atarus_recon/templates/`), so non-editable installs (`pip install .`, pipx) can write reports.
- WeasyPrint is imported only for PDF export. The CLI now starts, and HTML and JSON reports work, on hosts without the Pango system libraries; a missing library produces a clear PDF error instead of a crash.
- Replaced deprecated `tempfile.mktemp` with `mkstemp` in the nuclei and webprobe modules.

### Added
- Offline unit tests (`tests/`) and a GitHub Actions workflow. `tests/test_passive_default.py` covers the passive default (every network sink mocked, socket layer guarded), the `--active` and `--yes` usage errors, out-of-scope skipping and the confirmation gate.
- `install-deps.sh` installs Pango for PDF export.
- `constraints.txt` with the dependency versions the tests last passed with.
- SECURITY.md and this changelog.

### Docs
- README: default is passive, how to run active checks, the scope and confirmation rules, a per-module table of what is sent over the network, WAF detection corrected (it sends a HEAD request, it is not passive). Earlier corrections: default output format is `all`, the whois module does not do ASN lookups, DNS wildcards are not detected, nmap max-rate is ten times `--rate-limit`, private IPs are not port scanned, nuclei v3 and a browser for gowitness are required.

## 0.5.0 (2026-04-27)
- Audit pass with 22 fixes across all modules.
- `install-deps.sh` bootstrap for external tools.

## 0.4.1 (2026-04-26)
- Bug fixes for resolve, webprobe and credcheck dependencies.

## 0.4.0 (2026-04-24)
- credcheck module: credential exposure via the HaveIBeenPwned domain breach API, hygiene score and remediation CSVs.

## Earlier builds (2026-04-12 to 2026-04-14)
- 0.1.0 initial release; 0.2.0 httpx probing, gowitness screenshots, CDN detection; 0.3.0 subfinder, WHOIS, module toggles; WAF detection and certificate analysis; nuclei scanning and risk scoring; tabbed HTML report; branded PDF export.
