# Changelog

All notable changes to atarus-recon. Dates are commit dates. Version numbers in the early history were not strictly increasing (0.5.x builds landed before the 0.4.0 credcheck release); the git tags v0.4.0, v0.4.1 and v0.5.0 are the published releases.

## Unreleased (refresh-2026-10)

### Fixed
- nuclei module: nuclei v3 removed `-json` and `-no-update-templates`, so nuclei exited with an error and every scan silently reported "No vulnerabilities found". The module now passes `-jsonl` and `-disable-update-check`.
- HTML report template moved into the package (`src/atarus_recon/templates/`), so non-editable installs (`pip install .`, pipx) can write reports.
- WeasyPrint is imported only for PDF export. The CLI now starts, and HTML and JSON reports work, on hosts without the Pango system libraries; a missing library produces a clear PDF error instead of a crash.
- Replaced deprecated `tempfile.mktemp` with `mkstemp` in the nuclei and webprobe modules.

### Added
- Offline unit tests (`tests/`) and a GitHub Actions workflow.
- `install-deps.sh` installs Pango for PDF export.
- `constraints.txt` with the dependency versions the tests last passed with.
- SECURITY.md and this changelog.

### Docs
- README corrected: default output format is `all`, the whois module does not do ASN lookups, DNS wildcards are not detected, nmap max-rate is ten times `--rate-limit`, private IPs are not port scanned, nuclei v3 and a browser for gowitness are required.

## 0.5.0 (2026-04-27)
- Audit pass with 22 fixes across all modules.
- `install-deps.sh` bootstrap for external tools.

## 0.4.1 (2026-04-26)
- Bug fixes for resolve, webprobe and credcheck dependencies.

## 0.4.0 (2026-04-24)
- credcheck module: credential exposure via the HaveIBeenPwned domain breach API, hygiene score and remediation CSVs.

## Earlier builds (2026-04-12 to 2026-04-14)
- 0.1.0 initial release; 0.2.0 httpx probing, gowitness screenshots, CDN detection; 0.3.0 subfinder, WHOIS, module toggles; WAF detection and certificate analysis; nuclei scanning and risk scoring; tabbed HTML report; branded PDF export.
