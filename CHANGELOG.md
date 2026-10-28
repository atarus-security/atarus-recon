# Changelog

All notable changes to atarus-recon. Dates are commit dates. Version numbers in the early history were not strictly increasing (0.5.x builds landed before the 0.4.0 credcheck release); the git tags v0.4.0, v0.4.1 and v0.5.0 are the published releases.

## 0.6.0 (unreleased, refresh-2026-10)

### Security

- **nuclei, nmap, httpx and gowitness failures are reported as checks not made, never as clean results.**

  What was wrong: the nuclei module ran the binary through a shell string with stderr sent to /dev/null, never looked at the exit code, and treated an empty output file as "No vulnerabilities found". A missing binary (shell exit 127), a template error, a crash or a timeout all read as a clean scan, and the HTML report then printed "No vulnerabilities detected by nuclei". The nmap and gowitness wrappers ignored their exit codes too, so a failed nmap read as zero open ports and a failed gowitness as zero screenshots. A module that reported failure (`success=False`) was printed as a warning in the terminal but was not added to the report's list of modules not run, so "httpx produced no output" never reached the report and the report still read as clean for that check.

  Correction to this changelog: the "Fixed" entry below about nuclei v3 flags was written as if it closed this. It did not. Before this commit the only change was the two flags (`-jsonl`, `-disable-update-check`), which made nuclei start again. The exit code was still ignored, stderr was still discarded and an empty output file still counted as clean, so the same false-clean report was still possible whenever nuclei failed for any other reason. The audit's High on this point stayed open until now.

  What changed: nuclei is run as an argument list (no shell), with stderr captured and the exit code checked, and with `-ni` (no interactsh out of band callbacks to a third-party server) and `-disable-redirects`. A missing binary, a non-zero exit, a timeout, or exit 0 with nuclei saying on stderr that no templates were loaded, is returned as not run with the reason, including the tail of nuclei's stderr, and the HTML report says "Nuclei was not run" with that reason instead of "No vulnerabilities detected". Exit 0 with an empty output file and no such message is a clean result, reported with the one thing it does not vouch for: the module says "nuclei exited 0 with no findings; template load not verified" and the HTML says "No nuclei findings (template load not verified)". nmap and gowitness get the same treatment: a non-zero exit, a missing binary or a timeout is a not-run with the reason, and for nmap the message names the addresses whose ports are therefore unknown. httpx (webprobe) was moved off the shell string as well and checks its exit code. The runner records every module that returns `success=False`, or raises, in `modules_not_run` with its message; the terminal line reads "not run" and the report cannot show a clean section for it.

- **Target-controlled text is escaped before it reaches the terminal.** whois registrar and organisation fields, subfinder's stderr, nuclei, nmap, httpx and gowitness output and discovered host names were printed through rich's console as markup, so `[red]` sequences and control characters in a whois record or a certificate name could style, clear or retitle the operator's terminal. `scope.safe_text` (vendored from atarus-phpcheck) replaces control, format and separator characters with their visible escapes, and every console line built from target-derived text goes through `rich.markup.escape(safe_text(...))`. The HTML and JSON reports were already escaped.

- Fixed: the typed confirmation gate could never open on a real terminal. The terminal was opened in a mode that needs a seekable stream, which a terminal is not, so every interactive active run was refused with the no-terminal error and only --yes worked. The terminal is now opened as a raw descriptor and the prompt is written and read through it; verified on a pseudo-terminal.

- **Passive by default; active checks need `--active`, `--scope` and a typed confirmation.**

  What was wrong: a bare `atarus-recon -t example.com` port scanned every resolved IP with nmap, probed every web service with httpx, sent HEAD requests for WAF detection, opened TLS connections, ran every nuclei template at low severity and above, and drove a headless browser across the hosts, with no question asked. The only limit on where that traffic went was the name filter (anything ending in the target domain), so a subdomain pointing at a CDN, a SaaS vendor or a dangling record owned by someone else was scanned too. The person running the tool carried that exposure, and the project's own statement that active checks always ask was not true.

  What changed, in plain terms: a plain run now only asks public sources (crt.sh, subfinder's sources, DNS, whois, HaveIBeenPwned) and sends nothing to the target's hosts. To probe, you pass `--active` and a `--scope` listing the hosts, networks or domains you are authorized to touch; the tool resolves the names, shows you the scope, the active modules and every host with its IP, and waits for you to type `yes` on the terminal. Hosts that resolve outside the scope are listed as out of scope and never probed. The report records the mode, the scope, how the run was confirmed, and every module that did not run and why, so a passive report cannot be mistaken for a clean active one.

  Technically: `cli.MODULE_REGISTRY` carries an `active` flag per module (portscan, webprobe, waf, cert, nuclei and screenshot are active; crtsh, subfinder, resolve, whois, credcheck and risk are passive). `ReconRunner` refuses active modules unless constructed with `active=True` and an `ActiveScope`, runs the confirmation gate once before the first active module, and hands active modules a `result.hosts` restricted to the in-scope subset (`ActiveScope.split_hosts`), so a module cannot see an out-of-scope host at all. `scope.ActiveScope` parses `--scope` (file or list) into exact hosts, `*.domain` wildcards, addresses and CIDR networks, and `covers(name, ip)` matches by name or by resolved address. The confirmation is read from `/dev/tty` by `scope.read_tty_line`; stdin, environment variables and configuration files are not consulted, and click's environment-variable support is not enabled. `--yes` is accepted only with `--scope`, is printed at the start of the run and is stored in `ScanResult.confirmation`. `--active` without `--scope`, `--yes` without `--scope`, `--only` naming an active module without `--active`, and `--active` with neither a terminal nor `--yes` exit with a usage error (code 2) before any module runs. `ScanResult` gained `mode`, `active_scope`, `confirmation`, `modules_not_run` and `out_of_scope`; the HTML report shows them and says "Nuclei was not run" instead of "No vulnerabilities detected" when it did not run. Modules left out with `--skip` or `--only` are recorded there too. The version string now lives in `atarus_recon.__version__` and feeds the CLI, the User-Agent headers and the report.

  Known limits, still open: httpx and gowitness follow redirects off-domain, and the confirmation prompt shows resolved IPs but not their owner (CNAME target or ASN). Both are tracked in the README's Known issues.

### Fixed
- nuclei module: nuclei v3 removed `-json` and `-no-update-templates`, so nuclei exited with an error and every scan silently reported "No vulnerabilities found". The module now passes `-jsonl` and `-disable-update-check`. This entry fixed the flags only; the exit code and empty output handling that let any other nuclei failure read as clean stayed open until the Security entry above.
- HTML report template moved into the package (`src/atarus_recon/templates/`), so non-editable installs (`pip install .`, pipx) can write reports.
- WeasyPrint is imported only for PDF export. The CLI now starts, and HTML and JSON reports work, on hosts without the Pango system libraries; a missing library produces a clear PDF error instead of a crash.
- Replaced deprecated `tempfile.mktemp` with `mkstemp` in the nuclei and webprobe modules.

### Added
- Tests: the confirmation gate is exercised on a real pseudo-terminal (`pty.fork`), not a regular file standing in for `/dev/tty`, so a regression in how the terminal is opened fails the suite; nuclei, nmap and gowitness are tested with a non-zero exit, a missing binary, an empty output file (clean, with the detail) and a no-templates message on stderr (not run); a module that fails is checked to land in `modules_not_run` and to make the HTML say not run; rich markup and control characters in host names and module messages are checked to be escaped.
- Offline unit tests (`tests/`) and a GitHub Actions workflow. `tests/test_passive_default.py` covers the passive default (every network sink mocked, socket layer guarded), the `--active` and `--yes` usage errors, out-of-scope skipping and the confirmation gate.
- `install-deps.sh` installs Pango for PDF export.
- `constraints.txt` with the dependency versions the tests last passed with.
- SECURITY.md and this changelog.

### Docs
- README: the sentence saying an automation or AI agent driving the CLI cannot pass the gate was wrong and is corrected: `--yes` together with `--scope` opens the gate without a terminal and is recorded in the report, so in non-interactive runs the scope file is the control. The nuclei row of the network table lists `-ni` and `-disable-redirects`; the install notes say that external binaries' exit codes are checked.
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
