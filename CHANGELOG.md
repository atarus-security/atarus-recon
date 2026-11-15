# Changelog

All notable changes to atarus-recon. Dates are commit dates. Version numbers in the early history were not strictly increasing (0.5.x builds landed before the 0.4.0 credcheck release); the git tags v0.4.0, v0.4.1 and v0.5.0 are the published releases.

## Unreleased

### Security

- **A name under the target domain that resolves to a loopback, link-local, private or other non-public address is out of scope unless a network entry admits that address.**

  What was wrong: `ActiveScope` admitted any host whose name matched a host or domain entry, whatever address it resolved to. Only the port scan refused private, loopback and link-local addresses. With `--scope '*.lab.test'`, a record such as `lo.lab.test -> 127.0.0.1` or `meta.lab.test -> 169.254.169.254` was listed under "Hosts to probe", the WAF and certificate checks connected to 127.0.0.1 and 169.254.169.254, and httpx, nuclei and gowitness were handed the names. Anyone who controls a record under the target zone (the client, a dangling CNAME, a takeover) could point the scan at the operator's own loopback services, LAN or a cloud metadata endpoint, and nuclei templates were fired at it. With `--yes` nobody reads the host list. The out-of-scope list gave no reason for any host.

  What changed: a host admitted by name alone must resolve to a globally routable address. Loopback, link-local, private, shared (100.64.0.0/10), unspecified (0.0.0.0), multicast, reserved and documentation addresses, and the IPv4-mapped IPv6 forms of them, are listed as out of scope. So is 168.63.129.16, a public address that answers only inside Azure, where it serves the platform's own agent and metadata (reason "cloud platform"). IPv4-compatible (`::127.0.0.1`), IPv4-translated (`::ffff:0:7f00:1`) and NAT64 (`64:ff9b::7f00:1`) addresses are refused whatever IPv4 address they embed, since where they lead depends on a translator the tool cannot see, and the reason names the embedded address; discovery asks for A records only, so these IPv6 forms do not come up in a normal run. A network entry that contains the address is the only way to admit any such host. Every out-of-scope host now carries a reason (`not covered by --scope`, `resolves to a loopback address; only a network entry in --scope that contains it admits it`, and so on) in the terminal, the HTML report and the JSON (`reason` on each `out_of_scope` entry).

- **Every A record of a name is checked at the scope gate, not only the first.**

  What was wrong: the resolve module kept only the first A record of each name and the scope check looked at that one address. A name whose first record fell inside a network entry was admitted even when its other records pointed elsewhere, and which record came first depended on the resolver, which often rotates the order. httpx, nuclei and gowitness were then handed the name, and each looks it up again and may connect to any address in the set.

  What changed: `Host.ips` keeps every A record, in order and without repeats, and `Host.ip` is the first of them. The gate admits a host only when every address is admitted on its own (inside a network entry, or public with a name match), so a name with one public and one loopback record is out of scope in either order, and the reason names the address that failed. The WAF, certificate and port checks connect to `Host.ip`, which the gate approved with the rest of the set. The confirmation, the HTML report and the JSON (`ips`, also on each `out_of_scope` entry) show every address.

- **The confirmation, the report and the README now say what the scope check cannot hold for httpx, nuclei and gowitness.**

  What was wrong: the README said a host outside the scope "is never handed to an active module", but every active module was given the host name and looked it up again after the check: the WAF and certificate checks connected by name, and httpx, nuclei and gowitness resolve the name in their own processes. A record that answers public at the check and 169.254.169.254 afterwards (a TTL 0 rebinding record), or a resolver that answers differently from the one atarus-recon used, could send them to an address the check never saw. Nothing in the README or the report said so.

  What changed: the WAF, certificate and port checks now connect to a checked address (see the entries on the WAF probe and on nmap). httpx, nuclei and gowitness are still given host names; pinning them to the checked address needs options that have not been verified against the real binaries. The confirmation prints a note naming the name-resolving tools that will run and `--skip webprobe,nuclei,screenshot` as the way to avoid the gap; the same note is in the HTML report ("Scope note") and the JSON (`scope_note`). The README states what the check holds and what it does not, and lists the gap under Known issues; SECURITY.md names it next to the out-of-scope rule.

- **A discovered name that is not a DNS name can no longer steer an active module to another host.**

  What was wrong: names from crt.sh and subfinder were kept whenever they ended in the target domain, with no check that they were host names at all. A name such as `127.0.0.1:18431#.lab.test` or `other.host/x.lab.test` matches `*.lab.test` by suffix, and with wildcard DNS it also resolves into the client's range, so it passed the scope check and was listed under "Hosts to probe". The active modules then build URLs from the name, and in a URL it means a different host: the WAF module sent its HEAD request to 127.0.0.1:18431, and httpx and nuclei were handed `https://127.0.0.1:18431#.lab.test` and `https://other.host/x.lab.test`. Anyone who can get text into a passive source (a scraped page, a passive DNS feed, a certificate log) could point the active scan at a host the user never named.

  What changed: `scope.normalize_name` lower-cases a name, drops one trailing dot and accepts it only if it is a well formed DNS name (letters, digits and hyphens per label). `ScopeValidator.is_in_scope` and `filter_in_scope` use it, so crt.sh and subfinder keep only real names (in canonical form, without duplicates) and say how many they ignored. `ActiveScope.covers` refuses a malformed name even when its address is inside a network entry, so the confirmation lists such a host as out of scope and no active module ever sees it. crt.sh JSON that is not a list of records is now a not-run with a plain reason instead of a crash. Names with underscores (such as `_dmarc` records) are no longer kept as hosts; they are not web hosts.

- **The WAF probe no longer follows redirects, and the WAF and certificate checks connect to the checked address.**

  What was wrong: the WAF module sent its HEAD request through `urllib.request.urlopen`, which follows redirects. An in-scope host that answered `301 Location: http://somewhere-else/` made the tool send a second request, as a GET, to a host outside `--scope`; the README promised one HEAD request. Both the WAF and the certificate modules also connected by host name, so the name was resolved a second time after the confirmation: a host admitted because its address was inside a network entry could be reached at a different address by the time the packet went out.

  What changed: the WAF HEAD request is sent with `http.client` over a socket opened to `host.ip`, with the name only in SNI and the Host header; a 3xx answer is read for its headers and nothing more is sent. The certificate grab opens its TLS connection to `host.ip` with the name as SNI. When no host answers at all, both modules now report the check as not run (WAF presence unknown, no certificate read) instead of "Detected WAF/protection on 0 hosts" or "Analyzed 0 certificates", and a partial run says how many hosts gave no answer. Repeated headers such as Set-Cookie are all matched now. A response with a status line and no headers at all counts as an answer, so no second request is sent over plain HTTP.

- **httpx follows a redirect only when it stays on the same host.** webprobe ran httpx with `-follow-redirects`, so any in-scope host that redirected elsewhere made httpx request the redirect target, outside `--scope` (it was listed under Known issues). It now passes `-follow-host-redirects`. The README's Known issues now name what is left (gowitness's browser, and the external tools resolving names again) and note that IPv6 scope entries never match because discovery resolves A records only.

- **nmap scans a host that an explicit network entry admits, whatever kind of address it has.**

  What was wrong: on an internal engagement, a user who added a network entry such as `10.20.0.0/16` to `--scope` saw a host at `10.20.0.5` listed under "Hosts to probe", and the other active modules ran on it, but the port scan reported only `No valid public IPs (skipped 1)`, because it refused every private, loopback and link-local address on its own. Nothing at the confirmation said so, and the README said only public addresses are scanned.

  What changed: the port scan trusts the scope gate, which hands it only in-scope hosts. A network entry the user wrote is the opt in for its addresses, so such a host is now port scanned like any other. nmap is still not given a value that is not one host address (not an address, 0.0.0.0, multicast, 255.255.255.255); the message says `nmap scans unicast host addresses only` and how many hosts were left out.

### Fixed

- **A host name with a newline inside it is no longer taken as valid.** The label and top-level checks used `^...$` with `re.match`, and `$` also matches just before a trailing newline, so `a\n.lab.test` passed, through `-t` or a comma-separated `--scope`. Written to the httpx and nuclei list files, such a name becomes two target lines. The patterns are now matched with `fullmatch`. Discovered names were not affected: crt.sh and subfinder output is split on newlines first.

- **`--skip` and `--only` can no longer leave in a module the user meant to leave out.**

  What was wrong: an unknown key was ignored without a word, so `--skip portscna` ran nmap; a repeated option kept only its last value (click's default), so `--skip portscan --skip nuclei` ran nmap too; `--only` together with `--skip` silently dropped the `--skip`. In an active run each of these sent traffic the user had asked not to send. A repeated `--scope` likewise kept only the last value, and a mistyped scope file name such as `scop.txt` was taken as a one-host scope with no warning. `--rate-limit 0` or a negative value was passed straight to nmap, httpx and nuclei.

  What changed: `--skip`, `--only` and `--scope` accept repeats and merge every value. Module keys are matched case-insensitively against the registry, and an unknown key is a usage error that lists the known keys. `--skip` with `--only` is a usage error. A `--scope` value that looks like a file path but does not exist is a usage error ("scope file not found"), and scope files are read as UTF-8. This changes one input that used to work: a single value with a path separator, such as `--scope lab.test/`, used to mean the host `lab.test` and is now refused as a missing file (exit 2); write `--scope lab.test`, or a full URL such as `https://lab.test/`, which is still taken as a host. `--rate-limit` must be 1 or more.

- **An invalid target or an unusable output directory stops the run before it starts.**

  What was wrong: a target that is not a domain (`203.0.113.5`, `not a domain`, a Unicode name such as `bücher.example`) printed "Invalid target", then wrote an empty HTML, JSON and PDF report anyway and exited 0, so a script could not tell it from a finished scan. An output path that was a file, or a directory that could not be written, ended in a Python traceback; for an unwritable directory that happened only after every module, active ones included, had already run, and the results were lost. An output path containing `[/]` crashed the banner with a rich MarkupError, and when the output was piped, rich wrapped long report paths across two lines.

  What changed: the target is validated first and a bad one is a usage error (exit 2) with no report; the message says to give the Punycode (`xn--`) form of an internationalized name rather than converting it, so the name queried is exactly the one given. The output directory is created and test-written before anything runs, and failure is a usage error naming the directory. Paths are printed escaped and unwrapped. The README gains an exit code table.

- **Output that is not UTF-8 no longer crashes a module, and reports are always written as UTF-8.**

  What was wrong: every external binary was read with `text=True` and strict decoding, so one byte that is not UTF-8 raised UnicodeDecodeError. Many whois servers answer in Latin-1 (a registrant such as "Müller GmbH"), so the WHOIS module crashed and the report listed it as not run although the data had arrived; subfinder, nmap, httpx, nuclei and gowitness had the same weakness. Report files were opened in the locale's encoding, so under a Latin-1 locale the HTML report failed on the first non-Latin-1 character in a page title.

  What changed: all seven `subprocess.run` calls decode as UTF-8 with replacement, and the httpx and nuclei result files are read the same way. The HTML, JSON, CSV and PDF steps read and write UTF-8 explicitly.

- **The report no longer reads as if nothing was found for port, WAF and screenshot checks that were not made.**

  What was wrong: the HTML report printed "No open ports detected in top 100" for every resolved host that had no ports, including every host of a passive run and every host nmap never scanned (out of scope, refused by the port scan, nmap failed). The WAF cell said "None detected" when the WAF check never ran or got no answer, and the risk score added its no-WAF weight on that basis, so a passive run scored every host as low risk for a missing WAF it never looked for. The screenshot module counted any matching PNG already in `screenshots/`, so a second run into the same output directory reported "Captured N screenshots" and linked the old images even when gowitness captured nothing. Run timestamps had no time zone.

  What changed: `Host` gains `ports_scanned` (set when nmap's XML for that address parsed) and `waf_checked` (set when the HEAD request got an answer); both appear in the JSON. The HTML says "No open ports detected in top 100" only for a scanned host and "Ports not scanned for this host" otherwise, and the WAF cell says "Not checked" unless the check got an answer. The no-WAF risk weight applies only to a checked host. The screenshot module notes what is in the directory before gowitness runs and counts only files written or rewritten by this run. `started_at` and `finished_at` carry the local UTC offset.

- **nuclei and gowitness are pointed at the URL httpx answered on, and a gowitness run that captures nothing is a not-run.**

  What was wrong: nuclei and gowitness guessed the scheme: `https://` whenever the host's status was 200, whatever httpx had found. A site that answers only on plain HTTP was therefore scanned at `https://`, every template failed to connect, nuclei exited 0 with no findings, and the report said "No nuclei findings" for a site that was never scanned. Sites on a non-default port were never reached at all. gowitness exits 0 even when the browser fails on every page, and "Captured 0 screenshots" was reported as done.

  What changed: webprobe records the origin httpx answered on (`Host.web_url`, scheme, host and any non-default port, only when it is on the same host) and nuclei and gowitness use it, falling back to the old guess only when httpx gave none. gowitness exit 0 with no screenshot written is reported as not run with the reason; a partial run says how many of the web hosts were captured.

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
