# Security policy

## Reporting a vulnerability

Please report security issues in atarus-recon privately by email to info@atarussecurity.com. Do not open a public GitHub issue for a vulnerability.

Include:

- the version or commit you tested
- steps to reproduce, and a proof of concept if you have one
- the impact you expect

We aim to acknowledge reports within 5 business days and to agree a fix and disclosure date with you. We are happy to credit reporters who want credit.

## Supported versions

Only the latest release on the default branch receives security fixes.

## Scope

In scope: the code in this repository and the reports it generates.

Out of scope: third-party tools this project calls or downloads (for example nmap, subfinder, httpx, nuclei and gowitness), and findings that require an attacker who already controls the machine running the tool.

## Using this tool

atarus-recon is passive by default: a plain run asks public sources and sends nothing to the target's own hosts. Active scanning (nmap, httpx, the WAF and certificate checks, nuclei, gowitness) runs only with `--active`, against hosts inside a `--scope` you provide, after you type `yes` on the terminal (or pass `--yes` together with `--scope` for scripted runs). Only use `--active` against hosts you own or are authorized in writing to test.

Treat as a security bug and report it: any run that sends traffic to the target without `--active`, any active module reaching a host outside `--scope`, any way to pass the confirmation gate other than typing `yes` on the terminal or the documented `--yes` flag, a report that reads as clean for a check that did not run, and any network destination not listed in the README's network table.
