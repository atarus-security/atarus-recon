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

atarus-recon performs active scanning (nmap, httpx, nuclei). Only run it against domains you own or are authorized in writing to test.
