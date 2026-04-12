# atarus-recon

External attack surface reconnaissance tool by [Atarus Offensive Security](https://atarussecurity.com).

One command. Full recon. Clean report.

## What it does

- Subdomain enumeration via certificate transparency logs
- DNS resolution with alive host detection
- Port scanning with service version detection (via nmap)
- Professional HTML report with executive summary
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
- Linux (tested on Kali Linux)

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
```

## Output

Reports are saved to ./output/ by default.

- HTML: Visual report with summary dashboard and per-host breakdown
- JSON: Machine-readable output for piping into other tools

## Adding modules

Every module is a function with this signature:

```python
def run(result, scope, rate_limit, verbose) -> ModuleResult:
```

Register it in cli.py:

```python
runner.register("My new module", my_module.run)
```

## License

MIT License. See LICENSE for details.

## Built by

[Atarus Offensive Security LLC](https://atarussecurity.com)
