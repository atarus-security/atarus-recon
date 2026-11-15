import os
import tempfile
import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from atarus_recon import __version__
from atarus_recon.runner import ReconRunner
from atarus_recon.scope import ActiveScope, ScopeValidator, safe_text, tty_available
from atarus_recon.modules import crtsh, resolve, portscan, webprobe, screenshot, subfinder, whois_asn, waf_detect, cert_analysis, nuclei_scan, risk_score, credcheck
from atarus_recon.reports import html, json_export, pdf, credcheck_csv

console = Console()

VERSION = __version__

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╦═╗╔═╗╔═╗╔═╗╔╗╔
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ╠╦╝║╣ ║  ║ ║║║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╩╚═╚═╝╚═╝╚═╝╝╚╝
   Atarus Offensive Security | v{VERSION}
"""

# (name, key, function, active). active=True marks a module that sends packets
# to the target's own hosts; it runs only behind --active, inside --scope and
# after the confirmation gate. Passive modules only talk to third parties
# (crt.sh, subfinder's sources, the DNS resolver, whois, HIBP) or work offline.
MODULE_REGISTRY = [
    ("crt.sh subdomain enum", "crtsh", crtsh.run, False),
    ("Subfinder enum", "subfinder", subfinder.run, False),
    ("DNS resolution", "resolve", resolve.run, False),
    ("WHOIS lookup", "whois", whois_asn.run, False),
    ("Port scan", "portscan", portscan.run, True),
    ("Web probe", "webprobe", webprobe.run, True),
    ("WAF detection", "waf", waf_detect.run, True),
    ("Certificate analysis", "cert", cert_analysis.run, True),
    ("Nuclei vulnerability scan", "nuclei", nuclei_scan.run, True),
    ("Screenshot capture", "screenshot", screenshot.run, True),
    ("Credential exposure check", "credcheck", credcheck.run, False),
    ("Risk scoring", "risk", risk_score.run, False),
]

ACTIVE_MODULES = [key for _, key, _, active in MODULE_REGISTRY if active]
PASSIVE_MODULES = [key for _, key, _, active in MODULE_REGISTRY if not active]


def _writable_output_dir(path: str) -> str:
    """Create the output directory and prove it is writable, before any module runs.

    A scan (an active one included) must not run to the end and then lose its
    results to a traceback because the reports cannot be written.
    """
    path = os.path.abspath(path)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        raise click.UsageError(f"--output: cannot use {path} as the output directory: {e.strerror or e}")
    try:
        with tempfile.TemporaryFile(dir=path):
            pass
    except OSError as e:
        raise click.UsageError(f"--output: cannot write to {path}: {e.strerror or e}")
    return path


def _module_keys(values, flag: str) -> list:
    """The module keys named by every use of --skip or --only, lower-cased, in order.

    An unknown key is a usage error: a typo in --skip must not quietly leave a
    module the user meant to skip in the run.
    """
    known = [key for _, key, _, _ in MODULE_REGISTRY]
    keys = []
    for value in values or ():
        for part in value.split(","):
            key = part.strip().lower()
            if key and key not in keys:
                keys.append(key)
    unknown = [k for k in keys if k not in known]
    if unknown:
        raise click.UsageError(
            f"{flag}: unknown module {', '.join(unknown)}; known modules: {', '.join(known)}"
        )
    return keys


@click.command()
@click.option("-t", "--target", default="", help="Target domain to scan (e.g. example.com)")
@click.option("-o", "--output", default="./output", help="Output directory for reports")
@click.option("--format", "out_format", default="all", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format (default: all)")
@click.option("--rate-limit", default=10, type=click.IntRange(min=1), help="Max requests per second (1 or more)")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("--skip", multiple=True, help="Comma-separated modules to skip; may be repeated. See --list-modules for the keys.")
@click.option("--only", multiple=True, help="Comma-separated modules to run exclusively; may be repeated. Cannot be combined with --skip.")
@click.option("--active", is_flag=True, help="Run the modules that send packets to the target (portscan, webprobe, waf, cert, nuclei, screenshot). Needs --scope and a typed confirmation.")
@click.option("--scope", "scope_spec", multiple=True, help="Hosts, networks or domains allowed for active checks: a file with one entry per line, or a comma-separated list (app.example.com, *.example.com, 203.0.113.0/24). May be repeated; the scope is every entry named. Required with --active.")
@click.option("--yes", "assume_yes", is_flag=True, help="Stand in for the typed confirmation on non-interactive runs. Accepted only with --scope; its use is recorded in the report.")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.version_option(version=VERSION, prog_name="atarus-recon")
def main(target, output, out_format, rate_limit, verbose, skip, only, active, scope_spec, assume_yes, list_modules):
    """atarus-recon: External attack surface reconnaissance by Atarus Offensive Security

    Passive by default: without --active nothing is sent to the target's own
    hosts. Active checks need --active, a --scope, and the word yes typed on
    the terminal (or --yes together with --scope for scripted runs).
    """

    if list_modules:
        table = Table(title="Available modules")
        table.add_column("Key", style="bold cyan")
        table.add_column("Mode")
        table.add_column("Description")
        for name, key, _, is_active in MODULE_REGISTRY:
            table.add_row(key, "active (needs --active)" if is_active else "passive", name)
        console.print(table)
        return

    if not target:
        raise click.UsageError("--target is required. Use -t example.com")
    if not ScopeValidator(target).validate_target():
        raise click.UsageError(
            f"--target: {safe_text(target, 200)} is not a domain name. Give a domain such as example.com "
            "or sub.example.com (no IP address, no port). For an internationalized name, give its "
            "Punycode form (xn--...), so the exact name you are authorized for is the one queried."
        )

    skip_list = _module_keys(skip, "--skip")
    only_list = _module_keys(only, "--only")
    if skip_list and only_list:
        raise click.UsageError("use --only or --skip, not both")

    # The gate rules. A flag alone never opens it: --yes needs --scope, and
    # --active needs --scope plus either a terminal or --yes. Click reads no
    # environment variables for these options and there is no config file.
    if assume_yes and not scope_spec:
        raise click.UsageError("--yes is only accepted together with --scope")
    if active and not scope_spec:
        raise click.UsageError(
            "--active requires --scope: a file or comma-separated list of the hosts, "
            "networks or domains you are authorized to probe"
        )
    active_scope = None
    if scope_spec:
        try:
            active_scope = ActiveScope.from_option(scope_spec)
        except (ValueError, OSError) as e:
            raise click.UsageError(f"--scope: {e}")
    wanted_active = [k for k in only_list if k in ACTIVE_MODULES]
    if wanted_active and not active:
        raise click.UsageError(
            f"--only names active modules ({', '.join(wanted_active)}); add --active and --scope to run them"
        )
    if active and not assume_yes and not tty_available():
        raise click.UsageError(
            "--active needs a terminal to type the confirmation on; run interactively, "
            "or pass --yes together with --scope for a non-interactive run"
        )

    output = _writable_output_dir(output)
    os.environ["ATARUS_OUTPUT_DIR"] = output

    console.print(BANNER, style="bold red")
    console.print(f"[bold white]Target:[/] {escape(safe_text(target))}")
    console.print(f"[bold white]Output:[/] {escape(output)}", soft_wrap=True)
    console.print(f"[bold white]Format:[/] {out_format}")
    console.print(f"[bold white]Rate limit:[/] {rate_limit} req/s")
    console.print(f"[bold white]Mode:[/] {'active' if active else 'passive'}")
    if active_scope is not None:
        console.print(f"[bold white]Scope:[/] {active_scope.describe()}")
        if not active:
            console.print("[dim]--scope given without --active: nothing will be probed.[/]")
    if assume_yes:
        console.print("[yellow]--yes given: the terminal confirmation will be skipped and this is recorded in the report.[/]")

    runner = ReconRunner(
        target=target,
        output_dir=output,
        rate_limit=rate_limit,
        verbose=verbose,
        skip=skip_list,
        only=only_list,
        active=active,
        active_scope=active_scope,
        assume_yes=assume_yes,
    )

    for name, key, func, is_active in MODULE_REGISTRY:
        runner.register(name, key, func, active=is_active)

    result = runner.run()

    if result.credential_exposure and result.credential_exposure.breaches:
        csv_paths = credcheck_csv.generate(result, output)
        for p in csv_paths:
            console.print(f"[bold green]CSV report:[/] {escape(p)}", soft_wrap=True)

    html_path = None
    if out_format in ("html", "all", "pdf"):
        html_path = html.generate(result, output)
        if out_format in ("html", "all"):
            console.print(f"\n[bold green]HTML report:[/] {escape(html_path)}", soft_wrap=True)

    if out_format in ("json", "all"):
        json_path = json_export.generate(result, output)
        console.print(f"[bold green]JSON report:[/] {escape(json_path)}", soft_wrap=True)

    if out_format in ("pdf", "all"):
        try:
            pdf_path = pdf.generate(result, output, existing_html_path=html_path)
            console.print(f"[bold green]PDF report:[/] {escape(pdf_path)}", soft_wrap=True)
        except (OSError, ImportError) as e:
            console.print(f"[bold red]PDF report failed:[/] {escape(safe_text(e, 160))}")
            console.print("[dim]WeasyPrint needs the Pango system libraries. See README (Install).[/]")


if __name__ == "__main__":
    main()
