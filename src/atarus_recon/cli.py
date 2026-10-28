import os
import click
from rich.console import Console
from rich.table import Table
from atarus_recon import __version__
from atarus_recon.runner import ReconRunner
from atarus_recon.scope import ActiveScope, tty_available
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


@click.command()
@click.option("-t", "--target", default="", help="Target domain to scan (e.g. example.com)")
@click.option("-o", "--output", default="./output", help="Output directory for reports")
@click.option("--format", "out_format", default="all", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format (default: all)")
@click.option("--rate-limit", default=10, help="Max requests per second")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("--skip", default="", help="Comma-separated modules to skip")
@click.option("--only", default="", help="Comma-separated modules to run exclusively")
@click.option("--active", is_flag=True, help="Run the modules that send packets to the target (portscan, webprobe, waf, cert, nuclei, screenshot). Needs --scope and a typed confirmation.")
@click.option("--scope", "scope_spec", default="", help="Hosts, networks or domains allowed for active checks: a file with one entry per line, or a comma-separated list (app.example.com, *.example.com, 203.0.113.0/24). Required with --active.")
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

    skip_list = [s.strip() for s in skip.split(",") if s.strip()] if skip else []
    only_list = [s.strip() for s in only.split(",") if s.strip()] if only else []

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
    wanted_active = [k for k in only_list if k.lower() in ACTIVE_MODULES]
    if wanted_active and not active:
        raise click.UsageError(
            f"--only names active modules ({', '.join(wanted_active)}); add --active and --scope to run them"
        )
    if active and not assume_yes and not tty_available():
        raise click.UsageError(
            "--active needs a terminal to type the confirmation on; run interactively, "
            "or pass --yes together with --scope for a non-interactive run"
        )

    output = os.path.abspath(output)
    os.makedirs(output, exist_ok=True)
    os.environ["ATARUS_OUTPUT_DIR"] = output

    console.print(BANNER, style="bold red")
    console.print(f"[bold white]Target:[/] {target}")
    console.print(f"[bold white]Output:[/] {output}")
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
            console.print(f"[bold green]CSV report:[/] {p}")

    html_path = None
    if out_format in ("html", "all", "pdf"):
        html_path = html.generate(result, output)
        if out_format in ("html", "all"):
            console.print(f"\n[bold green]HTML report:[/] {html_path}")

    if out_format in ("json", "all"):
        json_path = json_export.generate(result, output)
        console.print(f"[bold green]JSON report:[/] {json_path}")

    if out_format in ("pdf", "all"):
        try:
            pdf_path = pdf.generate(result, output, existing_html_path=html_path)
            console.print(f"[bold green]PDF report:[/] {pdf_path}")
        except (OSError, ImportError) as e:
            console.print(f"[bold red]PDF report failed:[/] {str(e)[:160]}")
            console.print("[dim]WeasyPrint needs the Pango system libraries. See README (Install).[/]")


if __name__ == "__main__":
    main()
