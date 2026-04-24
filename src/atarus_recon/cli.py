import click
from rich.console import Console
from rich.table import Table
from atarus_recon.runner import ReconRunner
from atarus_recon.modules import crtsh, resolve, portscan, webprobe, screenshot, subfinder, whois_asn, waf_detect, cert_analysis, nuclei_scan, risk_score, credcheck
from atarus_recon.reports import html, json_export, pdf, credcheck_csv

console = Console()

VERSION = "0.4.0"

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╦═╗╔═╗╔═╗╔═╗╔╗╔
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ╠╦╝║╣ ║  ║ ║║║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╩╚═╚═╝╚═╝╚═╝╝╚╝
   Atarus Offensive Security | v{VERSION}
"""

MODULE_REGISTRY = [
    ("crt.sh subdomain enum", "crtsh", crtsh.run),
    ("Subfinder enum", "subfinder", subfinder.run),
    ("DNS resolution", "resolve", resolve.run),
    ("WHOIS and ASN lookup", "whois", whois_asn.run),
    ("Port scan", "portscan", portscan.run),
    ("Web probe", "webprobe", webprobe.run),
    ("WAF detection", "waf", waf_detect.run),
    ("Certificate analysis", "cert", cert_analysis.run),
    ("Nuclei vulnerability scan", "nuclei", nuclei_scan.run),
    ("Screenshot capture", "screenshot", screenshot.run),
    ("Credential exposure check", "credcheck", credcheck.run),
    ("Risk scoring", "risk", risk_score.run),
]


@click.command()
@click.option("-t", "--target", default="", help="Target domain to scan")
@click.option("-o", "--output", default="./output", help="Output directory for reports")
@click.option("--format", "out_format", default="html", type=click.Choice(["html", "json", "pdf", "all"]), help="Report format")
@click.option("--rate-limit", default=10, help="Max requests per second")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("--skip", default="", help="Comma-separated modules to skip")
@click.option("--only", default="", help="Comma-separated modules to run exclusively")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.version_option(version=VERSION, prog_name="atarus-recon")
def main(target, output, out_format, rate_limit, verbose, skip, only, list_modules):
    """atarus-recon: External attack surface reconnaissance by Atarus Offensive Security"""

    if list_modules:
        table = Table(title="Available modules")
        table.add_column("Key", style="bold cyan")
        table.add_column("Description")
        for name, key, _ in MODULE_REGISTRY:
            table.add_row(key, name)
        console.print(table)
        return

    if not target:
        console.print("[bold red]Error:[/] --target is required. Use -t example.com")
        return

    console.print(BANNER, style="bold red")
    console.print(f"[bold white]Target:[/] {target}")
    console.print(f"[bold white]Output:[/] {output}")
    console.print(f"[bold white]Format:[/] {out_format}")
    console.print(f"[bold white]Rate limit:[/] {rate_limit} req/s")

    skip_list = [s.strip() for s in skip.split(",") if s.strip()] if skip else []
    only_list = [s.strip() for s in only.split(",") if s.strip()] if only else []

    runner = ReconRunner(
        target=target,
        output_dir=output,
        rate_limit=rate_limit,
        verbose=verbose,
        skip=skip_list,
        only=only_list,
    )

    for name, key, func in MODULE_REGISTRY:
        runner.register(name, key, func)

    result = runner.run()

    if result.credential_exposure and result.credential_exposure.breaches:
        csv_paths = credcheck_csv.generate(result, output)
        for p in csv_paths:
            console.print(f"[bold green]CSV report:[/] {p}")


    if out_format in ("html", "all"):
        report_path = html.generate(result, output)
        console.print(f"\n[bold green]HTML report:[/] {report_path}")

    if out_format in ("json", "all"):
        json_path = json_export.generate(result, output)
        console.print(f"[bold green]JSON report:[/] {json_path}")

    if out_format in ("pdf", "all"):
        pdf_path = pdf.generate(result, output)
        console.print(f"[bold green]PDF report:[/] {pdf_path}")


if __name__ == "__main__":
    main()
