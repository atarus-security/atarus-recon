import click
from rich.console import Console
from atarus_recon.runner import ReconRunner
from atarus_recon.modules import crtsh, resolve, portscan
from atarus_recon.reports import html, json_export

console = Console()

VERSION = "0.1.0"

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╦═╗╔═╗╔═╗╔═╗╔╗╔
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ╠╦╝║╣ ║  ║ ║║║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╩╚═╚═╝╚═╝╚═╝╝╚╝
   Atarus Offensive Security | v{VERSION}
"""


@click.command()
@click.option("-t", "--target", required=True, help="Target domain to scan (e.g. example.com)")
@click.option("-o", "--output", default="./output", help="Output directory for reports")
@click.option("--format", "out_format", default="html", type=click.Choice(["html", "json", "both"]), help="Report format")
@click.option("--rate-limit", default=10, help="Max requests per second")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.version_option(version=VERSION, prog_name="atarus-recon")
def main(target, output, out_format, rate_limit, verbose):
    """atarus-recon: External attack surface reconnaissance by Atarus Offensive Security"""
    console.print(BANNER, style="bold red")
    console.print(f"[bold white]Target:[/] {target}")
    console.print(f"[bold white]Output:[/] {output}")
    console.print(f"[bold white]Format:[/] {out_format}")
    console.print(f"[bold white]Rate limit:[/] {rate_limit} req/s")

    runner = ReconRunner(
        target=target,
        output_dir=output,
        rate_limit=rate_limit,
        verbose=verbose,
    )

    runner.register("crt.sh subdomain enum", crtsh.run)
    runner.register("DNS resolution", resolve.run)
    runner.register("Port scan", portscan.run)

    result = runner.run()

    if out_format in ("html", "both"):
        report_path = html.generate(result, output)
        console.print(f"\n[bold green]HTML report:[/] {report_path}")

    if out_format in ("json", "both"):
        json_path = json_export.generate(result, output)
        console.print(f"[bold green]JSON report:[/] {json_path}")


if __name__ == "__main__":
    main()
