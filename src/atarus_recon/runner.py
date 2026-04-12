from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator

console = Console()


class ModuleResult:
    """Wrapper for what a module returns"""
    def __init__(self, success: bool, message: str = ""):
        self.success = success
        self.message = message


class ReconRunner:
    """Orchestrates the recon pipeline"""

    def __init__(self, target: str, output_dir: str, rate_limit: int = 10, verbose: bool = False):
        self.target = target
        self.output_dir = output_dir
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.scope = ScopeValidator(target)
        self.result = ScanResult(target=target)
        self.modules = []

    def register(self, name: str, func):
        self.modules.append({"name": name, "func": func})

    def run(self):
        console.print()

        if not self.scope.validate_target():
            console.print(f"[bold red]Invalid target:[/] {self.target}")
            return self.result

        console.print(f"[bold green]Scope locked:[/] *.{self.target}")
        console.print(f"[bold white]Modules loaded:[/] {len(self.modules)}")
        console.print()

        for module in self.modules:
            name = module["name"]
            func = module["func"]

            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold cyan]{name}[/]"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task(name, total=None)

                try:
                    module_result = func(self.result, self.scope, self.rate_limit, self.verbose)

                    if module_result.success:
                        console.print(f"  [green]done[/] {module_result.message}")
                    else:
                        console.print(f"  [yellow]warn[/] {module_result.message}")

                except Exception as e:
                    console.print(f"  [red]fail[/] {name}")
                    if self.verbose:
                        console.print(f"  [red]Error: {e}[/]")

            console.print()

        self.result.finalize()

        console.print(f"[bold white]Scan complete[/]")
        console.print(f"  Subdomains found: {self.result.total_subdomains}")
        console.print(f"  Alive hosts: {self.result.total_alive}")
        console.print(f"  Open ports: {self.result.total_ports}")
        console.print(f"  Duration: {self.result.started_at} to {self.result.finished_at}")

        return self.result
