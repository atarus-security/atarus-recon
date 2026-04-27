import traceback
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

    def __init__(self, target: str, output_dir: str, rate_limit: int = 10,
                 verbose: bool = False, skip: list = None, only: list = None):
        self.target = target
        self.output_dir = output_dir
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.skip = [s.strip().lower() for s in (skip or [])]
        self.only = [s.strip().lower() for s in (only or [])]
        self.scope = ScopeValidator(target)
        self.result = ScanResult(target=self.scope.target)
        self.modules = []

    def register(self, name: str, key: str, func):
        """Register a module. Key is the short name used in --skip/--only."""
        self.modules.append({"name": name, "key": key, "func": func})

    def _should_run(self, key: str) -> bool:
        if self.only:
            return key in self.only
        if self.skip:
            return key not in self.skip
        return True

    def run(self):
        console.print()

        if not self.scope.validate_target():
            console.print(f"[bold red]Invalid target:[/] {self.target}")
            console.print(f"[dim]Cleaned to:[/] {self.scope.target}")
            console.print(f"[dim]Hint:[/] target must be a domain like example.com or sub.example.com")
            return self.result

        active = [m for m in self.modules if self._should_run(m["key"])]
        skipped = len(self.modules) - len(active)

        console.print(f"[bold green]Scope locked:[/] *.{self.scope.target}")
        console.print(f"[bold white]Modules:[/] {len(active)} active, {skipped} skipped")
        console.print()

        if skipped and self.verbose:
            skip_names = [m["key"] for m in self.modules if not self._should_run(m["key"])]
            console.print(f"  [dim]Skipped: {', '.join(skip_names)}[/]")
            console.print()

        for module in active:
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
                    err_type = type(e).__name__
                    console.print(f"  [red]fail[/] {name}: {err_type}: {str(e)[:120]}")
                    if self.verbose:
                        console.print(f"[red]{traceback.format_exc()}[/]")

            console.print()

        self.result.finalize()

        console.print(f"[bold white]Scan complete[/]")
        console.print(f"  Subdomains found: {self.result.total_subdomains}")
        console.print(f"  Alive hosts: {self.result.total_alive}")
        console.print(f"  Open ports: {self.result.total_ports}")
        console.print(f"  Duration: {self.result.started_at} to {self.result.finished_at}")

        return self.result
