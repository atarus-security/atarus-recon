import traceback
from contextlib import contextmanager
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator, read_tty_line

console = Console()

CONFIRM_WORD = "yes"


class ModuleResult:
    """Wrapper for what a module returns"""
    def __init__(self, success: bool, message: str = ""):
        self.success = success
        self.message = message


class ReconRunner:
    """Orchestrates the recon pipeline.

    Modules registered with active=True send packets to the target's own
    hosts. They run only when the runner was created with active=True, only
    against hosts covered by active_scope, and only after the confirmation
    gate has passed. The gate reads the word "yes" from the controlling
    terminal, or accepts assume_yes (the --yes flag), which is recorded in
    the result. Nothing else can open the gate.
    """

    def __init__(self, target: str, output_dir: str, rate_limit: int = 10,
                 verbose: bool = False, skip: list = None, only: list = None,
                 active: bool = False, active_scope=None, assume_yes: bool = False):
        self.target = target
        self.output_dir = output_dir
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.skip = [s.strip().lower() for s in (skip or [])]
        self.only = [s.strip().lower() for s in (only or [])]
        self.scope = ScopeValidator(target)
        self.active = bool(active)
        self.active_scope = active_scope
        self.assume_yes = bool(assume_yes)
        if self.active and self.active_scope is None:
            raise ValueError("active runs need an active_scope")
        self.result = ScanResult(target=self.scope.target, mode="active" if self.active else "passive")
        if self.active_scope is not None:
            self.result.active_scope = list(self.active_scope.entries)
        self.modules = []
        self._gate_open = None
        self._gate_reason = ""

    def register(self, name: str, key: str, func, active: bool = False):
        """Register a module. Key is the short name used in --skip/--only.
        active=True marks a module that sends packets to the target's hosts.
        """
        self.modules.append({"name": name, "key": key, "func": func, "active": bool(active)})

    def _should_run(self, key: str) -> bool:
        if self.only:
            return key in self.only
        if self.skip:
            return key not in self.skip
        return True

    def selected_modules(self) -> list:
        return [m for m in self.modules if self._should_run(m["key"])]

    def _not_run(self, module: dict, reason: str):
        self.result.modules_not_run.append({"module": module["key"], "name": module["name"], "reason": reason})
        console.print(f"  [dim]not run[/] [bold cyan]{module['name']}[/]: {reason}")
        console.print()

    @contextmanager
    def _restricted_to(self, hosts: list):
        """Hand a module only the given hosts. The host objects are shared, so
        anything the module records on them stays on the full list."""
        all_hosts = self.result.hosts
        self.result.hosts = hosts
        try:
            yield
        finally:
            self.result.hosts = all_hosts

    def _confirm_active(self, active_modules: list) -> bool:
        """The confirmation gate. Runs once, before the first packet to the target.

        Prints the exact scope, the active modules and every host that would
        be probed, then waits for the word "yes" typed on the terminal.
        --yes (assume_yes) stands in for the typed word on non-interactive
        runs and is recorded in the result. No environment variable or
        configuration file is read.
        """
        in_scope, out_of_scope = self.active_scope.split_hosts(self.result.hosts)
        self.result.out_of_scope = [{"hostname": h.hostname, "ip": h.ip} for h in out_of_scope]

        console.print("[bold yellow]Active checks requested[/]")
        console.print(f"  [bold white]Scope:[/] {self.active_scope.describe()}")
        console.print(f"  [bold white]Active modules:[/] {', '.join(m['key'] for m in active_modules)}")
        if in_scope:
            console.print(f"  [bold white]Hosts to probe ({len(in_scope)}):[/]")
            for h in in_scope:
                console.print(f"    {h.hostname} -> {h.ip}")
        else:
            console.print("  [bold white]Hosts to probe:[/] none")
        if out_of_scope:
            console.print(f"  [bold white]Out of scope, not probed ({len(out_of_scope)}):[/]")
            for h in out_of_scope:
                console.print(f"    {h.hostname} -> {h.ip}")
        console.print()

        if not in_scope:
            self._gate_reason = "no resolved host inside --scope"
            return False

        if self.assume_yes:
            self.result.confirmation = "--yes flag (no terminal confirmation)"
            console.print("[yellow]Confirmation taken from --yes; recorded in the report.[/]")
            console.print()
            return True

        prompt = (
            f"Type {CONFIRM_WORD} to send packets to the {len(in_scope)} host(s) listed above "
            f"(scope: {self.active_scope.describe()}): "
        )
        answer = read_tty_line(prompt)
        if answer is None:
            self._gate_reason = "no terminal to confirm on; pass --yes with --scope for non-interactive runs"
            return False
        if answer.lower() != CONFIRM_WORD:
            self._gate_reason = "confirmation not given on the terminal"
            return False
        self.result.confirmation = "typed yes on the terminal"
        console.print()
        return True

    def _run_module(self, module: dict):
        name = module["name"]
        func = module["func"]

        with Progress(
            SpinnerColumn(),
            TextColumn(f"[bold cyan]{name}[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            progress.add_task(name, total=None)

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

    def run(self):
        console.print()

        if not self.scope.validate_target():
            console.print(f"[bold red]Invalid target:[/] {self.target}")
            console.print(f"[dim]Cleaned to:[/] {self.scope.target}")
            console.print(f"[dim]Hint:[/] target must be a domain like example.com or sub.example.com")
            return self.result

        selected = self.selected_modules()
        skipped = len(self.modules) - len(selected)
        active_selected = [m for m in selected if m["active"]]

        console.print(f"[bold green]Discovery scope:[/] *.{self.scope.target}")
        if self.active:
            console.print(f"[bold green]Active scope:[/] {self.active_scope.describe()}")
        else:
            console.print("[bold green]Mode:[/] passive (no packets to the target's hosts; add --active and --scope to probe)")
        console.print(f"[bold white]Modules:[/] {len(selected)} selected, {skipped} skipped")
        console.print()

        if skipped and self.verbose:
            skip_names = [m["key"] for m in self.modules if not self._should_run(m["key"])]
            console.print(f"  [dim]Skipped: {', '.join(skip_names)}[/]")
            console.print()

        for module in selected:
            if not module["active"]:
                self._run_module(module)
                continue

            if not self.active:
                self._not_run(module, "passive mode; add --active and --scope to run it")
                continue

            if self._gate_open is None:
                self._gate_open = self._confirm_active(active_selected)

            if not self._gate_open:
                self._not_run(module, self._gate_reason)
                continue

            in_scope, _ = self.active_scope.split_hosts(self.result.hosts)
            with self._restricted_to(in_scope):
                self._run_module(module)

        # A module the user skipped is also a check that was not made; record it
        # so the report cannot read as clean for it.
        for module in self.modules:
            if not self._should_run(module["key"]):
                self.result.modules_not_run.append(
                    {"module": module["key"], "name": module["name"], "reason": "skipped with --skip or --only"}
                )

        self.result.finalize()

        console.print(f"[bold white]Scan complete[/]")
        if self.result.mode == "passive":
            console.print("  Mode: passive, no packets were sent to the target's hosts")
        else:
            console.print(f"  Mode: active, confirmation: {self.result.confirmation or 'not given'}")
        console.print(f"  Subdomains found: {self.result.total_subdomains}")
        console.print(f"  Alive hosts: {self.result.total_alive}")
        console.print(f"  Open ports: {self.result.total_ports}")
        if self.result.modules_not_run:
            console.print(f"  Modules not run: {', '.join(m['module'] for m in self.result.modules_not_run)}")
        if self.result.out_of_scope:
            console.print(f"  Out of scope, not probed: {len(self.result.out_of_scope)} host(s)")
        console.print(f"  Duration: {self.result.started_at} to {self.result.finished_at}")

        return self.result
