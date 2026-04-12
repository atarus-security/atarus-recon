import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator


def generate(result: ScanResult, output_dir: str) -> str:
    """Generate an HTML report from scan results"""

    os.makedirs(output_dir, exist_ok=True)

    possible_dirs = [
        os.path.join(os.path.dirname(__file__), "..", "templates"),
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "templates"),
    ]

    template_dir = None
    for d in possible_dirs:
        d = os.path.normpath(d)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "report.html")):
            template_dir = d
            break

    if template_dir is None:
        raise FileNotFoundError("Could not find templates/report.html")

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(default=True, default_for_string=True),
    )
    template = env.get_template("report.html")

    unique_ips = len(set(h.ip for h in result.hosts if h.ip))

    html_content = template.render(result=result, unique_ips=unique_ips)

    safe_target = ScopeValidator.sanitize_filename(result.target)
    output_path = os.path.join(output_dir, f"atarus-recon-{safe_target}.html")

    with open(output_path, "w") as f:
        f.write(html_content)

    return output_path
