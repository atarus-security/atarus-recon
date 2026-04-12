import os
import json
from dataclasses import asdict
from atarus_recon.models import ScanResult
from atarus_recon.scope import ScopeValidator


def generate(result: ScanResult, output_dir: str) -> str:
    """Generate a JSON report from scan results"""

    os.makedirs(output_dir, exist_ok=True)

    data = asdict(result)
    data["tool"] = "atarus-recon"
    data["version"] = "0.1.0"

    safe_target = ScopeValidator.sanitize_filename(result.target)
    output_path = os.path.join(output_dir, f"atarus-recon-{safe_target}.json")

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    return output_path
