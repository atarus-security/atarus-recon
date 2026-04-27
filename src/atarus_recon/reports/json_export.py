import os
import json
from dataclasses import asdict, is_dataclass
from atarus_recon.scope import ScopeValidator


def generate(result, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    safe_target = ScopeValidator.sanitize_filename(result.target)
    path = os.path.join(output_dir, f"atarus-recon-{safe_target}.json")

    data = _to_dict(result)
    data = _make_paths_relative(data, output_dir)

    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def _to_dict(obj):
    if is_dataclass(obj):
        return {k: _to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def _make_paths_relative(data, output_dir: str):
    """Convert absolute screenshot paths to relative for portability"""
    if isinstance(data, dict):
        if "screenshot_path" in data and data.get("screenshot_path"):
            abs_path = data["screenshot_path"]
            try:
                rel_path = os.path.relpath(abs_path, output_dir)
                data["screenshot_path"] = rel_path
            except (ValueError, OSError):
                pass
        return {k: _make_paths_relative(v, output_dir) for k, v in data.items()}
    if isinstance(data, list):
        return [_make_paths_relative(x, output_dir) for x in data]
    return data
