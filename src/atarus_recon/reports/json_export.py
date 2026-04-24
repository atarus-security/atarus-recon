import os
import json
from dataclasses import asdict, is_dataclass


def generate(result, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"atarus-recon-{result.target}.json")

    data = _to_dict(result)

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
