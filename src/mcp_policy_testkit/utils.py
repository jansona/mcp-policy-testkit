from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_EXTENSIONS = {".json", ".yaml", ".yml", ".py", ".js", ".ts", ".tsx", ".sh"}


def load_data(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    if path.suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
        return data or {}
    raise ValueError(f"Unsupported file type: {path}")


def is_url(value: str) -> bool:
    return value.startswith(("http://", "https://", "file://"))


def iter_candidate_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files = []
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(candidate)
    return sorted(files)


def json_pointer(prefix: str, segment: str) -> str:
    if prefix:
        return f"{prefix}/{segment}"
    return f"/{segment}"
